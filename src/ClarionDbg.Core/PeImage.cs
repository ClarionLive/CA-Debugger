using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ClarionDbg.Core
{
    /// <summary>A single PE section header (the fields we care about).</summary>
    public sealed class PeSection
    {
        public string Name;
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint PointerToRawData;
        public uint SizeOfRawData;

        public uint Span { get { return Math.Max(VirtualSize, SizeOfRawData); } }
        public bool ContainsRva(uint rva) { return rva >= VirtualAddress && rva < VirtualAddress + Span; }
    }

    /// <summary>
    /// Minimal PE32 reader: enough to find the image base, the section table
    /// (for RVA-&gt;file-offset mapping and the .text range), and the Debug Directory.
    /// </summary>
    public sealed class PeImage
    {
        public byte[] Bytes { get; private set; }
        public ushort Machine { get; private set; }
        public uint ImageBase { get; private set; }
        public uint SizeOfImage { get; private set; }
        public uint EntryPointRva { get; private set; }
        public uint DebugDirRva { get; private set; }
        public uint DebugDirSize { get; private set; }
        public List<PeSection> Sections { get; private set; }

        public bool IsX86 { get { return Machine == 0x014C; } }

        public static PeImage Load(string path)
        {
            return new PeImage(File.ReadAllBytes(path));
        }

        public PeImage(byte[] bytes)
        {
            Bytes = bytes;
            Sections = new List<PeSection>();

            int peOff = BitConverter.ToInt32(bytes, 0x3C);
            if (BitConverter.ToUInt32(bytes, peOff) != 0x00004550) // "PE\0\0"
                throw new InvalidDataException("Not a PE image (missing PE signature).");

            Machine = BitConverter.ToUInt16(bytes, peOff + 4);
            ushort numSec = BitConverter.ToUInt16(bytes, peOff + 6);
            ushort optSize = BitConverter.ToUInt16(bytes, peOff + 20);
            int optOff = peOff + 24;
            ushort magic = BitConverter.ToUInt16(bytes, optOff);
            if (magic != 0x10B)
                throw new InvalidDataException("Only PE32 (32-bit) images are supported; Clarion targets are 32-bit.");

            // PE32 optional header: AddressOfEntryPoint @+16, ImageBase @+28, SizeOfImage @+56.
            EntryPointRva = BitConverter.ToUInt32(bytes, optOff + 16);
            ImageBase = BitConverter.ToUInt32(bytes, optOff + 28);
            SizeOfImage = BitConverter.ToUInt32(bytes, optOff + 56);

            // Data directories begin at +96 in PE32; Debug Directory is index 6 (8 bytes each).
            int debugDir = optOff + 96 + 6 * 8;
            DebugDirRva = BitConverter.ToUInt32(bytes, debugDir);
            DebugDirSize = BitConverter.ToUInt32(bytes, debugDir + 4);

            int secOff = optOff + optSize;
            for (int i = 0; i < numSec; i++)
            {
                int o = secOff + i * 40;
                Sections.Add(new PeSection
                {
                    Name = Encoding.ASCII.GetString(bytes, o, 8).TrimEnd('\0'),
                    VirtualSize = BitConverter.ToUInt32(bytes, o + 8),
                    VirtualAddress = BitConverter.ToUInt32(bytes, o + 12),
                    SizeOfRawData = BitConverter.ToUInt32(bytes, o + 16),
                    PointerToRawData = BitConverter.ToUInt32(bytes, o + 20),
                });
            }
        }

        public PeSection Text
        {
            get { return Sections.Find(s => s.Name == ".text"); }
        }

        public PeSection FindSection(string name)
        {
            return Sections.Find(s => string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        // import directory (data directory index 1) — for resolving a live import address at runtime
        private uint _importDirRva;

        /// <summary>
        /// The IAT slot RVA for an imported function: at runtime, the u32 at loadBase+slot holds
        /// the function's live address in the loaded DLL. Returns 0 when not imported.
        /// </summary>
        public uint FindImportIatSlotRva(string dllName, string funcName)
        {
            if (_importDirRva == 0)
            {
                int peOff = BitConverter.ToInt32(Bytes, 0x3C);
                int optOff = peOff + 24;
                _importDirRva = BitConverter.ToUInt32(Bytes, optOff + 96 + 1 * 8);
                if (_importDirRva == 0) return 0;
            }
            long dirOff = RvaToOffset(_importDirRva);
            if (dirOff < 0) return 0;

            for (int d = 0; ; d++)
            {
                int desc = (int)dirOff + d * 20;
                uint oft = BitConverter.ToUInt32(Bytes, desc);        // OriginalFirstThunk
                uint nameRva = BitConverter.ToUInt32(Bytes, desc + 12);
                uint ft = BitConverter.ToUInt32(Bytes, desc + 16);    // FirstThunk (the IAT)
                if (oft == 0 && nameRva == 0 && ft == 0) break;

                long nameOff = RvaToOffset(nameRva);
                if (nameOff < 0) continue;
                string dll = ReadAsciiZ((int)nameOff);
                if (!string.Equals(dll, dllName, StringComparison.OrdinalIgnoreCase)) continue;

                uint thunks = oft != 0 ? oft : ft;                    // name table (fall back to IAT pre-bind)
                long thunkOff = RvaToOffset(thunks);
                if (thunkOff < 0) continue;
                for (int i = 0; ; i++)
                {
                    uint entry = BitConverter.ToUInt32(Bytes, (int)thunkOff + i * 4);
                    if (entry == 0) break;
                    if ((entry & 0x80000000) != 0) continue;          // by-ordinal
                    long hintOff = RvaToOffset(entry);
                    if (hintOff < 0) continue;
                    if (string.Equals(ReadAsciiZ((int)hintOff + 2), funcName, StringComparison.Ordinal))
                        return ft + (uint)i * 4;
                }
            }
            return 0;
        }

        private string ReadAsciiZ(int off)
        {
            int end = off;
            while (end < Bytes.Length && Bytes[end] != 0) end++;
            return Encoding.ASCII.GetString(Bytes, off, end - off);
        }

        /// <summary>Map a virtual address (RVA) to a file offset, or -1 if not in any section.</summary>
        public long RvaToOffset(uint rva)
        {
            foreach (var s in Sections)
                if (s.ContainsRva(rva))
                    return s.PointerToRawData + (rva - s.VirtualAddress);
            return -1;
        }

        public bool RvaInText(uint rva)
        {
            var t = Text;
            return t != null && rva >= t.VirtualAddress && rva < t.VirtualAddress + t.VirtualSize;
        }

        /// <summary>Holds the first IMAGE_DEBUG_DIRECTORY entry.</summary>
        public struct DebugEntry { public uint Type; public uint SizeOfData; public uint PointerToRawData; }

        public DebugEntry ReadFirstDebugEntry()
        {
            long off = RvaToOffset(DebugDirRva);
            if (off < 0) throw new InvalidDataException("Debug directory RVA not mapped to a section.");
            int o = (int)off;
            return new DebugEntry
            {
                Type = BitConverter.ToUInt32(Bytes, o + 12),
                SizeOfData = BitConverter.ToUInt32(Bytes, o + 16),
                PointerToRawData = BitConverter.ToUInt32(Bytes, o + 24),
            };
        }

        /// <summary>Non-throwing variant: false when there is no debug directory (or it is not
        /// mapped to a section), used to tier images that carry no debug info at all.</summary>
        public bool TryReadFirstDebugEntry(out DebugEntry entry)
        {
            entry = default(DebugEntry);
            if (DebugDirRva == 0 || DebugDirSize == 0) return false;
            long off = RvaToOffset(DebugDirRva);
            if (off < 0) return false;
            int o = (int)off;
            if (o + 28 > Bytes.Length) return false;
            entry = new DebugEntry
            {
                Type = BitConverter.ToUInt32(Bytes, o + 12),
                SizeOfData = BitConverter.ToUInt32(Bytes, o + 16),
                PointerToRawData = BitConverter.ToUInt32(Bytes, o + 24),
            };
            return true;
        }
    }
}
