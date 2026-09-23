using System;
using System.IO;

namespace ClarionDbg.Core
{
    /// <summary>
    /// Headers-only PE probe: the machine type, and whether the image's FIRST debug directory entry is TSWD.
    /// <para>
    /// Built for the attach picker (<c>ClarionDbg procs</c>), which probes every running process's image.
    /// <see cref="PeImage.Load"/> reads the WHOLE file, which is far too heavy per process; this reads the
    /// DOS header, the PE headers, the section table and one 28-byte debug entry through a FileStream -
    /// a few KB at most (<see cref="MaxHeaderBytes"/>).
    /// </para>
    /// <para>
    /// The TSWD rule is the one <see cref="TswdDebugInfo.TryFromPe"/> applies: the FIRST
    /// IMAGE_DEBUG_DIRECTORY entry has Type == <see cref="TswdDebugInfo.TswdMagic"/>. It tiers by the PE
    /// debug directory, never by a file or section name. The RVA-to-file-offset rule is
    /// <see cref="PeSection.ContainsRva"/>'s, so the two readers cannot disagree about where the entry is.
    /// </para>
    /// Never throws: a missing, locked, truncated or non-PE file reports false.
    /// </summary>
    public static class PeProbe
    {
        public const ushort MachineI386 = 0x014C;
        public const ushort MachineAmd64 = 0x8664;

        /// <summary>The most header bytes one probe will read. The PE headers plus the section table fit in
        /// the first 4 KB of any image a linker produces; the cap keeps a hostile e_lfanew or
        /// NumberOfSections from turning a probe into a large read.</summary>
        public const int MaxHeaderBytes = 64 * 1024;

        private const int DebugDirIndex = 6;       // IMAGE_DIRECTORY_ENTRY_DEBUG
        private const int DebugEntrySize = 28;     // sizeof(IMAGE_DEBUG_DIRECTORY)
        private const int SectionHeaderSize = 40;

        /// <summary>True when <paramref name="path"/> is a PE image whose headers parse. <paramref name="machine"/>
        /// is the COFF Machine field; <paramref name="hasTswd"/> is true only for a PE32 image whose first debug
        /// entry is TSWD.</summary>
        public static bool TryProbe(string path, out ushort machine, out bool hasTswd)
        {
            machine = 0;
            hasTswd = false;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                               FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.None))
                {
                    return Probe(fs, out machine, out hasTswd);
                }
            }
            catch (Exception)
            {
                machine = 0;
                hasTswd = false;
                return false;
            }
        }

        /// <summary>The probe over an open, seekable stream. Exposed for tests; same contract as TryProbe.</summary>
        public static bool Probe(Stream s, out ushort machine, out bool hasTswd)
        {
            machine = 0;
            hasTswd = false;

            byte[] head = ReadAt(s, 0, 4096);
            if (head.Length < 0x40 || head[0] != (byte)'M' || head[1] != (byte)'Z') return false;

            int peOff = BitConverter.ToInt32(head, 0x3C);
            if (peOff < 0x40 || peOff > MaxHeaderBytes - 24) return false;

            // The COFF header, to learn how much more to read.
            byte[] coff = ReadAt(s, peOff, 24);
            if (coff.Length < 24 || BitConverter.ToUInt32(coff, 0) != 0x00004550) return false; // "PE\0\0"
            ushort mach = BitConverter.ToUInt16(coff, 4);
            ushort numSec = BitConverter.ToUInt16(coff, 6);
            ushort optSize = BitConverter.ToUInt16(coff, 20);

            long optOff = peOff + 24;
            long secOff = optOff + optSize;
            long hdrEnd = secOff + (long)numSec * SectionHeaderSize;
            if (hdrEnd > MaxHeaderBytes) return false;

            byte[] hdr = ReadAt(s, optOff, (int)(hdrEnd - optOff));
            if (hdr.Length < hdrEnd - optOff || optSize < 2) return false;

            machine = mach;   // the headers parsed this far: the machine is known even if the rest is not PE32

            // PE32 (0x10B) keeps its data directories at +96; PE32+ (0x20B) at +112. Only PE32 can be TSWD:
            // Clarion targets are 32-bit, and TswdDebugInfo reads through PeImage, which rejects PE32+.
            ushort magic = BitConverter.ToUInt16(hdr, 0);
            if (magic != 0x10B) return true;
            const int numDirsOff = 92, dirsOff = 96;
            if (optSize < dirsOff + (DebugDirIndex + 1) * 8) return true;
            uint numDirs = BitConverter.ToUInt32(hdr, numDirsOff);
            if (numDirs <= DebugDirIndex) return true;
            uint dbgRva = BitConverter.ToUInt32(hdr, dirsOff + DebugDirIndex * 8);
            uint dbgSize = BitConverter.ToUInt32(hdr, dirsOff + DebugDirIndex * 8 + 4);
            if (dbgRva == 0 || dbgSize == 0) return true;

            long dbgOff = -1;
            for (int i = 0; i < numSec && dbgOff < 0; i++)
            {
                int o = optSize + i * SectionHeaderSize;
                var sec = new PeSection
                {
                    VirtualSize = BitConverter.ToUInt32(hdr, o + 8),
                    VirtualAddress = BitConverter.ToUInt32(hdr, o + 12),
                    SizeOfRawData = BitConverter.ToUInt32(hdr, o + 16),
                    PointerToRawData = BitConverter.ToUInt32(hdr, o + 20),
                };
                if (sec.ContainsRva(dbgRva)) dbgOff = sec.PointerToRawData + (long)(dbgRva - sec.VirtualAddress);
            }
            if (dbgOff < 0) return true;

            byte[] entry = ReadAt(s, dbgOff, DebugEntrySize);
            if (entry.Length < DebugEntrySize) return true;
            hasTswd = BitConverter.ToUInt32(entry, 12) == TswdDebugInfo.TswdMagic;
            return true;
        }

        /// <summary>Up to <paramref name="count"/> bytes at <paramref name="offset"/>; shorter at end of file.</summary>
        private static byte[] ReadAt(Stream s, long offset, int count)
        {
            if (offset < 0 || count <= 0 || offset >= s.Length) return new byte[0];
            s.Seek(offset, SeekOrigin.Begin);
            var buf = new byte[(int)Math.Min(count, s.Length - offset)];
            int got = 0;
            while (got < buf.Length)
            {
                int n = s.Read(buf, got, buf.Length - got);
                if (n <= 0) break;
                got += n;
            }
            if (got < buf.Length) Array.Resize(ref buf, got);
            return buf;
        }
    }
}
