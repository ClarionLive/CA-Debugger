using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ locals (Variables panel)

        /// <summary>EXPERIMENT: locals — list the current procedure's local variables and their live values,
        /// read from the paused frame ([EBP + frameOffset]). Decoded via TswdDebugInfo.ReadLocals (ported
        /// from clarion-pdb). Emits a `locals` event for the host's Variables panel.</summary>
        private void HandleLocalsCommand(string[] parts, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            var rows = new List<string>();
            string proc = null;

            if (haveCtx)
            {
                uint eip = ctx.Eip;
                var m = ModuleAt(eip);
                ProcSymbol sym;
                if (m != null && m.Dbg != null && m.Dbg.ResolveSymbol(eip - m.LoadBase, out sym))
                {
                    proc = sym.Name;
                    var map = m.Dbg.ReadLocals();
                    List<LocalSym> locals;
                    if (map.TryGetValue(sym.EntryRva, out locals))
                    {
                        foreach (var l in locals)
                        {
                            uint va = (uint)((long)ctx.Ebp + l.FrameOff);
                            string type = ClarionTypeLabel(l);
                            string val = ReadLocalValue(l, va);
                            rows.Add("{\"name\":" + Json.Str(l.Name)
                                + ",\"type\":" + Json.Str(type)
                                + ",\"value\":" + Json.Str(val)
                                + ",\"frameOff\":" + l.FrameOff + "}");
                        }
                    }
                }
            }

            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"locals\",\"proc\":" + Json.Str(proc)
                    + ",\"items\":[" + string.Join(",", rows) + "]}");
            else
            {
                Console.WriteLine($"  locals ({rows.Count}) in {proc ?? "(unknown)"}:");
                // (text view is JSON-free; the structured rows above carry the detail for the host)
            }
        }

        /// <summary>Render a Clarion type label from the decoded local (e.g. LONG, STRING(20), DECIMAL(7,2)).</summary>
        private static string ClarionTypeLabel(LocalSym l)
        {
            switch (l.TypeCode)
            {
                case 0x11: return l.Size == 2 ? "SHORT" : l.Size == 4 ? "LONG" : "SIGNED";
                case 0x12: return l.Size == 1 ? "BYTE" : l.Size == 2 ? "USHORT" : l.Size == 4 ? "ULONG" : "UNSIGNED";
                case 0x13: case 0x25: return l.Size == 8 ? "REAL" : "SREAL";
                case 0x18: return "STRING(" + l.Size + ")";   // STRING/CSTRING/PSTRING not yet distinguished
                case 0x23: return "DECIMAL(" + DecimalDigits(l.Size) + "," + l.Places + ")";
                case 0x24: return "PDECIMAL(" + DecimalDigits(l.Size) + "," + l.Places + ")";
                case 0x16:
                    // a by-ref STRING is, to the user, just a STRING(N) — the pointer is an ABI detail
                    if (l.Target == 0x18) return "STRING(" + l.Size + ")";
                    return l.Target == 0x08 ? "&GROUP" : l.Target == 0x05 ? "&CLASS" : "&REF";
                case 0x08: return "GROUP";
                default:   return "TYPE(0x" + l.TypeCode.ToString("X2") + ")";
            }
        }

        // a Clarion packed-decimal of N bytes carries 2N-1 significant digits (the remaining nibble is the sign)
        private static int DecimalDigits(uint sizeBytes) { return sizeBytes > 0 ? (int)(sizeBytes * 2 - 1) : 0; }

        /// <summary>Read and format a local's live value from <paramref name="va"/> on the paused thread.</summary>
        private string ReadLocalValue(LocalSym l, uint va)
        {
            int len;
            switch (l.TypeCode)
            {
                case 0x18: len = (int)Math.Min(l.Size == 0 ? 1u : l.Size, 1024u); break;
                case 0x23: case 0x24: len = (int)(l.Size == 0 ? 1u : l.Size); break;
                case 0x11: case 0x12: case 0x13: case 0x25: len = (int)(l.Size == 0 ? 4u : l.Size); break;
                case 0x16: len = 4; break;
                default:   len = l.Size > 0 ? (int)Math.Min(l.Size, 64u) : 4; break;
            }
            var buf = new byte[len];
            int got = ReadBlock(va, buf);
            if (got <= 0) return "<unreadable>";

            switch (l.TypeCode)
            {
                case 0x11:   // signed
                    if (l.Size == 1) return ((sbyte)buf[0]).ToString();
                    if (l.Size == 2) return BitConverter.ToInt16(buf, 0).ToString();
                    return BitConverter.ToInt32(buf, 0).ToString();
                case 0x12:   // unsigned
                    if (l.Size == 1) return buf[0].ToString();
                    if (l.Size == 2) return BitConverter.ToUInt16(buf, 0).ToString();
                    return BitConverter.ToUInt32(buf, 0).ToString();
                case 0x13: case 0x25:   // float (SREAL / REAL)
                    return l.Size == 8 ? BitConverter.ToDouble(buf, 0).ToString("R")
                                       : BitConverter.ToSingle(buf, 0).ToString("R");
                case 0x18:   // STRING/CSTRING/PSTRING — show the text (cut at NUL, else trim trailing spaces)
                {
                    int n = Array.IndexOf(buf, (byte)0, 0, got);
                    if (n < 0) n = got;
                    return "'" + Encoding.ASCII.GetString(buf, 0, n).TrimEnd(' ') + "'";
                }
                case 0x23: return FormatBcd(buf, got, l.Places, packed: false);  // DECIMAL (sign-first)
                case 0x24: return FormatBcd(buf, got, l.Places, packed: true);   // PDECIMAL (sign-last)
                case 0x16:   // reference: the stack slot holds a pointer
                {
                    uint ptr = BitConverter.ToUInt32(buf, 0);
                    if (ptr == 0) return "(null)";
                    if (l.Target == 0x18)   // &STRING — deref and show the fixed N-char buffer (space-padded)
                    {
                        int sn = l.Size > 0 && l.Size <= 4096 ? (int)l.Size : 256;
                        var sbuf = new byte[sn];
                        int sg = ReadBlock(ptr, sbuf);
                        if (sg <= 0) return "&0x" + ptr.ToString("X") + " <unreadable>";
                        int nz = Array.IndexOf(sbuf, (byte)0, 0, sg);   // CSTRING terminator, if any
                        if (nz < 0) nz = sg;
                        return "'" + Encoding.ASCII.GetString(sbuf, 0, nz).TrimEnd(' ') + "'";
                    }
                    return "&0x" + ptr.ToString("X");
                }
                default:
                {
                    var sb = new StringBuilder("0x");
                    for (int i = 0; i < got; i++) sb.Append(buf[i].ToString("X2"));
                    return sb.ToString();
                }
            }
        }

        /// <summary>Decode a Clarion packed-BCD decimal. Two layouts (verified in clarion-pdb):
        /// DECIMAL (sign-first): sign = high nibble of byte 0 (non-zero = negative); digits = byte0.low,
        /// then byte_i.high, byte_i.low (MSB first). PDECIMAL (sign-last/IBM): sign = low nibble of the last
        /// byte (0x0D = negative); digits = byte_i.high, byte_i.low up to the last byte's high nibble.</summary>
        private static string FormatBcd(byte[] b, int size, int places, bool packed)
        {
            var digits = new StringBuilder();
            bool neg;
            if (!packed)
            {
                neg = (b[0] >> 4) != 0;
                digits.Append((b[0] & 0xf).ToString());
                for (int i = 1; i < size; i++) { digits.Append(((b[i] >> 4) & 0xf)); digits.Append((b[i] & 0xf)); }
            }
            else
            {
                neg = (b[size - 1] & 0xf) == 0xd;
                for (int i = 0; i < size - 1; i++) { digits.Append(((b[i] >> 4) & 0xf)); digits.Append((b[i] & 0xf)); }
                digits.Append(((b[size - 1] >> 4) & 0xf));
            }

            string ds = digits.ToString();
            string intPart, fracPart = "";
            if (places > 0)
            {
                if (ds.Length <= places) ds = ds.PadLeft(places + 1, '0');
                intPart = ds.Substring(0, ds.Length - places);
                fracPart = ds.Substring(ds.Length - places);
            }
            else intPart = ds;

            intPart = intPart.TrimStart('0');
            if (intPart.Length == 0) intPart = "0";
            string val = places > 0 ? intPart + "." + fracPart : intPart;
            return (neg && val != "0") ? "-" + val : val;
        }
    }
}
