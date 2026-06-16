using System;
using System.Globalization;
using System.Text;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// Edit-variable-value: write a user-supplied value into a live debugged variable. The host sends
    /// <c>setval &lt;vaHex&gt; &lt;typeCodeHex&gt; &lt;size&gt; &lt;places&gt; &lt;valueB64&gt;</c> — the VA is the
    /// exact live address the value was read from (the displayed row already carries it: the stack slot for a
    /// frame local, LoadBase+Rva for module data, the resolved instance VA for Watch incl. THREADed), so this
    /// path does NO re-resolution. <see cref="EncodeValue"/> is the inverse of FormatValueAt; after writing we
    /// re-read and echo the canonical formatted value so the UI can confirm. Valid only while paused.
    /// </summary>
    internal sealed partial class DebugEngine
    {
        /// <summary>The scalar Clarion type codes whose values can be written back: signed/unsigned
        /// integers, SREAL/REAL, STRING, and DECIMAL/PDECIMAL. References and groups/classes are not
        /// editable (composite or pointer slots) and carry no edit metadata.</summary>
        private static bool IsEditableCode(byte code)
        {
            return code == 0x11 || code == 0x12 || code == 0x13 || code == 0x25
                || code == 0x18 || code == 0x23 || code == 0x24;
        }

        private void HandleSetValCommand(string[] parts)
        {
            if (parts.Length < 6) { EmitError("setval expects: setval <va> <typeCode> <size> <places> <valueB64>"); return; }

            uint va = ParseHexU(parts[1]);
            byte code = (byte)ParseHexU(parts[2]);
            int size, places;
            if (!int.TryParse(parts[3], out size) || size <= 0 || size > 4096) { EmitVarSetError(va, "bad size"); return; }
            if (!int.TryParse(parts[4], out places)) places = 0;

            string value;
            try { value = Encoding.UTF8.GetString(Convert.FromBase64String(parts[5])); }
            catch { EmitVarSetError(va, "bad value encoding"); return; }

            byte[] bytes; string err;
            if (!EncodeValue(code, (uint)size, places, value, out bytes, out err)) { EmitVarSetError(va, err); return; }
            if (!WriteBlock(va, bytes)) { EmitVarSetError(va, "memory write failed at 0x" + va.ToString("X")); return; }

            // re-read at the same location so the UI shows the engine's canonical rendering of what landed
            string nv = FormatValueAt(code, 0, (uint)size, places, va);
            Console.WriteLine($"  setval 0x{va:X}: {nv}");
            if (EmitJson) Console.WriteLine("@JSON " + Json.VarSet(va, true, nv, null));
        }

        private void EmitVarSetError(uint va, string err)
        {
            Console.WriteLine($"  setval 0x{va:X} failed: {err}");
            if (EmitJson) Console.WriteLine("@JSON " + Json.VarSet(va, false, null, err));
        }

        /// <summary>Encode a user value into <paramref name="size"/> target bytes for Clarion type
        /// <paramref name="code"/> — the inverse of FormatValueAt. Returns false (with a user-facing
        /// <paramref name="err"/>) for unparseable input, out-of-range values, or non-editable types.</summary>
        private static bool EncodeValue(byte code, uint size, int places, string str, out byte[] bytes, out string err)
        {
            bytes = null; err = null;
            str = (str ?? "").Trim();
            switch (code)
            {
                case 0x11: // signed integer
                {
                    long v;
                    if (!long.TryParse(str, NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) { err = "expected an integer"; return false; }
                    if (!FitsSigned(v, size)) { err = $"out of range for a {size}-byte signed integer"; return false; }
                    bytes = IntBytes((ulong)v, size); return true;
                }
                case 0x12: // unsigned integer
                {
                    ulong v;
                    if (!ulong.TryParse(str, NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) { err = "expected a non-negative integer"; return false; }
                    if (!FitsUnsigned(v, size)) { err = $"out of range for a {size}-byte unsigned integer"; return false; }
                    bytes = IntBytes(v, size); return true;
                }
                case 0x13: case 0x25: // SREAL / REAL
                {
                    double d;
                    if (!double.TryParse(str, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) { err = "expected a number"; return false; }
                    bytes = size == 8 ? BitConverter.GetBytes(d) : BitConverter.GetBytes((float)d);
                    return true;
                }
                case 0x18: // STRING / CSTRING / PSTRING — fixed buffer, space-padded (STRING semantics)
                {
                    string s = StripQuotes(str);
                    var buf = new byte[size];
                    for (int i = 0; i < size; i++) buf[i] = (byte)' ';
                    var ascii = Encoding.ASCII.GetBytes(s);
                    Array.Copy(ascii, buf, Math.Min(ascii.Length, (int)size));
                    bytes = buf; return true;
                }
                case 0x23: return EncodeBcd(str, size, places, packed: false, bytes: out bytes, err: out err); // DECIMAL
                case 0x24: return EncodeBcd(str, size, places, packed: true,  bytes: out bytes, err: out err); // PDECIMAL
                default:
                    err = "type 0x" + code.ToString("X2") + " is not editable";
                    return false;
            }
        }

        /// <summary>Encode a decimal string into Clarion packed BCD — the inverse of FormatBcd. Both layouts
        /// hold D = 2*size-1 significant digits; sign is the high nibble of byte 0 (DECIMAL) or low nibble of
        /// the last byte (PDECIMAL, 0x0D negative / 0x0C positive).</summary>
        private static bool EncodeBcd(string str, uint size, int places, bool packed, out byte[] bytes, out string err)
        {
            bytes = null;
            int D = (int)(2 * size - 1);
            bool neg;
            string ds = BcdDigits(str, places, D, out neg, out err);
            if (ds == null) return false;

            var b = new byte[size];
            if (!packed)
            {
                // DECIMAL (sign-first): byte0 high = sign, byte0 low = ds[0]; byte_i = ds[2i-1] | ds[2i]
                b[0] = (byte)(((neg ? 0xF : 0x0) << 4) | (ds[0] - '0'));
                for (int i = 1; i < size; i++)
                    b[i] = (byte)(((ds[2 * i - 1] - '0') << 4) | (ds[2 * i] - '0'));
            }
            else
            {
                // PDECIMAL (sign-last): byte_i = ds[2i] | ds[2i+1]; last byte = ds[D-1] | sign
                for (int i = 0; i < size - 1; i++)
                    b[i] = (byte)(((ds[2 * i] - '0') << 4) | (ds[2 * i + 1] - '0'));
                b[size - 1] = (byte)(((ds[D - 1] - '0') << 4) | (neg ? 0x0D : 0x0C));
            }
            bytes = b;
            return true;
        }

        /// <summary>Normalize a signed decimal string to exactly D BCD digits (fraction scaled to
        /// <paramref name="places"/>), reporting the sign. Null + err on bad input or overflow.</summary>
        private static string BcdDigits(string str, int places, int D, out bool neg, out string err)
        {
            neg = false; err = null;
            str = (str ?? "").Trim();
            if (str.Length == 0) { err = "expected a number"; return null; }
            if (str[0] == '+' || str[0] == '-') { neg = str[0] == '-'; str = str.Substring(1); }

            string intp, frac;
            int dot = str.IndexOf('.');
            if (dot >= 0) { intp = str.Substring(0, dot); frac = str.Substring(dot + 1); }
            else { intp = str; frac = ""; }
            if (!AllDigits(intp) || !AllDigits(frac) || (intp.Length == 0 && frac.Length == 0)) { err = "expected a decimal number"; return null; }

            if (places > 0) frac = frac.Length > places ? frac.Substring(0, places) : frac.PadRight(places, '0');
            else frac = "";

            string ds = (intp + frac).TrimStart('0');
            if (ds.Length == 0) { ds = "0"; neg = false; }
            if (ds.Length > D) { err = "value has too many digits for this field"; return null; }
            return ds.PadLeft(D, '0');
        }

        private static bool AllDigits(string s)
        {
            foreach (char c in s) if (c < '0' || c > '9') return false;
            return true;
        }

        private static byte[] IntBytes(ulong v, uint size)
        {
            var b = new byte[size];
            for (int i = 0; i < size && i < 8; i++) { b[i] = (byte)(v & 0xFF); v >>= 8; }
            return b;
        }

        private static bool FitsSigned(long v, uint size)
        {
            switch (size)
            {
                case 1: return v >= sbyte.MinValue && v <= sbyte.MaxValue;
                case 2: return v >= short.MinValue && v <= short.MaxValue;
                case 4: return v >= int.MinValue && v <= int.MaxValue;
                default: return true; // 8-byte+ — long already bounds it
            }
        }

        private static bool FitsUnsigned(ulong v, uint size)
        {
            switch (size)
            {
                case 1: return v <= byte.MaxValue;
                case 2: return v <= ushort.MaxValue;
                case 4: return v <= uint.MaxValue;
                default: return true;
            }
        }
    }
}
