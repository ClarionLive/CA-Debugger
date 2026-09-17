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

        /// <summary>setval &lt;va&gt; &lt;typeCode&gt; &lt;size&gt; &lt;places&gt; &lt;valueB64&gt; [tid]
        ///
        /// TWO guards, deliberately at different levels. The optional tid catches a stale SELECTION — what
        /// the host believed it was editing. <see cref="ThreadedWriteAllowed"/> catches a stale ADDRESS, and
        /// needs nothing from the host at all, so it also covers the paths nobody told us about.
        ///
        /// The optional trailing tid is the thread the HOST believed it was editing when it built the row.
        /// A THREADed value's VA is one thread's instance, so if the selection moved between the row being
        /// read and the edit being sent — a switch racing a keystroke — writing it would silently modify a
        /// different thread's data at an address that is still perfectly valid. That is the one outcome this
        /// ticket has to make impossible, so the write is refused and says so.
        ///
        /// An ABSENT tid means "unscoped" and is accepted, matching the rest of the protocol: a host that
        /// does not send one is exactly as safe as it was before, and absence is never a sentinel.</summary>
        private void HandleSetValCommand(string[] parts, uint selectedTid)
        {
            if (parts.Length < 6) { EmitError("setval expects: setval <va> <typeCode> <size> <places> <valueB64> [tid]"); return; }

            uint va = ParseHexU(parts[1]);
            if (parts.Length > 6)
            {
                uint wantTid;
                if (!uint.TryParse(parts[6], out wantTid))
                {
                    EmitVarSetError(va, "setval: bad thread id '" + parts[6] + "'");
                    return;
                }
                if (wantTid != selectedTid)
                {
                    EmitVarSetError(va, "not written: this edit was for thread " + wantTid
                                        + ", but thread " + selectedTid + " is selected now");
                    return;
                }
            }
            byte code = (byte)ParseHexU(parts[2]);
            int size, places;
            if (!int.TryParse(parts[3], out size) || size <= 0 || size > 4096) { EmitVarSetError(va, "bad size"); return; }
            if (!int.TryParse(parts[4], out places)) places = 0;

            string value;
            try { value = Encoding.UTF8.GetString(Convert.FromBase64String(parts[5])); }
            catch { EmitVarSetError(va, "bad value encoding"); return; }

            byte[] bytes; string err;
            if (!EncodeValue(code, (uint)size, places, value, out bytes, out err)) { EmitVarSetError(va, err); return; }

            // The ADDRESS guard. The tid check above catches a stale SELECTION — the host telling us which
            // thread it meant. This catches a stale ADDRESS, and it needs no cooperation from anyone: a
            // write that touches THREADed data which is not the selected thread's own is refused however it
            // got here, including from a row the host built before a switch, an expanded node whose veto we
            // cannot see, or a hand-typed CLI setval. Enforcing at the WRITE covers every path into it
            // rather than every row that might produce one.
            //
            // Deliberately placed HERE, immediately before WriteBlock and after EncodeValue, because it
            // needs the LENGTH: a write is an interval, and bytes.Length is the interval this call will
            // actually put on the target.
            string threadedWhy;
            if (!ThreadedWriteAllowed(va, bytes.Length, selectedTid, out threadedWhy))
            { EmitVarSetError(va, threadedWhy); return; }

            if (!WriteBlock(va, bytes)) { EmitVarSetError(va, "memory write failed at 0x" + va.ToString("X")); return; }

            // re-read at the same location so the UI shows the engine's canonical rendering of what landed
            string nv = FormatValueAt(code, 0, (uint)size, places, va);
            Console.WriteLine($"  setval 0x{va:X}: {nv}");
            if (EmitJson) Console.WriteLine("@JSON " + Json.VarSet(va, true, nv, null));
        }

        /// <summary>
        /// May a write of <paramref name="len"/> bytes at <paramref name="va"/> land, for the selected thread?
        ///
        /// A WRITE IS AN INTERVAL, not an address. This tested only the start address until the claims
        /// audit caught it: WriteBlock puts `len` bytes down (up to 4096), so a write beginning just below
        /// a protected block and running into it was allowed, and landed on it. Worse, the test that was
        /// supposed to prove the guard asserted the byte immediately below the template MUST BE ALLOWED —
        /// true of a single byte, false as a general claim, and the control case was itself the hole. Every
        /// comparison below is therefore an overlap of [va, va+len) with the protected range.
        ///
        /// Two refusals, both about THREADed (.cwtls) data:
        ///  • the VA is inside an image's .cwtls TEMPLATE range — the shared block every Clarion thread's
        ///    instance is copied from. Writing it changes the initial value every FUTURE thread starts with,
        ///    which is a side effect on threads that do not exist yet. No legitimate edit ever carries a
        ///    template VA: a row that falls back to the template is vetoed and offers no pencil. This test
        ///    is pure address arithmetic, so it holds even when nothing else can be resolved.
        ///
        ///    THE PRINCIPLE, because it generalises: A GUARD THAT CANNOT BE RECOVERED FROM MUST NOT DEPEND
        ///    ON AN OPTIONAL CAPABILITY. This loop used to skip any image without HasThreadedData, which is
        ///    `CwtlsHi != 0 AND ThrGetInstanceIatRva != 0` — so an image with a real .cwtls section whose
        ///    THR$GetInstance import could not be resolved (a statically or locally linked runtime, a renamed
        ///    runtime DLL, an import by ordinal) had its rows vetoed by the row-level checks, which gate on
        ///    CwtlsHi alone, while the write guard waved the same template through. The template test needs
        ///    no import; only the other-thread comparison does. So the loop gates on the section, and the
        ///    import gates only the part that actually needs it.
        ///  • the VA is inside ANOTHER live thread's instance block for that image — the stale-row case,
        ///    where the address is still perfectly valid and belongs to somebody else.
        ///
        /// Everything else is allowed, and that includes a VA we could not classify. The instance comparison
        /// FAILS OPEN on purpose: an unresolvable VA is overwhelmingly an ordinary global, local or module
        /// value, and refusing those to catch a rarer case would break editing for everyone. The template
        /// test, which is the one that cannot be recovered from, fails CLOSED and needs no resolution at all.
        /// </summary>
        private bool ThreadedWriteAllowed(uint va, int len, uint selectedTid, out string reason)
        {
            reason = null;
            if (len < 1) len = 1;
            // 64-bit so a write near the top of the address space cannot wrap the end past the start and
            // silently turn an overlap into a miss.
            ulong wLo = va, wHi = (ulong)va + (ulong)len;

            foreach (var m in _modules)
            {
                // Gated on the SECTION, not on HasThreadedData: the template refusal below needs no import.
                if (m == null || m.LoadBase == 0 || m.CwtlsHi == 0) continue;
                uint tmplSpan = m.CwtlsHi - m.CwtlsLo;     // file-aligned; over-width here is only padding
                if (tmplSpan == 0) continue;
                uint tmplLo = m.LoadBase + m.CwtlsLo;

                // 1. the shared template — unconditional, needs nothing resolved
                if (Overlaps(wLo, wHi, tmplLo, tmplSpan))
                {
                    uint ownBase;
                    string where = m.HasThreadedData && va >= tmplLo && va < tmplLo + tmplSpan
                                   && TryInstanceBase(m, selectedTid, out ownBase)
                        ? " — thread " + selectedTid + "'s own copy is at 0x" + (va - tmplLo + ownBase).ToString("X")
                        : " and thread " + selectedTid + " has no instance of it";
                    reason = "not written: " + Range(va, len) + " touches the shared " + m.Name
                           + " template, not one thread's data" + where;
                    return false;
                }

                // The instance-block comparisons DO need the import, and they are the recoverable half:
                // without it we simply cannot say whose copy an address is, and allowing is the safe answer.
                if (!m.HasThreadedData) continue;

                // An instance block is the DECLARED threaded-data size the RTL allocates, not the section's
                // file-aligned span — using the span would over-refuse up to FileAlignment-1 bytes past a
                // real block, into adjacent heap where a legitimately editable allocation can sit. Refusing
                // a valid write breaks editing, which is worse than the case it would catch.
                uint blockSpan = m.CwtlsDataSize != 0 ? m.CwtlsDataSize : tmplSpan;

                // 2. somebody else's instance block. There is deliberately no early "it is inside MY block,
                //    allow" shortcut any more: with intervals a write can touch two adjacent blocks at once,
                //    and returning early on the first would skip the refusal the second one earns. Being
                //    inside the selected thread's own block is simply the absence of any refusal.
                foreach (uint t in _threads)
                {
                    if (t == selectedTid) continue;
                    uint otherBase;
                    if (!TryInstanceBase(m, t, out otherBase)) continue;
                    if (!Overlaps(wLo, wHi, otherBase, blockSpan)) continue;
                    reason = "not written: " + Range(va, len) + " touches thread " + t + "'s copy of the "
                           + m.Name + " data, but thread " + selectedTid + " is selected";
                    return false;
                }
            }
            return true;
        }

        /// <summary>Do the half-open intervals [wLo,wHi) and [bLo, bLo+bLen) share a byte?</summary>
        private static bool Overlaps(ulong wLo, ulong wHi, uint bLo, uint bLen)
        {
            ulong lo = bLo, hi = (ulong)bLo + bLen;
            return wLo < hi && wHi > lo;
        }

        /// <summary>An address range for a refusal message — a single byte reads as just its address.</summary>
        private static string Range(uint va, int len)
        {
            return len <= 1 ? "0x" + va.ToString("X")
                            : len + " bytes at 0x" + va.ToString("X")
                              + " (through 0x" + ((uint)(va + len - 1)).ToString("X") + ")";
        }

        /// <summary>The base of one thread's .cwtls instance block for an image, via the same read-only
        /// THR$GetInstance emulation every other per-thread read uses. False when the thread has no instance
        /// or it could not be resolved. Cached per (thread, image) for the stop, so a write costs at most one
        /// emulation per thread per threaded image and usually none.</summary>
        private bool TryInstanceBase(LoadedModule m, uint tid, out uint instanceBase)
        {
            instanceBase = 0;
            uint cwtlsBase = m.LoadBase + m.CwtlsLo;
            IntPtr h = OpenThreadForContext(tid);
            if (h == IntPtr.Zero) return false;
            try
            {
                uint instanceVa; string why;
                if (TryResolveThreadedInstance(m, cwtlsBase, tid, h, out instanceVa, out why) != ThreadedResolve.Ok)
                    return false;
                instanceBase = instanceVa;
                return true;
            }
            finally { Native.CloseHandle(h); }
        }

        /// <summary>Test seam for `protocolcheck`: assert the shipped write guard, not a copy of its rules.</summary>
        internal bool ThreadedWriteAllowedForTest(uint va, int len, uint tid, out string reason)
        {
            return ThreadedWriteAllowed(va, len, tid, out reason);
        }

        /// <summary>Test seam: register a mapped image with a known .cwtls range, so the template-range
        /// refusal can be asserted without a live debuggee (that branch is pure address arithmetic).</summary>
        /// <param name="iatRva">0 models an image with a real .cwtls section whose THR$GetInstance import
        /// could not be resolved — the configuration in which the template refusal must still hold.</param>
        internal void RegisterThreadedModuleForTest(string name, uint loadBase, uint cwtlsLo, uint cwtlsHi,
                                                    uint iatRva = 4)
        {
            _modules.Add(new LoadedModule
            {
                Name = name, LoadBase = loadBase, Size = 0x200000,
                CwtlsLo = cwtlsLo, CwtlsHi = cwtlsHi, CwtlsDataSize = cwtlsHi - cwtlsLo,
                ThrGetInstanceIatRva = iatRva,
            });
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
