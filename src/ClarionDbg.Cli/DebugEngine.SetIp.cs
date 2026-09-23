using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    // ------------------------------------------------------------------ set next statement (task a77abd94)
    //
    // `setip <module>:<line>` moves the STOPPED thread's EIP to that line's single code record, inside the
    // procedure it is already in, and re-announces the stop with reason "setip". It never runs target code.
    //
    // WHAT MAKES IT SAFE is one measured fact (a77abd94 item 0, clbrws, 2026-09-23, 363 stops): at every
    // statement boundary (a line record, gap 0) of one frame, ESP is the same, EXCEPT across an ACCEPT.
    // Clarion code is EBP-relative and balances its pushes within a statement, so moving EIP between two
    // boundaries of the same frame leaves nothing on the machine stack out of place.
    //
    // ACCEPT is the exception. It compiles to `call [IAT ClaRUN!Cla$StartEventLoop]` at the head and
    // `call [IAT Cla$EndEventLoop]; cmp al,0; je <return address of the Start call>` at the back-edge, and
    // ClaRUN keeps the loop's state ON THE PROCEDURE'S OWN STACK: the body ran 0xFC below the frame's base
    // in the steady state (both SplashScreen and BrowseAuthors), and deeper on the first one or two passes
    // (0x30 more, and once 0x1148 more). So:
    //   - inside one ACCEPT, staying inside it: safe. The current ESP IS the right ESP for every line of the
    //     region whatever the iteration, and EndEventLoop re-seats ESP on the back-edge;
    //   - across its boundary, either way: unsafe, and not fixable by adjusting ESP, because the first pass's
    //     depth is not the steady one. Refused as `accept-boundary`.
    // The rule compares the INNERMOST region (by its Start call site), so a nested ACCEPT is covered without
    // having been measured, and a region that cannot be paired refuses the whole procedure (`accept-unpaired`).
    //
    // NOT MEASURED, and so not claimed: LOOP i = 1 TO n, REPORT/PRINT, nested ACCEPT, BREAK out of an ACCEPT.
    internal sealed partial class DebugEngine
    {
        // ---- the frozen refusal codes. Wire: {"event":"setip","ok":false,"reason":<code>,"error":<text>,...}
        //
        // Every code has ONE user-facing sentence, and the pad shows it as is. The list is frozen: the pad
        // switches on nothing but `ok`, but a host or a test may key on a code, so rename none of them.
        internal const string SetIpBadArgs         = "bad-args";
        internal const string SetIpNotPaused       = "not-paused";
        internal const string SetIpOtherThread     = "other-thread";
        internal const string SetIpNoContext       = "no-context";
        internal const string SetIpNotOnStatement  = "not-on-statement";
        internal const string SetIpOtherModule     = "other-module";
        internal const string SetIpNoCode          = "no-code";
        internal const string SetIpAmbiguousLine   = "ambiguous-line";
        internal const string SetIpOtherProc       = "other-proc";
        internal const string SetIpPrologue        = "prologue";
        internal const string SetIpCodeUnreadable  = "code-unreadable";
        internal const string SetIpAcceptUnpaired  = "accept-unpaired";
        internal const string SetIpAcceptBoundary  = "accept-boundary";
        internal const string SetIpWriteFailed     = "write-failed";

        /// <summary>Every refusal code, in the order <see cref="DecideSetIp"/> tests them (bad-args and
        /// not-paused come first because they are decided before there is a stop to test). protocolcheck
        /// reads this rather than retyping it.</summary>
        internal static readonly string[] SetIpRefusalCodes =
        {
            SetIpBadArgs, SetIpNotPaused, SetIpOtherThread, SetIpNoContext, SetIpNotOnStatement,
            SetIpOtherModule, SetIpNoCode, SetIpAmbiguousLine, SetIpOtherProc, SetIpPrologue,
            SetIpCodeUnreadable, SetIpAcceptUnpaired, SetIpAcceptBoundary, SetIpWriteFailed,
        };

        /// <summary>The sentence the pad shows for a refusal code. Null for an unknown code, which
        /// protocolcheck treats as a failure: a code with no sentence would reach the user as a bare slug.</summary>
        internal static string SetIpMessage(string code)
        {
            switch (code)
            {
                case SetIpBadArgs:        return "Set next statement needs a module:line.";
                case SetIpNotPaused:      return "Set next statement only works while the program is paused.";
                case SetIpOtherThread:    return "Switch back to the stopped thread first: set next statement only moves the thread that stopped.";
                case SetIpNoContext:      return "Can't read the stopped thread's registers, so its next statement can't be moved.";
                case SetIpNotOnStatement: return "The program isn't stopped at the start of a source statement (for example, it was paused inside the runtime). Step to a line first.";
                case SetIpOtherModule:    return "That line is in a different source module. Set next statement only moves within the current procedure.";
                case SetIpNoCode:         return "That line has no code to run. Pick a line with a statement on it.";
                case SetIpAmbiguousLine:  return "That line compiles to more than one place (a loop head, for example), so the target is ambiguous.";
                case SetIpOtherProc:      return "That line is outside the current procedure or routine. Moving there would corrupt the stack.";
                case SetIpPrologue:       return "Can't move to or from a procedure's entry line: its stack frame is set up there.";
                case SetIpCodeUnreadable: return "Can't read the current procedure's code to check that the move is safe.";
                case SetIpAcceptUnpaired: return "Can't work out this procedure's ACCEPT loops, so no move inside it can be checked as safe.";
                case SetIpAcceptBoundary: return "Can't move across an ACCEPT loop boundary: the runtime keeps the loop's state on the stack.";
                case SetIpWriteFailed:    return "Couldn't set the thread's instruction pointer.";
                default:                  return null;
            }
        }

        // ------------------------------------------------------------------ ACCEPT regions (pure)

        /// <summary>One ACCEPT loop's body, as an address range. <see cref="Lo"/> is the Start call's return
        /// address (where the back-edge jumps to), <see cref="Hi"/> is one past the back-edge `je`.
        /// <see cref="StartCall"/> is the region's identity: two addresses are in the same loop exactly when
        /// their innermost regions have the same StartCall.</summary>
        internal struct EventLoopRegion
        {
            public uint StartCall;
            public uint Lo;
            public uint Hi;
            public bool Contains(uint a) { return a >= Lo && a < Hi; }
        }

        private const string StartEventLoopName = "Cla$StartEventLoop";
        private const string EndEventLoopName   = "Cla$EndEventLoop";

        /// <summary>Which of the two event-loop imports an IAT name is, from a "dll!func" name: 1 = Start,
        /// 2 = End, 0 = neither. The function part must match exactly (case-sensitive, as ClaRUN exports it)
        /// and the DLL must be ClaRUN.</summary>
        private static int EventLoopImportKind(string name)
        {
            if (string.IsNullOrEmpty(name)) return 0;
            int bang = name.LastIndexOf('!');
            if (bang <= 0) return 0;
            if (!string.Equals(name.Substring(0, bang), "ClaRUN.dll", StringComparison.OrdinalIgnoreCase)) return 0;
            string fn = name.Substring(bang + 1);
            if (fn == StartEventLoopName) return 1;
            if (fn == EndEventLoopName) return 2;
            return 0;
        }

        /// <summary>
        /// Find every ACCEPT loop in one procedure's code. PURE: a function of the bytes, the address of
        /// <paramref name="code"/>[0], and a lookup from an absolute IAT slot address to its "dll!func" name
        /// (null when the address is not an import slot). Returns null and fills <paramref name="regions"/>
        /// on success; returns a short reason, and leaves no regions, when the structure cannot be trusted.
        ///
        /// FAIL CLOSED, in every way it can be wrong:
        ///   - every Start call must be claimed by exactly one back-edge, and every End call must be a
        ///     back-edge (`call [End]; cmp al,0; je T`) whose T is some Start call's return address;
        ///   - regions must nest properly (disjoint or one inside the other);
        ///   - a RAW scan for the two slot addresses, at every byte offset, must count exactly as many
        ///     references as the decoder found calls. A linear sweep that desyncs (data in code, a jump table)
        ///     can hide a call from the decoder; it cannot hide the slot address from a byte scan. So can any
        ///     other way of reaching the import (`mov reg,[slot]; call reg`), and a stray immediate that
        ///     happens to equal a slot address. All of them refuse, rather than read as "no ACCEPT here".
        /// </summary>
        internal static string FindEventLoopRegions(byte[] code, int len, uint baseAddr, Func<uint, string> slotName,
                                                    List<EventLoopRegion> regions)
        {
            regions.Clear();
            if (code == null || len <= 0 || len > code.Length) return "no code";

            // 1) raw references to either slot, at every byte offset
            int rawRefs = 0;
            for (int i = 0; i + 4 <= len; i++)
                if (EventLoopImportKind(slotName(BitConverter.ToUInt32(code, i))) != 0) rawRefs++;

            // 2) linear decode
            var reader = new Iced.Intel.ByteArrayCodeReader(code, 0, len);
            var decoder = Iced.Intel.Decoder.Create(32, reader);
            decoder.IP = baseAddr;
            var ins = new List<Iced.Intel.Instruction>();
            while (reader.CanReadByte)
            {
                Iced.Intel.Instruction instr;
                decoder.Decode(out instr);
                ins.Add(instr);   // invalid ones too: they keep the indexes honest and never match below
            }

            var starts = new Dictionary<uint, uint>();   // Start call's return address -> Start call site
            var ends = new List<int>();                  // instruction index of each End call
            for (int k = 0; k < ins.Count; k++)
            {
                int kind = CallSlotKind(ins[k], slotName);
                if (kind == 1) starts[(uint)ins[k].NextIP] = (uint)ins[k].IP;
                else if (kind == 2) ends.Add(k);
            }
            if (starts.Count + ends.Count != rawRefs)
                return "event-loop import referenced " + rawRefs + " time(s) but decoded as " + (starts.Count + ends.Count) + " call(s)";

            // 3) pair each back-edge with the Start whose return address its je targets
            var claimed = new HashSet<uint>();
            var found = new List<EventLoopRegion>();
            foreach (int k in ends)
            {
                if (k + 2 >= ins.Count) return "EndEventLoop at 0x" + ((uint)ins[k].IP).ToString("X") + " has no back-edge after it";
                var cmp = ins[k + 1];
                var je = ins[k + 2];
                // `cmp al,0` has two encodings: 3C 00 (what clbrws has, 2 bytes at 0x756A3) and 80 F8 00.
                bool cmpAl0 = (cmp.Code == Iced.Intel.Code.Cmp_AL_imm8 || cmp.Code == Iced.Intel.Code.Cmp_rm8_imm8)
                              && cmp.Op0Kind == Iced.Intel.OpKind.Register
                              && cmp.Op0Register == Iced.Intel.Register.AL && cmp.Immediate8 == 0;
                bool isJe = je.Code == Iced.Intel.Code.Je_rel8_32 || je.Code == Iced.Intel.Code.Je_rel32_32;
                if (!cmpAl0 || !isJe) return "EndEventLoop at 0x" + ((uint)ins[k].IP).ToString("X") + " is not followed by cmp al,0 / je";
                uint target = (uint)je.NearBranchTarget;
                uint startCall;
                if (!starts.TryGetValue(target, out startCall))
                    return "back-edge at 0x" + ((uint)je.IP).ToString("X") + " targets 0x" + target.ToString("X") + ", which is no StartEventLoop return address";
                if (!claimed.Add(target)) return "StartEventLoop at 0x" + startCall.ToString("X") + " has two back-edges";
                found.Add(new EventLoopRegion { StartCall = startCall, Lo = target, Hi = (uint)je.NextIP });
            }
            if (claimed.Count != starts.Count) return "a StartEventLoop call has no back-edge";

            // 4) proper nesting
            for (int a = 0; a < found.Count; a++)
                for (int b = 0; b < found.Count; b++)
                {
                    if (a == b) continue;
                    var x = found[a]; var y = found[b];
                    bool disjoint = x.Hi <= y.Lo || y.Hi <= x.Lo;
                    bool xInY = x.Lo >= y.Lo && x.Hi <= y.Hi;
                    bool yInX = y.Lo >= x.Lo && y.Hi <= x.Hi;
                    if (!disjoint && !xInY && !yInX) return "ACCEPT regions overlap without nesting";
                }

            regions.AddRange(found);
            return null;
        }

        /// <summary>1/2 when <paramref name="i"/> is `call dword ptr [disp32]` through the Start/End slot.</summary>
        private static int CallSlotKind(Iced.Intel.Instruction i, Func<uint, string> slotName)
        {
            if (i.Code != Iced.Intel.Code.Call_rm32 || i.Op0Kind != Iced.Intel.OpKind.Memory) return 0;
            if (i.MemoryBase != Iced.Intel.Register.None || i.MemoryIndex != Iced.Intel.Register.None) return 0;
            return EventLoopImportKind(slotName((uint)i.MemoryDisplacement64));
        }

        /// <summary>The INNERMOST region containing <paramref name="addr"/>, as its StartCall, or 0 when the
        /// address is in no ACCEPT at all. Regions nest properly (FindEventLoopRegions refuses otherwise), so
        /// the innermost containing region is the one with the greatest Lo.</summary>
        internal static uint InnermostEventLoop(List<EventLoopRegion> regions, uint addr)
        {
            uint best = 0, bestLo = 0; bool any = false;
            foreach (var r in regions)
                if (r.Contains(addr) && (!any || r.Lo > bestLo)) { best = r.StartCall; bestLo = r.Lo; any = true; }
            return any ? best : 0;
        }

        // ------------------------------------------------------------------ the decision (pure)

        /// <summary>Everything <see cref="DecideSetIp"/> needs, gathered by the handler. A plain bag so
        /// protocolcheck can build one by hand and move ONE field at a time.</summary>
        internal sealed class SetIpFacts
        {
            public uint StoppedTid;
            public uint SelectedTid;
            public bool HaveCtx;
            public bool Resolved;          // the stop resolved to a line record
            public uint Gap;               // EIP minus that record's RVA
            public bool ModuleInImage;     // the requested .clw is a compiland of the STOPPED image
            public int  TargetRvaCount;    // records for the requested line in that compiland
            public bool StopSymKnown;      // the stop resolved to a verified symbol
            public uint StopEntryRva;
            public uint NextEntryRva;      // 0 = no following symbol (the span has no upper bound)
            public bool TargetSymKnown;
            public uint TargetEntryRva;
            public uint StopRva;
            public uint TargetRva;
            public uint FirstRecordRva;    // the stop symbol's entry record (0 = none of its own)
            public string RegionError;     // FindEventLoopRegions' reason; null = regions are good
            public bool CodeRead;          // the span's bytes were read
            public List<EventLoopRegion> Regions = new List<EventLoopRegion>();
            public uint LoadBase;          // regions are in VA; stop/target are RVAs
        }

        /// <summary>
        /// The refusal code for a setip, or null to go ahead. PURE. The order is the order of the codes in
        /// <see cref="SetIpRefusalCodes"/>, and it matters only for which reason the user reads first when two
        /// apply; each test is independent of the others.
        /// </summary>
        internal static string DecideSetIp(SetIpFacts f)
        {
            if (f.SelectedTid != f.StoppedTid) return SetIpOtherThread;
            if (!f.HaveCtx) return SetIpNoContext;
            // Only a stop exactly on a statement boundary has nothing of the CURRENT statement on the stack.
            // Breakpoint and step stops are; a Pause inside ClaRUN or mid-statement is not.
            if (!f.Resolved || f.Gap != 0) return SetIpNotOnStatement;
            if (!f.ModuleInImage) return SetIpOtherModule;
            if (f.TargetRvaCount == 0) return SetIpNoCode;
            if (f.TargetRvaCount > 1) return SetIpAmbiguousLine;
            // Same symbol AND inside its span. A ROUTINE is its own symbol with its own EBP frame and its own
            // return address on the stack, so routine <-> procedure is refused here too, which is correct.
            if (!f.StopSymKnown || !f.TargetSymKnown || f.TargetEntryRva != f.StopEntryRva) return SetIpOtherProc;
            if (f.TargetRva < f.StopEntryRva || (f.NextEntryRva != 0 && f.TargetRva >= f.NextEntryRva)) return SetIpOtherProc;
            // The entry record runs the prologue (push ebp / sub esp,N): moving TO it builds a second frame on
            // top of the first, and moving FROM it (a step-into lands there) leaves the frame unbuilt.
            if (IsPrologueRecord(f.TargetRva, f.FirstRecordRva) || IsPrologueRecord(f.StopRva, f.FirstRecordRva)) return SetIpPrologue;
            if (!f.CodeRead) return SetIpCodeUnreadable;
            if (f.RegionError != null) return SetIpAcceptUnpaired;
            // THE ACCEPT RULE: the same innermost loop, or both outside every loop. This is also what refuses
            // BREAK out of an ACCEPT and any target past the loop's end from inside it: the target is outside
            // the region, so the innermost regions differ. That refusal is deliberate - leaving the loop by
            // moving EIP orphans ClaRUN's loop state on the stack - so do not "fix" it into a pass.
            if (InnermostEventLoop(f.Regions, f.LoadBase + f.StopRva) != InnermostEventLoop(f.Regions, f.LoadBase + f.TargetRva))
                return SetIpAcceptBoundary;
            return null;
        }

        /// <summary>At or below the procedure's first record: its entry, where the frame is built. A
        /// procedure with no record of its own (0) has nothing to compare, and the other tests decide.</summary>
        private static bool IsPrologueRecord(uint rva, uint firstRecordRva)
        {
            return firstRecordRva != 0 && rva <= firstRecordRva;
        }

        // ------------------------------------------------------------------ wire

        /// <summary>The success reply. No tid member here: EmitThreadEvent stamps it through WithTid, which
        /// is the one place an unknown tid becomes an ABSENT member.</summary>
        internal static string SetIpOkJson(string module, int line, int fromLine, uint rva, uint va)
        {
            return "{\"event\":\"setip\",\"ok\":true"
                 + ",\"module\":" + Json.Str(module)
                 + ",\"line\":" + line
                 + ",\"fromLine\":" + fromLine
                 + ",\"rva\":\"0x" + rva.ToString("X") + "\""
                 + ",\"va\":\"0x" + va.ToString("X") + "\"}";
        }

        /// <summary>A refusal. <paramref name="module"/> null / <paramref name="line"/> &lt;= 0 omit the
        /// member (an unparsable request has neither); <paramref name="candidates"/> is written only for
        /// ambiguous-line.</summary>
        internal static string SetIpRefusedJson(string code, string module, int line, int candidates)
        {
            var sb = new StringBuilder("{\"event\":\"setip\",\"ok\":false");
            sb.Append(",\"reason\":").Append(Json.Str(code));
            sb.Append(",\"error\":").Append(Json.Str(SetIpMessage(code) ?? code));
            if (module != null) sb.Append(",\"module\":").Append(Json.Str(module));
            if (line > 0) sb.Append(",\"line\":").Append(line);
            if (code == SetIpAmbiguousLine) sb.Append(",\"candidates\":").Append(candidates);
            return sb.Append('}').ToString();
        }

        /// <summary>Parse `setip module:line`, splitting on the LAST colon like the host's ModuleLineRequest.
        /// The module must be a bare .clw basename: [A-Za-z0-9_.-], the host's IsValidModuleName.</summary>
        internal static bool TryParseSetIpArgs(string[] parts, out string module, out int line)
        {
            module = null; line = 0;
            if (parts == null || parts.Length != 2) return false;
            string spec = parts[1];
            int c = spec.LastIndexOf(':');
            if (c <= 0 || c == spec.Length - 1) return false;
            string mod = spec.Substring(0, c);
            foreach (char ch in mod)
                if (!(char.IsLetterOrDigit(ch) && ch < 128) && ch != '_' && ch != '.' && ch != '-') return false;
            int ln;
            if (!int.TryParse(spec.Substring(c + 1), System.Globalization.NumberStyles.None,
                              System.Globalization.CultureInfo.InvariantCulture, out ln) || ln <= 0) return false;
            module = mod; line = ln;
            return true;
        }

        /// <summary>`setip` while the target runs. Not thread-scoped: there is no stop, so no tid.</summary>
        private void EmitSetIpNotPaused(string[] parts)
        {
            string module; int line;
            TryParseSetIpArgs(parts, out module, out line);
            if (EmitJson) Console.WriteLine("@JSON " + SetIpRefusedJson(SetIpNotPaused, module, line, 0));
            else Console.WriteLine("  setip: " + SetIpMessage(SetIpNotPaused));
        }

        // ------------------------------------------------------------------ the handler

        /// <summary>
        /// setip module:line, on the STOPPED thread. Returns true when EIP moved; the caller then re-runs the
        /// stop announcement (<see cref="AnnounceStop"/>), which re-emits `paused` with reason "setip" and
        /// recomputes the pause loop's locals, so a Step that follows compares against the NEW line.
        /// On false, nothing changed: not EIP, not a byte, not the re-arm.
        /// </summary>
        private bool HandleSetIpCommand(string[] parts, uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            string module; int line;
            if (!TryParseSetIpArgs(parts, out module, out line))
            {
                EmitSetIpRefusal(tid, SetIpBadArgs, module, line, 0);
                return false;
            }

            var f = new SetIpFacts { StoppedTid = tid, SelectedTid = _selectedTid, HaveCtx = haveCtx };
            LoadedModule m = null;
            int fromLine = 0, mi = -1, targetMi = -1;
            List<uint> rvas = null;
            if (haveCtx)
            {
                m = ModuleAt(ctx.Eip);
                if (m != null && m.Dbg != null)
                {
                    f.LoadBase = m.LoadBase;
                    f.StopRva = ctx.Eip - m.LoadBase;
                    uint recRva;
                    f.Resolved = m.Dbg.ResolveAddr(f.StopRva, out fromLine, out mi, out recRva);
                    f.Gap = f.Resolved ? f.StopRva - recRva : 0;

                    // The target is looked up in the STOPPED image only, never across images, so a same-named
                    // .clw in another DLL cannot arise: it would be a different procedure anyway.
                    targetMi = m.Dbg.FindModuleIdx(module);
                    f.ModuleInImage = targetMi >= 0;
                    rvas = f.ModuleInImage ? m.Dbg.LineToRvasInModuleIdx(targetMi, line) : new List<uint>();
                    f.TargetRvaCount = rvas.Count;
                    if (rvas.Count == 1) f.TargetRva = rvas[0];

                    // ResolveSymbolVerified for BOTH ends: raw ResolveSymbol at an entry can inherit the
                    // previous compiland's symbol, and a wrong "same symbol" here is a stack corruption.
                    ProcSymbol stopSym, targetSym = null;
                    f.StopSymKnown = m.Dbg.ResolveSymbolVerified(f.StopRva, out stopSym);
                    f.TargetSymKnown = rvas.Count == 1 && m.Dbg.ResolveSymbolVerified(f.TargetRva, out targetSym);
                    if (f.TargetSymKnown) f.TargetEntryRva = targetSym.EntryRva;
                    if (f.StopSymKnown)
                    {
                        f.StopEntryRva = stopSym.EntryRva;
                        f.NextEntryRva = m.Dbg.NextSymbolEntryRva(stopSym.EntryRva);
                        f.FirstRecordRva = FirstRecordRvaInProc(m, stopSym.EntryRva);
                        ReadEventLoopRegions(m, f);
                    }
                }
            }

            string refusal = DecideSetIp(f);
            if (refusal != null)
            {
                EmitSetIpRefusal(tid, refusal, module, line, rvas != null ? rvas.Count : 0);
                return false;
            }

            uint oldVa = ctx.Eip;
            uint newVa = m.LoadBase + f.TargetRva;

            // EIP FIRST. If the context write fails, nothing else has changed yet, and the refusal is true.
            var moved = ctx;
            moved.Eip = newVa;
            if (!Native.SetThreadContext(hThread, ref moved))
            {
                EmitSetIpRefusal(tid, SetIpWriteFailed, module, line, 0);
                return false;
            }
            ctx.Eip = newVa;

            // THE RE-ARM HANDOVER (risk 5). _rearm holds ONE entry per thread. At a breakpoint stop it is the
            // hit VA, whose byte was restored so the real instruction can run. If we left that entry and the
            // target is itself armed, RestoreIfArmed would OVERWRITE it, and the origin breakpoint would never
            // be re-planted: it would silently stop firing. So re-plant the OLD VA first - EIP no longer sits
            // on it, so 0xCC there is safe - and only then restore the target's byte and record the new one.
            Rearm pr;
            if (_rearm.TryGetValue(tid, out pr) && pr.Va != newVa)
            {
                bool stillWanted = pr.IsTemp ? _temp.ContainsKey(pr.Va) : _armed.ContainsKey(pr.Va);
                if (stillWanted) WriteByte(pr.Va, 0xCC);
                _rearm.Remove(tid);
            }
            RestoreIfArmed(tid, newVa);

            string canon = m.Dbg.ModuleNameForIdx(targetMi) ?? module;
            if (EmitJson) EmitThreadEvent(tid, SetIpOkJson(canon, line, fromLine, f.TargetRva, newVa));
            Console.WriteLine($"  setip: {canon}:{line} (from line {fromLine}, EIP 0x{oldVa:X8} -> 0x{newVa:X8})");
            return true;
        }

        /// <summary>Read the stop symbol's span and find its ACCEPT loops into <paramref name="f"/>. The bytes
        /// come from the live image through ReadCleanBlock, so our own INT3s read as the original code, and
        /// the IAT slot addresses in them are the relocated ones that LoadBase + slot RVA name.</summary>
        private void ReadEventLoopRegions(LoadedModule m, SetIpFacts f)
        {
            f.CodeRead = false;
            // The last symbol in an image has no upper bound; a span we cannot bound is a span we cannot check.
            if (f.NextEntryRva == 0 || f.NextEntryRva <= f.StopEntryRva) return;
            uint size = f.NextEntryRva - f.StopEntryRva;
            if (size > MAX_SETIP_SPAN || m.Pe == null) return;
            var buf = new byte[size];
            int got = ReadCleanBlock(m.LoadBase + f.StopEntryRva, buf);
            if (got != (int)size) return;
            f.CodeRead = true;

            var iat = m.Pe.BuildIatNameMap();   // slot RVA -> "dll!func"
            uint loadBase = m.LoadBase;
            Func<uint, string> slotName = abs =>
            {
                string nm;
                return abs >= loadBase && iat.TryGetValue(abs - loadBase, out nm) ? nm : null;
            };
            f.RegionError = FindEventLoopRegions(buf, got, loadBase + f.StopEntryRva, slotName, f.Regions);
        }

        /// <summary>1 MB: far past any real procedure (the largest measured was 0x4188 bytes), and a bound on
        /// what a garbage span can make us read.</summary>
        private const uint MAX_SETIP_SPAN = 0x100000;

        private void EmitSetIpRefusal(uint tid, string code, string module, int line, int candidates)
        {
            if (EmitJson) EmitThreadEvent(tid, SetIpRefusedJson(code, module, line, candidates));
            Console.WriteLine("  setip refused (" + code + "): " + SetIpMessage(code));
        }
    }
}
