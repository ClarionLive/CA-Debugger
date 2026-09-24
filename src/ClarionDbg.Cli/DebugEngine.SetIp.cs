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
    // NOT MEASURED, and so not claimed: REPORT/PRINT, nested ACCEPT, BREAK out of an ACCEPT. (LOOP i = 1 TO n
    // was measured later the same day: ESP constant over 23 iterations of SetupStringStops.)
    //
    // That rule alone was not enough (pipeline run 1): "no ACCEPT crossing" is not "ESP equal at the stop
    // and at the target". A move is now allowed by one of two paths - the PROOF (every call in the procedure
    // has a known effect on ESP, plus the ACCEPT rule) or the OBSERVED path (this frame instance already
    // stopped at the target with the current ESP). Both are below.
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
        internal const string SetIpStackUnproven   = "stack-unproven";
        internal const string SetIpAcceptBoundary  = "accept-boundary";
        internal const string SetIpWriteFailed     = "write-failed";

        /// <summary>Every refusal code, in the order <see cref="DecideSetIp"/> tests them (bad-args and
        /// not-paused come first because they are decided before there is a stop to test). protocolcheck
        /// reads this rather than retyping it.</summary>
        internal static readonly string[] SetIpRefusalCodes =
        {
            SetIpBadArgs, SetIpNotPaused, SetIpOtherThread, SetIpNoContext, SetIpNotOnStatement,
            SetIpOtherModule, SetIpNoCode, SetIpAmbiguousLine, SetIpOtherProc, SetIpPrologue,
            SetIpCodeUnreadable, SetIpAcceptUnpaired, SetIpStackUnproven, SetIpAcceptBoundary, SetIpWriteFailed,
        };

        /// <summary>How to get past a proof refusal: the observed path allows a move back to a line this frame
        /// has already stopped on at the same stack depth.</summary>
        internal const string SetIpStepFirstHint = "Step to that line first; then you can return to it.";

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
                case SetIpCodeUnreadable: return "Can't read the current procedure's code, so the move can't be checked.";
                // Only stack-unproven carries the step-first hint: it is the ONE refusal the observed path can
                // override. The two ACCEPT refusals bind both paths (pipeline run 2), so no way round them exists.
                case SetIpAcceptUnpaired: return "Can't work out this procedure's ACCEPT loops, so the move can't be checked.";
                case SetIpStackUnproven:  return "Can't prove the stack is the same at that line: this procedure calls code whose effect on the stack was never measured. " + SetIpStepFirstHint;
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

            // 2) linear decode. Invalid instructions stay in: they keep the indexes honest and never match below.
            var ins = DecodeLinear(code, len, baseAddr);

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
                var je = ins[k + 2];
                if (!IsBackEdge(ins[k + 1], je)) return "EndEventLoop at 0x" + ((uint)ins[k].IP).ToString("X") + " is not followed by cmp al,0 / je";
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

        /// <summary>A linear 32-bit decode of <paramref name="code"/>[0, len) placed at <paramref name="baseAddr"/>,
        /// INVALID instructions included. What one of those means is each caller's call: FindEventLoopRegions
        /// keeps them so its instruction indexes stay honest, ProveCallsBalanced refuses the procedure.</summary>
        private static List<Iced.Intel.Instruction> DecodeLinear(byte[] code, int len, uint baseAddr)
        {
            var reader = new Iced.Intel.ByteArrayCodeReader(code, 0, len);
            var decoder = Iced.Intel.Decoder.Create(32, reader);
            decoder.IP = baseAddr;
            var ins = new List<Iced.Intel.Instruction>();
            while (reader.CanReadByte)
            {
                Iced.Intel.Instruction i;
                decoder.Decode(out i);
                ins.Add(i);
            }
            return ins;
        }

        /// <summary>Is <paramref name="i"/> `call dword ptr [disp32]`, with no base or index register: a call
        /// through the absolute address <paramref name="slot"/>, which for an import is its IAT slot?</summary>
        private static bool IsAbsoluteSlotCall(Iced.Intel.Instruction i, out uint slot)
        {
            slot = 0;
            if (i.Code != Iced.Intel.Code.Call_rm32 || i.Op0Kind != Iced.Intel.OpKind.Memory) return false;
            if (i.MemoryBase != Iced.Intel.Register.None || i.MemoryIndex != Iced.Intel.Register.None) return false;
            slot = (uint)i.MemoryDisplacement64;
            return true;
        }

        /// <summary>1/2 when <paramref name="i"/> is `call dword ptr [disp32]` through the Start/End slot.</summary>
        private static int CallSlotKind(Iced.Intel.Instruction i, Func<uint, string> slotName)
        {
            uint slot;
            return IsAbsoluteSlotCall(i, out slot) ? EventLoopImportKind(slotName(slot)) : 0;
        }

        /// <summary>Which event-loop import the ONE call instruction at <paramref name="callVa"/> calls, by the
        /// same test FindEventLoopRegions uses (<see cref="CallSlotKind"/>): 1 = Start, 2 = End, 0 = anything
        /// else. <paramref name="retVa"/> is the return address the step machine saw on the stack; a decode
        /// that does not end exactly there is not this call, and answers 0. PURE, like FindEventLoopRegions:
        /// the step machine's consumer is <see cref="EventLoopCallKindAt"/>.</summary>
        internal static int EventLoopCallKind(byte[] code, int len, uint callVa, uint retVa, Func<uint, string> slotName)
        {
            if (code == null || len <= 0 || len > code.Length) return 0;
            var decoder = Iced.Intel.Decoder.Create(32, new Iced.Intel.ByteArrayCodeReader(code, 0, len));
            decoder.IP = callVa;
            Iced.Intel.Instruction i;
            decoder.Decode(out i);
            if ((uint)i.NextIP != retVa) return 0;
            return CallSlotKind(i, slotName);
        }

        /// <summary>Are these the two instructions after `call [End]` that make an ACCEPT back-edge,
        /// `cmp al,0; je T`?</summary>
        private static bool IsBackEdge(Iced.Intel.Instruction cmp, Iced.Intel.Instruction je)
        {
            // `cmp al,0` has two encodings: 3C 00 (what clbrws has, 2 bytes at 0x756A3) and 80 F8 00.
            bool cmpAl0 = (cmp.Code == Iced.Intel.Code.Cmp_AL_imm8 || cmp.Code == Iced.Intel.Code.Cmp_rm8_imm8)
                          && cmp.Op0Kind == Iced.Intel.OpKind.Register
                          && cmp.Op0Register == Iced.Intel.Register.AL && cmp.Immediate8 == 0;
            bool isJe = je.Code == Iced.Intel.Code.Je_rel8_32 || je.Code == Iced.Intel.Code.Je_rel32_32;
            return cmpAl0 && isJe;
        }

        /// <summary>The loop head T of the back-edge `cmp al,0; je T` starting at <paramref name="at"/> (the
        /// return address of a `call [End]`), or 0 when the bytes there are not that shape. T is the Start
        /// call's return address. PURE.
        ///
        /// The step machine needs it because EndEventLoop does not return to its call site when the loop goes
        /// round: it re-seats ESP and resumes at T itself (measured on clbrws SplashScreen 2026-09-24: a temp
        /// INT3 at End's return address never fired, and the next pass ran from T). Only the loop's exit
        /// returns to the call site.</summary>
        internal static uint EventLoopBackEdgeTarget(byte[] code, int len, uint at)
        {
            if (code == null || len <= 0 || len > code.Length) return 0;
            var decoder = Iced.Intel.Decoder.Create(32, new Iced.Intel.ByteArrayCodeReader(code, 0, len));
            decoder.IP = at;
            Iced.Intel.Instruction cmp, je;
            decoder.Decode(out cmp);
            decoder.Decode(out je);   // bytes that run out decode as invalid, which IsBackEdge refuses
            return IsBackEdge(cmp, je) ? (uint)je.NearBranchTarget : 0;
        }

        /// <summary><see cref="EventLoopBackEdgeTarget"/> on the live image, read clean.</summary>
        private uint EventLoopBackEdgeTargetAt(uint at)
        {
            var buf = new byte[9];   // the longest back-edge: 80 F8 00 + 0F 84 rel32
            int got = ReadCleanBlock(at, buf);
            return got > 0 ? EventLoopBackEdgeTarget(buf, got, at) : 0;
        }

        /// <summary><see cref="EventLoopCallKind"/> on the live image: the call at <paramref name="callVa"/>,
        /// read clean (our INT3s show as the original bytes), with the slot names of the image it is in.</summary>
        private int EventLoopCallKindAt(uint callVa, uint retVa)
        {
            var m = ModuleAt(callVa);
            if (m == null || m.Pe == null || retVa <= callVa || retVa - callVa > CALL_WINDOW) return 0;
            var buf = new byte[retVa - callVa];
            if (ReadCleanBlock(callVa, buf) != buf.Length) return 0;
            return EventLoopCallKind(buf, buf.Length, callVa, retVa, IatSlotNames(m));
        }

        /// <summary>An absolute IAT slot address in <paramref name="m"/> to its "dll!func" name, or null.</summary>
        private static Func<uint, string> IatSlotNames(LoadedModule m)
        {
            var iat = m.Pe.BuildIatNameMap();   // slot RVA -> "dll!func"
            uint loadBase = m.LoadBase;
            return abs =>
            {
                string nm;
                return abs >= loadBase && iat.TryGetValue(abs - loadBase, out nm) ? nm : null;
            };
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

        // ------------------------------------------------------------------ every call balanced (pure)
        //
        // THE PROPERTY setip needs is "ESP at the target equals ESP at the stop". Finding no ACCEPT crossing
        // is NOT that property: it only rules out the ONE runtime construct that was measured to move ESP.
        // Anything else the procedure calls could keep state on the stack the same way, and a move past it
        // would corrupt the frame just as silently (pipeline run 1 on a77abd94, two HIGH findings). So every
        // call site in the span must be one whose effect is KNOWN:
        //   - a call to a Clarion procedure, routine or method (a TSWD symbol entry). Measured balanced: every
        //     DO and every procedure call in the 2026-09-23 traces left ESP where it was at the next statement;
        //   - a call to an import on MeasuredBalancedImports, directly (`call [slot]`) or through the image's
        //     own `jmp [slot]` thunk (`call rel32` to it: clbrws calls PUSHBIND this way, 0x401300);
        //   - Cla$StartEventLoop / Cla$EndEventLoop through `call [slot]`: the modelled ACCEPT pair, which
        //     FindEventLoopRegions reads and the ACCEPT rule decides.
        // ANYTHING ELSE makes the whole procedure `stack-unproven`: an unlisted import, an indirect call
        // (a CLASS method call through a vtable is one), a call into in-image code that is neither a symbol
        // nor a thunk (a LOCALLY-LINKED runtime is that: its entries are E8 calls to unnamed code in the EXE),
        // the event-loop pair reached any other way, and any sign the linear decode is out of step with the
        // code (an invalid instruction, a line record or a jump target that is not an instruction boundary).

        /// <summary>
        /// The imports whose calls were MEASURED to leave ESP unchanged at the next statement boundary.
        ///
        /// Measured 2026-09-23 on clbrws.exe (C11 HowToClarion\Browses) with `nexti` from ten breakpoints
        /// (SplashScreen and its routines, INIRestoreWindow, INISaveWindow, BrowseAuthors, BRW1::FillRecord,
        /// BRW1::FillQueue, SetupStringStops): an import is here only if it was EXECUTED inside a statement
        /// whose two boundaries (same frame, both gap 0) had the SAME ESP, and never inside one whose
        /// boundaries differed. Only the two event-loop entries ever appeared in an unbalanced statement.
        ///
        /// ADD NOTHING BY READING. An entry belongs here only when a trace shows it executed between two equal
        /// boundaries. A name that merely looks harmless is how the ACCEPT case would have been missed.
        /// </summary>
        internal static readonly string[] MeasuredBalancedImports =
        {
            // 549 balanced statement segments, 2026-09-23; the count is how often each ran inside one. The two
            // groups say only how each entry happened to be OBSERVED: an entry on the list counts as measured
            // whichever way it is called (IsMeasuredBalancedImport does not look at the call path).
            // (observed via `call [slot]`)
            "ClaRUN.dll!Cla$ADDqueue",            // 14
            "ClaRUN.dll!Cla$CLEAR",               // 3
            "ClaRUN.dll!Cla$comparestr",          // 2
            "ClaRUN.dll!Cla$DecDistinct",         // 16
            "ClaRUN.dll!Cla$DecDistinctR",        // 13
            "ClaRUN.dll!Cla$DPopLong",            // 12
            "ClaRUN.dll!Cla$DPushLong",           // 29
            "ClaRUN.dll!Cla$FILE_GET_PROPERTY",   // 14
            "ClaRUN.dll!Cla$FILE_SET_PROPERTY",   // 14
            "ClaRUN.dll!Cla$freestr",             // 2
            "ClaRUN.dll!Cla$FreeUfo",             // 8
            "ClaRUN.dll!Cla$GetPropS",            // 23
            "ClaRUN.dll!Cla$Mem2Ufo",             // 8
            "ClaRUN.dll!Cla$PopCString",          // 20
            "ClaRUN.dll!Cla$PopTemp",             // 2
            "ClaRUN.dll!Cla$PushCString",         // 18
            "ClaRUN.dll!Cla$PushLong",            // 93
            "ClaRUN.dll!Cla$PushString",          // 164
            "ClaRUN.dll!Cla$SetPropS",            // 4
            "ClaRUN.dll!Cla$SetPropV",            // 8
            "ClaRUN.dll!Cla$Stack2DStack",        // 41
            "ClaRUN.dll!Cla$StackCompareN",       // 4
            "ClaRUN.dll!Cla$StackRotate",         // 2
            "ClaRUN.dll!Cla$storestr",            // 1
            // (observed via the image's `jmp [slot]` thunk)
            "ClaRUN.dll!Cla$CLOSEwindow",         // 2
            "ClaRUN.dll!Cla$DISPLAY",             // 1
            "ClaRUN.dll!Cla$ERRORCODE",           // 14
            "ClaRUN.dll!Cla$EVENT",               // 21
            "ClaRUN.dll!Cla$FIELD",               // 9
            "ClaRUN.dll!Cla$FILE_NEXT",           // 14
            "ClaRUN.dll!Cla$GETINI",              // 12
            "ClaRUN.dll!Cla$IsAlpha",             // 20
            "ClaRUN.dll!Cla$KEYCODE",             // 2
            "ClaRUN.dll!Cla$OPENwindow",          // 1
            "ClaRUN.dll!Cla$PopBind",             // 2
            "ClaRUN.dll!Cla$POST",                // 2
            "ClaRUN.dll!Cla$PushBind",            // 2
            "ClaRUN.dll!Cla$PUTINI",              // 6
            "ClaRUN.dll!Cla$SELECT",              // 2
            "ClaRUN.dll!Cla$StackINSTRING",       // 40
            "ClaRUN.dll!Cla$THREAD",              // 1
        };

        /// <summary>The ClaRUN.dll the list was measured on: clbrws's runtime (C11 HowToClarion\Browses),
        /// FileVersion read 2026-09-23. Another ClaRUN may compile the same entry differently, so the PROOF
        /// path applies only to this one; any other loaded version is stack-unproven ("runtime X not measured").
        /// The observed path does not depend on it.</summary>
        internal const string MeasuredClaRunVersion = "10.0.12799";

        /// <summary>
        /// The version gate, keyed on WHAT THE PROOF USED (pipeline run 3). PURE. When the proof accepted no
        /// measured import there is no runtime to vouch for, and it passes. When it did, the module that
        /// actually SERVES that import - found through the live IAT slot, not by name - must be mapped, have a
        /// resolved path, a readable version, and exactly the measured one. Every other case is a detail.
        ///
        /// It was once keyed on "a module NAMED clarun.dll": a LOAD_DLL whose path did not resolve registers
        /// the image under a synthetic name, the lookup missed, "no ClaRUN loaded" read as nothing to check,
        /// and the proof passed on an unverified runtime.
        /// </summary>
        internal static string ClaRunVersionGate(bool usedMeasuredImport, bool servingModuleMapped, bool pathResolved, string fileVersion)
        {
            if (!usedMeasuredImport) return null;
            if (!servingModuleMapped) return "the runtime serving the measured imports is not a mapped module";
            if (!pathResolved) return "the runtime's path is unresolved, so its version cannot be read";
            if (string.IsNullOrEmpty(fileVersion)) return "runtime version unreadable";
            if (fileVersion == MeasuredClaRunVersion) return null;
            return "runtime ClaRUN.dll " + fileVersion + " not measured";
        }

        /// <summary>What one measured IAT slot the proof used resolves to, live.</summary>
        internal struct RuntimeSlotFact
        {
            public uint Slot;            // absolute IAT slot address
            public bool Read;            // the slot's live value was read
            public bool Mapped;          // ...and lands in a mapped module
            public bool PathResolved;
            public string Version;
        }

        /// <summary>The gate over EVERY distinct measured slot the proof used (pipeline run 3, second pass):
        /// each one's live target must be a mapped module with a resolved path and the measured version. An app
        /// that hooks its own IAT can point a LATER slot somewhere else, so checking only the first is not
        /// enough. Null when all pass (or there are none), else a detail naming the slot. PURE.</summary>
        internal static string ClaRunVersionGateAll(IList<RuntimeSlotFact> slots)
        {
            if (slots == null) return null;
            foreach (var f in slots)
            {
                string at = " (IAT slot 0x" + f.Slot.ToString("X") + ")";
                if (!f.Read) return "the live value of a measured import's slot could not be read" + at;
                string d = ClaRunVersionGate(true, f.Mapped, f.PathResolved, f.Version);
                if (d != null) return d + at;
            }
            return null;
        }

        private static readonly HashSet<string> _measuredBalanced = BuildMeasuredSet();
        private static HashSet<string> BuildMeasuredSet()
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            foreach (var n in MeasuredBalancedImports) set.Add(NormalizeImportName(n));
            return set;
        }

        /// <summary>"dll!func" with the DLL part lower-cased (the import table's spelling of a DLL varies)
        /// and the function part as is (ClaRUN's names are case-sensitive).</summary>
        private static string NormalizeImportName(string name)
        {
            int bang = name.LastIndexOf('!');
            return bang <= 0 ? name : name.Substring(0, bang).ToLowerInvariant() + "!" + name.Substring(bang + 1);
        }

        /// <summary>Is <paramref name="name"/> ("dll!func") on the measured list?</summary>
        internal static bool IsMeasuredBalancedImport(string name)
        {
            if (string.IsNullOrEmpty(name) || name.LastIndexOf('!') <= 0) return false;
            return _measuredBalanced.Contains(NormalizeImportName(name));
        }

        /// <summary>
        /// Prove every call in one procedure's code has a known effect on ESP. PURE: a function of the bytes,
        /// the address of <paramref name="code"/>[0], and three lookups over absolute addresses:
        /// <paramref name="slotName"/> (an IAT slot's "dll!func", or null), <paramref name="isSymbolEntry"/>
        /// (a Clarion procedure/routine/method entry) and <paramref name="thunkSlot"/> (the slot a
        /// `jmp [slot]` thunk at that address jumps through, or 0). <paramref name="recordVas"/> are the line
        /// records inside the span. Returns null when proven, or a short reason naming what could not be.
        /// </summary>
        internal static string ProveCallsBalanced(byte[] code, int len, uint baseAddr, Func<uint, string> slotName,
                                                  Func<uint, bool> isSymbolEntry, Func<uint, uint> thunkSlot,
                                                  IEnumerable<uint> recordVas)
        {
            List<uint> measuredSlots;
            return ProveCallsBalanced(code, len, baseAddr, slotName, isSymbolEntry, thunkSlot, recordVas, out measuredSlots);
        }

        /// <summary><see cref="ProveCallsBalanced(byte[],int,uint,Func{uint,string},Func{uint,bool},Func{uint,uint},IEnumerable{uint})"/>,
        /// also returning the DISTINCT IAT slots (absolute) of every measured import the proof relied on, in
        /// first-use order, empty when it relied on none - so the version gate checks the runtime each one
        /// really comes from.</summary>
        internal static string ProveCallsBalanced(byte[] code, int len, uint baseAddr, Func<uint, string> slotName,
                                                  Func<uint, bool> isSymbolEntry, Func<uint, uint> thunkSlot,
                                                  IEnumerable<uint> recordVas, out List<uint> measuredSlots)
        {
            measuredSlots = new List<uint>();
            if (code == null || len <= 0 || len > code.Length) return "no code";
            uint end = baseAddr + (uint)len;
            var ins = DecodeLinear(code, len, baseAddr);
            var starts = new HashSet<uint>();
            foreach (var i in ins)
            {
                if (i.IsInvalid) return "undecodable bytes at 0x" + ((uint)i.IP).ToString("X");
                starts.Add((uint)i.IP);
            }

            // In step with the code: every line record, and every jump that lands inside the span, must fall
            // on an instruction the sweep decoded. A sweep that drifted would disagree with one of them.
            var records = new List<uint>();
            if (recordVas != null)
                foreach (uint r in recordVas)
                {
                    if (r < baseAddr || r >= end) continue;
                    if (!starts.Contains(r)) return "the line record at 0x" + r.ToString("X") + " is not on an instruction boundary";
                    records.Add(r);
                }
            records.Sort();

            // THE PROLOGUE IS EXEMPT, and only the prologue: the code before the procedure's SECOND line
            // record. That is its entry record - push ebp / sub esp,N, and for a large frame a call to
            // ClaRUN!__a_chkstk that allocates it - and it runs once, before the first statement boundary.
            // setip refuses the entry record as both stop and target (IsPrologueRecord), so nothing there is
            // ever between two boundaries it moves across: whatever it does to ESP is already in the ESP
            // every statement shares. Measured 2026-09-23: every routine's entry record stood 4 below the
            // caller and its next record at the frame's base, which is that allocation.
            // With fewer than two records there is no prologue to tell apart, so NOTHING is exempt. (It once
            // fell back to `end`, exempting the whole procedure - a fail-open found by the mutation run: six
            // fixtures that pass no records went red on the CLEAN build.)
            uint bodyStart = records.Count >= 2 ? records[1] : baseAddr;

            foreach (var i in ins)
            {
                var fc = i.FlowControl;
                if (fc == Iced.Intel.FlowControl.ConditionalBranch || fc == Iced.Intel.FlowControl.UnconditionalBranch)
                {
                    if (i.Op0Kind == Iced.Intel.OpKind.NearBranch32 || i.Op0Kind == Iced.Intel.OpKind.NearBranch16)
                    {
                        uint t = (uint)i.NearBranchTarget;
                        if (t >= baseAddr && t < end && !starts.Contains(t))
                            return "a jump at 0x" + ((uint)i.IP).ToString("X") + " lands inside an instruction";
                    }
                    continue;
                }
                if (fc != Iced.Intel.FlowControl.Call && fc != Iced.Intel.FlowControl.IndirectCall) continue;
                if ((uint)i.IP < bodyStart) continue;   // the prologue: see bodyStart above

                uint measuredSlot;
                string why = ClassifyCall(i, slotName, isSymbolEntry, thunkSlot, out measuredSlot);
                if (why != null) return why;
                if (measuredSlot != 0 && !measuredSlots.Contains(measuredSlot)) measuredSlots.Add(measuredSlot);
            }
            return null;
        }

        /// <summary>One call instruction's effect on ESP: null when it is KNOWN (the list above this section),
        /// else the reason it is not. <paramref name="measuredSlot"/> is the IAT slot of the measured import it
        /// relied on, or 0 when it relied on none (Clarion code, or the ACCEPT pair).</summary>
        private static string ClassifyCall(Iced.Intel.Instruction i, Func<uint, string> slotName,
                                           Func<uint, bool> isSymbolEntry, Func<uint, uint> thunkSlot,
                                           out uint measuredSlot)
        {
            measuredSlot = 0;
            string at = " at 0x" + ((uint)i.IP).ToString("X");
            if (i.Code == Iced.Intel.Code.Call_rel32_32)
            {
                uint t = (uint)i.NearBranchTarget;
                if (isSymbolEntry(t)) return null;                        // a Clarion procedure / routine / method
                uint slot = thunkSlot(t);
                string viaThunk = slot != 0 ? slotName(slot) : null;
                if (viaThunk == null)
                    return "a call" + at + " to 0x" + t.ToString("X") + ", which is neither a procedure nor an import";
                if (EventLoopImportKind(viaThunk) != 0)
                    return viaThunk + " reached through a thunk" + at + ", not in the modelled ACCEPT shape";
                if (!IsMeasuredBalancedImport(viaThunk)) return viaThunk + " not measured";
                measuredSlot = slot;
                return null;
            }
            uint s;
            if (IsAbsoluteSlotCall(i, out s))
            {
                string name = slotName(s);
                if (name == null) return "a call" + at + " through 0x" + s.ToString("X") + ", which is not an import slot";
                if (EventLoopImportKind(name) != 0) return null;            // the ACCEPT pair: the region rule decides
                if (!IsMeasuredBalancedImport(name)) return name + " not measured";
                measuredSlot = s;
                return null;
            }
            return "an indirect call" + at + " (" + i.ToString() + ")";
        }

        // ------------------------------------------------------------------ OBSERVED ESP (the second path)
        //
        // The proof above covers 683 of clbrws's 2003 symbols (census, 2026-09-23): most procedures call some
        // runtime entry nobody measured. The Owner's rule for them (a77abd94 item 3): a move is ALSO allowed
        // when this thread has already STOPPED at the target's line record, in the SAME frame instance, and
        // the ESP recorded then equals the current ESP exactly. That is the property setip needs, observed
        // rather than proven - which is what makes "go back and run that again" work everywhere, while a
        // move FORWARD to a line not yet reached still needs the proof.

        /// <summary>
        /// Which frame an observation belongs to: (tid, image, procedure entry, EBP, return address).
        ///
        /// EBP ALONE IS NOT AN IDENTITY (the pid-is-not-an-identity lesson again): a later call at the same
        /// depth reuses it. The procedure entry and the return address at [EBP+4] narrow that to "the same
        /// procedure, called from the same call site, with its frame at the same address".
        ///
        /// WHAT THIS STILL CANNOT TELL APART: a later invocation of the same procedure from the same call site
        /// whose frame lands at the same EBP - a procedure called twice in a row from one loop, or a recursive
        /// call that returns and is made again. The key is identical, so the old invocation's observations
        /// match the new one. WHY THAT IS STILL SAFE: the same procedure entered from the same call site with
        /// the same EBP has run the same prologue from the same starting point, so its frame has the same base
        /// ESP. An observation says "at this line, ESP was E relative to that base", and E is a property of
        /// the frame's layout at that line, not of which invocation measured it. The match additionally
        /// requires ESP to be EQUAL NOW, so a stack that differs in depth (an ACCEPT's extra state, a
        /// different iteration) still refuses. What neither key nor ESP can vouch for is PROGRAM state -
        /// locals, files, windows - and that is the pad's hazard warning, as for every setip.
        /// </summary>
        internal struct SetIpFrameKey : IEquatable<SetIpFrameKey>
        {
            public uint Tid, LoadBase, EntryRva, Ebp, Ret;
            public bool Equals(SetIpFrameKey o)
            {
                return Tid == o.Tid && LoadBase == o.LoadBase && EntryRva == o.EntryRva && Ebp == o.Ebp && Ret == o.Ret;
            }
            public override bool Equals(object o) { return o is SetIpFrameKey && Equals((SetIpFrameKey)o); }
            public override int GetHashCode()
            {
                unchecked { return (int)(Tid * 31 + LoadBase * 17 + EntryRva * 13 + Ebp * 7 + Ret); }
            }
        }

        /// <summary>
        /// The observations: per frame instance, the ESP seen at each line record the thread stopped on.
        /// PURE state (no process access), so protocolcheck drives it directly.
        /// </summary>
        internal sealed class SetIpObservations
        {
            /// <summary>Total entries kept; the oldest go first. Far more than a debugging session steps.</summary>
            internal const int Cap = 4096;

            private struct Obs { public uint Esp; public long Seq; }
            private readonly Dictionary<SetIpFrameKey, Dictionary<uint, Obs>> _byFrame = new Dictionary<SetIpFrameKey, Dictionary<uint, Obs>>();
            private struct Slot { public SetIpFrameKey Frame; public uint Rva; public long Seq; }
            private readonly Queue<Slot> _order = new Queue<Slot>();
            private long _seq;
            private int _count;

            internal int Count { get { return _count; } }

            /// <summary>The thread stopped exactly on the record at <paramref name="rva"/> with this ESP.
            /// A re-visit replaces the old ESP: the latest measurement is the one that describes the frame.</summary>
            internal void Record(SetIpFrameKey frame, uint rva, uint esp)
            {
                Dictionary<uint, Obs> lines;
                if (!_byFrame.TryGetValue(frame, out lines)) { lines = new Dictionary<uint, Obs>(); _byFrame[frame] = lines; }
                if (!lines.ContainsKey(rva)) _count++;
                long seq = ++_seq;
                lines[rva] = new Obs { Esp = esp, Seq = seq };
                _order.Enqueue(new Slot { Frame = frame, Rva = rva, Seq = seq });
                while (_count > Cap && _order.Count > 0) EvictOldest();
                if (_order.Count > 4 * Cap) Compact();   // stale slots from re-visits (a loop) must not grow forever
            }

            /// <summary>Rebuild the queue from the live entries only, oldest first.</summary>
            private void Compact()
            {
                var live = new List<Slot>();
                foreach (var f in _byFrame)
                    foreach (var l in f.Value) live.Add(new Slot { Frame = f.Key, Rva = l.Key, Seq = l.Value.Seq });
                live.Sort((a, b) => a.Seq.CompareTo(b.Seq));
                _order.Clear();
                foreach (var s in live) _order.Enqueue(s);
            }

            /// <summary>Test seam: the queue's length, so protocolcheck can see that compaction bounds it.</summary>
            internal int QueueLengthForTest { get { return _order.Count; } }

            /// <summary>Was the record at <paramref name="rva"/> seen in THIS frame, with exactly this ESP?</summary>
            internal bool Matches(SetIpFrameKey frame, uint rva, uint currentEsp)
            {
                Dictionary<uint, Obs> lines;
                Obs o;
                return _byFrame.TryGetValue(frame, out lines) && lines.TryGetValue(rva, out o) && o.Esp == currentEsp;
            }

            /// <summary>At a stop of <paramref name="tid"/>: drop that thread's frames that have been popped,
            /// i.e. whose EBP is now BELOW the current ESP (the stack grows down, so a live frame's EBP is at
            /// or above ESP). Other threads' frames are not judged by this thread's ESP.</summary>
            internal void PrunePopped(uint tid, uint currentEsp)
            {
                var dead = new List<SetIpFrameKey>();
                foreach (var f in _byFrame.Keys) if (f.Tid == tid && f.Ebp < currentEsp) dead.Add(f);
                foreach (var f in dead) Remove(f);
            }

            /// <summary>A resume. EVERY thread but <paramref name="tid"/> runs freely now (the engine suspends
            /// none), so their observations go; <paramref name="tid"/>'s go too unless <paramref name="keepTid"/>.</summary>
            internal void OnResume(uint tid, bool keepTid)
            {
                var dead = new List<SetIpFrameKey>();
                foreach (var f in _byFrame.Keys) if (f.Tid != tid || !keepTid) dead.Add(f);
                foreach (var f in dead) Remove(f);
            }

            /// <summary>EXIT_THREAD: a reused tid must not inherit a dead thread's frames.</summary>
            internal void DropThread(uint tid)
            {
                var dead = new List<SetIpFrameKey>();
                foreach (var f in _byFrame.Keys) if (f.Tid == tid) dead.Add(f);
                foreach (var f in dead) Remove(f);
            }

            private void Remove(SetIpFrameKey f)
            {
                Dictionary<uint, Obs> lines;
                if (_byFrame.TryGetValue(f, out lines)) { _count -= lines.Count; _byFrame.Remove(f); }
            }

            /// <summary>The queue holds every Record in order, including ones since re-recorded or pruned. A
            /// slot evicts its entry only if that entry is still the one it recorded (same Seq); a stale slot
            /// is skipped, so a re-visit is never deleted by its own older queue slot.</summary>
            private void EvictOldest()
            {
                var s = _order.Dequeue();
                Dictionary<uint, Obs> lines;
                Obs o;
                if (!_byFrame.TryGetValue(s.Frame, out lines) || !lines.TryGetValue(s.Rva, out o) || o.Seq != s.Seq) return;
                lines.Remove(s.Rva); _count--;
                if (lines.Count == 0) _byFrame.Remove(s.Frame);
            }
        }

        private readonly SetIpObservations _setIpObs = new SetIpObservations();

        /// <summary>The frame instance the thread is in, or false when it cannot be identified (no
        /// symbol, or [EBP+4] unreadable): then nothing is recorded and nothing matches.</summary>
        private bool TryFrameKey(uint tid, ref Native.CONTEXT_X86 ctx, LoadedModule m, uint rva, out SetIpFrameKey key)
        {
            key = default(SetIpFrameKey);
            if (m == null || m.Dbg == null) return false;
            ProcSymbol sym;
            if (!m.Dbg.ResolveSymbolVerified(rva, out sym)) return false;
            var b = new byte[4];
            if (ReadBlock(ctx.Ebp + 4, b) != 4) return false;
            key = new SetIpFrameKey { Tid = tid, LoadBase = m.LoadBase, EntryRva = sym.EntryRva, Ebp = ctx.Ebp, Ret = BitConverter.ToUInt32(b, 0) };
            return true;
        }

        // ---- NO OBSERVATION SURVIVES A FREE RUN (pipeline run 2).
        //
        // PrunePopped only runs at stops. Across a free run a procedure can return and be entered again at
        // the SAME EBP from the SAME call site with no stop in between, and its old observations would then
        // match the new call. So a resume keeps a thread's observations only when that thread is
        // single-stepped the whole way to its next stop, where every trap is watched:
        //   - at the resume (ONE choke point: ArmResume's first statement, pinned by
        //     tools/test-engine-setip-sites.ps1): every OTHER thread runs freely, so theirs go; this thread's
        //     go unless the verb is step-into, step-over, stepi or nexti (step-out runs to the caller, and
        //     continue runs free);
        //   - during the step: the highest ESP any trap saw, so a frame the step popped and re-entered is
        //     pruned at the stop even though ESP is back below its EBP;
        //   - at the stop: a step that did not end as a step stop ("step"/"stepi") became a free run somewhere
        //     (a user breakpoint, a Pause, or the step-over-ACCEPT case that never stops, ticket 0f16e12c),
        //     and its observations go.

        /// <summary>Does a resume keep the resuming thread's observations? PURE. Only the verbs that
        /// single-step that thread all the way to its next stop.</summary>
        internal static bool ResumeKeepsObservations(bool stepping, bool instrStep, bool modeSingleStepsToStop, bool haveCtx)
        {
            // Without a context TF is never set (ArmResume returns first), so the "step" runs free (run 3).
            return haveCtx && stepping && (instrStep || modeSingleStepsToStop);
        }

        /// <summary>The step modes that single-step the thread to its next stop. Out is not one: it runs on
        /// through the procedure's return into the caller.</summary>
        private static bool ModeSingleStepsToStop(StepMode mode)
        {
            return mode == StepMode.Into || mode == StepMode.Over || mode == StepMode.OverInstr;
        }

        /// <summary>Test seam: <see cref="ModeSingleStepsToStop"/> by the mode's name (the enum is private).</summary>
        internal static bool ModeSingleStepsToStopForTest(string mode)
        {
            return ModeSingleStepsToStop((StepMode)Enum.Parse(typeof(StepMode), mode));
        }

        /// <summary>Does a stop with this reason keep the thread's observations? PURE. Only a step's own stop;
        /// setip re-announces without running anything.</summary>
        internal static bool StopKeepsObservations(string reason)
        {
            return reason == "step" || reason == "stepi" || reason == "setip";
        }

        private bool _setIpStepping;      // the resuming thread kept its observations: track its ESP until it stops
        private uint _setIpStepTid;
        private uint _setIpStepMaxEsp;    // the highest ESP the step's traps saw

        /// <summary>THE CHOKE POINT, called as ArmResume's first statement for every resume verb.</summary>
        private void SetIpOnResume(uint tid, bool stepping, bool haveCtx, uint esp)
        {
            bool keep = ResumeKeepsObservations(stepping, _instrStep, ModeSingleStepsToStop(_mode), haveCtx);
            _setIpObs.OnResume(tid, keep);
            _setIpStepping = keep;
            _setIpStepTid = tid;
            _setIpStepMaxEsp = esp;
        }

        /// <summary>The ESP a stop prunes popped frames by. PURE. After a watched step it is the HIGHEST ESP the
        /// step reached, not the current one: a frame the step popped and then re-entered at the same EBP has
        /// ESP back below its EBP by the time the thread stops.</summary>
        internal static uint PopLine(bool thisThreadStepped, uint stepMaxEsp, uint currentEsp)
        {
            return thisThreadStepped && stepMaxEsp > currentEsp ? stepMaxEsp : currentEsp;
        }

        /// <summary>Does passing a first-chance exception to the app end the watched step? PURE. Only for the
        /// thread whose observations were kept: the app's handler can unwind the frame and clear TF, a later
        /// silent tracepoint can set TF again, and the stop would then report "step" after a free run.</summary>
        internal static bool ExceptionPassedEndsWatchedStep(bool stepping, uint stepTid, uint tid)
        {
            return stepping && tid == stepTid;
        }

        /// <summary>The debug loop's EXCEPTION branch, where it returns DBG_EXCEPTION_NOT_HANDLED. Position
        /// pinned by tools/test-engine-setip-sites.ps1.</summary>
        private void SetIpOnExceptionPassed(uint tid)
        {
            if (!ExceptionPassedEndsWatchedStep(_setIpStepping, _setIpStepTid, tid)) return;
            _setIpObs.DropThread(tid);
            _setIpStepping = false;
        }

        /// <summary>From StepMachine, at every trap of the stepping thread.</summary>
        private void SetIpNoteStepEsp(uint tid, uint esp)
        {
            if (_setIpStepping && tid == _setIpStepTid && esp > _setIpStepMaxEsp) _setIpStepMaxEsp = esp;
        }

        /// <summary>At every stop (AnnounceStop, including setip's own re-announce): forget this thread's frames
        /// if the stop ended a free run, prune the frames it popped (by the highest ESP the step saw), then
        /// record the stop if it sits exactly on a line record.</summary>
        private void ObserveStop(uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx, LoadedModule m, uint rva, bool resolved, uint gap, string reason)
        {
            uint popLine = PopLine(_setIpStepping && tid == _setIpStepTid, _setIpStepMaxEsp, haveCtx ? ctx.Esp : 0);
            if (tid == _setIpStepTid) _setIpStepping = false;
            if (!StopKeepsObservations(reason)) _setIpObs.DropThread(tid);
            if (!haveCtx) return;
            _setIpObs.PrunePopped(tid, popLine);
            if (!resolved || gap != 0) return;
            SetIpFrameKey key;
            if (TryFrameKey(tid, ref ctx, m, rva, out key)) _setIpObs.Record(key, rva, ctx.Esp);
        }

        /// <summary>EXIT_THREAD hook (one line in the debug loop).</summary>
        private void ForgetSetIpThread(uint tid) { _setIpObs.DropThread(tid); }

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
            public string StackError;      // ProveCallsBalanced's reason; null = every call has a known effect
            public bool ObservedMatch;     // this frame instance was stopped at the target with the current ESP
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
            string allowedBy;
            return DecideSetIp(f, out allowedBy);
        }

        /// <summary>The path that allowed a move, on the success reply as "via".</summary>
        internal const string SetIpViaProof = "proof";
        internal const string SetIpViaObserved = "observed";

        /// <summary><see cref="DecideSetIp(SetIpFacts)"/>, also saying WHICH path allowed the move:
        /// <see cref="SetIpViaProof"/> when the call proof and the ACCEPT rule hold, else
        /// <see cref="SetIpViaObserved"/> when the target was seen in this frame at this ESP. Null on a refusal.</summary>
        internal static string DecideSetIp(SetIpFacts f, out string allowedBy)
        {
            allowedBy = null;
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

            // THE ACCEPT RULES BIND BOTH PATHS (pipeline run 2, two reviewers). Equal ESP says nothing about
            // whether the loop state ClaRUN keeps on the stack is the CURRENT loop's: two sibling ACCEPTs in
            // one frame run at the same steady depth, so an observation inside loop A matches a stop inside
            // loop B. And an unpaired scan means the structure is not known at all. So these two refuse
            // whatever was observed; "back within the same innermost loop" still works, which is the use.
            if (f.RegionError != null) return SetIpAcceptUnpaired;
            // THE ACCEPT RULE: the same innermost loop, or both outside every loop. This is also what refuses
            // BREAK out of an ACCEPT and any target past the loop's end from inside it: the target is outside
            // the region, so the innermost regions differ. That refusal is deliberate - leaving the loop by
            // moving EIP orphans ClaRUN's loop state on the stack - so do not "fix" it into a pass.
            if (InnermostEventLoop(f.Regions, f.LoadBase + f.StopRva) != InnermostEventLoop(f.Regions, f.LoadBase + f.TargetRva))
                return SetIpAcceptBoundary;
            // The stack itself: PROVEN (every call's effect on ESP is known - the ACCEPT rule above is only a
            // proof when the ACCEPT pair is the one call that moves ESP, pipeline run 1), or OBSERVED (this
            // frame stopped at the target with this very ESP). stack-unproven is the one refusal the observed
            // path overrides.
            if (f.StackError == null) { allowedBy = SetIpViaProof; return null; }
            if (f.ObservedMatch) { allowedBy = SetIpViaObserved; return null; }
            return SetIpStackUnproven;
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
        internal static string SetIpOkJson(string module, int line, int fromLine, uint rva, uint va, string via)
        {
            return "{\"event\":\"setip\",\"ok\":true"
                 + ",\"module\":" + Json.Str(module)
                 + ",\"line\":" + line
                 + ",\"fromLine\":" + fromLine
                 + ",\"rva\":\"0x" + rva.ToString("X") + "\""
                 + ",\"va\":\"0x" + va.ToString("X") + "\""
                 + ",\"via\":" + Json.Str(via) + "}";
        }

        /// <summary>A refusal. <paramref name="module"/> null / <paramref name="line"/> &lt;= 0 omit the
        /// member (an unparsable request has neither); <paramref name="candidates"/> is written only for
        /// ambiguous-line.</summary>
        internal static string SetIpRefusedJson(string code, string module, int line, int candidates, string detail = null)
        {
            var sb = new StringBuilder("{\"event\":\"setip\",\"ok\":false");
            sb.Append(",\"reason\":").Append(Json.Str(code));
            sb.Append(",\"error\":").Append(Json.Str(SetIpText(code, detail)));
            if (module != null) sb.Append(",\"module\":").Append(Json.Str(module));
            if (line > 0) sb.Append(",\"line\":").Append(line);
            if (code == SetIpAmbiguousLine) sb.Append(",\"candidates\":").Append(candidates);
            return sb.Append('}').ToString();
        }

        /// <summary>The sentence, plus what exactly was not proven when there is a detail:
        /// "Can't prove ... measured. (ClaRUN.dll!Cla$X not measured)".</summary>
        internal static string SetIpText(string code, string detail)
        {
            string msg = SetIpMessage(code) ?? code;
            return detail != null ? msg + " (" + detail + ")" : msg;
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
                        ReadProcCodeFacts(m, f);
                    }

                    // The observed path: has THIS frame instance stopped on the target with this very ESP?
                    SetIpFrameKey frame;
                    if (rvas.Count == 1 && TryFrameKey(tid, ref ctx, m, f.StopRva, out frame))
                        f.ObservedMatch = _setIpObs.Matches(frame, f.TargetRva, ctx.Esp);
                }
            }

            string via;
            string refusal = DecideSetIp(f, out via);
            if (refusal != null)
            {
                EmitSetIpRefusal(tid, refusal, module, line, rvas != null ? rvas.Count : 0,
                                 refusal == SetIpStackUnproven ? f.StackError
                                 : refusal == SetIpAcceptUnpaired ? f.RegionError : null);
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
            if (EmitJson) EmitThreadEvent(tid, SetIpOkJson(canon, line, fromLine, f.TargetRva, newVa, via));
            Console.WriteLine($"  setip: {canon}:{line} (from line {fromLine}, EIP 0x{oldVa:X8} -> 0x{newVa:X8}, via {via})");
            return true;
        }

        /// <summary>Read the stop symbol's span and record in <paramref name="f"/> the two facts setip's proof
        /// path decides on: its ACCEPT loops (<c>Regions</c>, or <c>RegionError</c>), and whether every call in
        /// it has a known effect on ESP on a measured runtime (<c>StackError</c>). The bytes come from the live
        /// image through ReadCleanBlock, so our own INT3s read as the original code, and the IAT slot addresses
        /// in them are the relocated ones that LoadBase + slot RVA name.</summary>
        private void ReadProcCodeFacts(LoadedModule m, SetIpFacts f)
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

            uint loadBase = m.LoadBase;
            Func<uint, string> slotName = IatSlotNames(m);
            f.RegionError = FindEventLoopRegions(buf, got, loadBase + f.StopEntryRva, slotName, f.Regions);

            // Every call must have a known effect on ESP (ProveCallsBalanced). Clarion code - a procedure,
            // routine or method entry - is one known case; the image's `jmp [slot]` thunks are read from the
            // live image, and only when the target is inside it.
            var entries = new HashSet<uint>();
            if (m.Dbg.Symbols != null)
                foreach (var sym in m.Dbg.Symbols)
                    if (sym.Kind == SymbolKind.Procedure || sym.Kind == SymbolKind.Routine || sym.Kind == SymbolKind.Method)
                        entries.Add(loadBase + sym.EntryRva);
            var records = new List<uint>();
            if (m.Dbg.AddrTable != null)
                foreach (var r in m.Dbg.AddrTable)
                    if (r.Rva >= f.StopEntryRva && r.Rva < f.NextEntryRva) records.Add(loadBase + r.Rva);
            Func<uint, uint> thunkSlot = va =>
            {
                if (!m.ContainsVa(va) || !m.ContainsVa(va + 5)) return 0;
                var t = new byte[6];
                if (ReadCleanBlock(va, t) != 6 || t[0] != 0xFF || t[1] != 0x25) return 0;   // jmp dword ptr [disp32]
                return BitConverter.ToUInt32(t, 2);
            };
            List<uint> measuredSlots;
            f.StackError = ProveCallsBalanced(buf, got, loadBase + f.StopEntryRva, slotName, entries.Contains, thunkSlot, records, out measuredSlots);
            if (f.StackError == null)
            {
                // The measured list is only a proof for the ClaRUN it was measured on - and "the ClaRUN" is the
                // module that SERVES each import the proof used, every one of them: the live IAT slot's target, whatever the image
                // was registered as. Mapped only (LoadBase != 0), the same filter ModuleByName applies.
                var facts = new List<RuntimeSlotFact>();
                foreach (uint slot in measuredSlots)
                {
                    var fact = new RuntimeSlotFact { Slot = slot };
                    var p = new byte[4];
                    if (ReadBlock(slot, p) == 4)
                    {
                        fact.Read = true;
                        var rt = ModuleAt(BitConverter.ToUInt32(p, 0));
                        fact.Mapped = rt != null && rt.LoadBase != 0;
                        fact.PathResolved = fact.Mapped && !string.IsNullOrEmpty(rt.Path);
                        try { if (fact.PathResolved) fact.Version = System.Diagnostics.FileVersionInfo.GetVersionInfo(rt.Path).FileVersion; } catch { }
                    }
                    facts.Add(fact);
                }
                f.StackError = ClaRunVersionGateAll(facts);
            }
        }

        /// <summary>1 MB: far past any real span, and a bound on what a garbage span can make us read. The
        /// largest span setip can read in clbrws.exe (symbol entry to the next, over all 2054 symbols, from
        /// `ClarionDbg symbols --json`) is 0x4B78 bytes, WMFPARSER.TAKERECORD: measured 2026-09-24. An earlier
        /// undated figure of 0x4188 could not be reproduced by that measure.</summary>
        private const uint MAX_SETIP_SPAN = 0x100000;

        private void EmitSetIpRefusal(uint tid, string code, string module, int line, int candidates, string detail = null)
        {
            if (EmitJson) EmitThreadEvent(tid, SetIpRefusedJson(code, module, line, candidates, detail));
            Console.WriteLine("  setip refused (" + code + "): " + SetIpText(code, detail));
        }
    }
}
