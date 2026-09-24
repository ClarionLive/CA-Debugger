using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ single-step machine

        private uint OnSingleStep(uint tid)
        {
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);

            // 1) pending re-plant after THIS thread stepped off a restored breakpoint byte
            Rearm pr;
            if (_rearm.TryGetValue(tid, out pr))
            {
                bool stillWanted = pr.IsTemp ? _temp.ContainsKey(pr.Va) : _armed.ContainsKey(pr.Va);
                if (stillWanted) WriteByte(pr.Va, 0xCC);
                _rearm.Remove(tid);
            }

            // 2) drive the step machine (TF auto-clears on each trap; re-set it to keep stepping)
            if (_mode != StepMode.None && tid == _stepTid && !_skipRunning && haveCtx)
                StepMachine(tid, hThread, ref ctx);

            // 3) instruction step (stepi): we asked for exactly one TF step — pause here at the new EIP.
            // If that lands exactly on an armed user breakpoint's byte (e.g. a breakpoint set on a
            // procedure's own entry line, then stepping INTO that call), restore-and-reschedule the
            // same way StopStepAndPause does — otherwise the still-planted 0xCC fires as a genuine
            // EXCEPTION_BREAKPOINT on the very next resume, reporting reason "breakpoint" instead of
            // "stepi" and spuriously jumping the host UI to source.
            else if (_instrStep && tid == _instrStepTid && haveCtx)
            {
                RestoreIfArmed(tid, ctx.Eip);
                PausedWait(tid, hThread, ref ctx, haveCtx, "stepi"); // PausedWait clears _instrStep
            }

            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        /// <summary>If <paramref name="va"/> carries an armed user breakpoint's byte, restore the
        /// original instruction so it executes correctly on resume, and schedule a re-plant after the
        /// thread takes one more step off it. Shared by every landing path (mode-driven step-stop and
        /// the raw single-instruction step) so none of them leave a stale 0xCC sitting where the debuggee
        /// is about to resume execution.</summary>
        private void RestoreIfArmed(uint tid, uint va)
        {
            byte orig;
            if (_armed.TryGetValue(va, out orig))
            {
                WriteByte(va, orig);
                _rearm[tid] = new Rearm { Va = va, IsTemp = false };
            }
        }

        private void StepMachine(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx)
        {
            _stepCount++;
            SetIpNoteStepEsp(tid, ctx.Esp);   // setip: the highest ESP this step reached (a frame it popped)
            uint va = ctx.Eip;
            var m = ModuleAt(va);
            uint rva = m != null ? va - m.LoadBase : va;

            // call-entry detection: the stack top holds an address just past the previous trap →
            // we just stepped INTO a CALL. Follow Clarion callees (step-into); skip everything else
            // at full speed via a temp INT3 at the return address.
            if (_prevVa != 0)
            {
                uint ret = ReadU32(ctx.Esp);
                if (ret > _prevVa && ret - _prevVa <= CALL_WINDOW && ret != va)
                {
                    bool follow = _mode == StepMode.Into && HasRecordInRange(m, rva, PROLOGUE_WINDOW);
                    if (!follow)
                    {
                        bool covered = _armed.ContainsKey(ret); // a user BP there already pauses us
                        if (!covered)
                        {
                            byte orig;
                            if (!_temp.ContainsKey(ret) && ReadByte(ret, out orig))
                            {
                                WriteByte(ret, 0xCC);
                                _temp[ret] = orig;
                                NotePlanted(ret, orig);   // a queued hit on it outlives CancelStep (Attach.cs)
                                covered = true;
                            }
                            else if (_temp.ContainsKey(ret))
                                covered = true;
                        }
                        if (covered)
                        {
                            _skipEntryEsp = ctx.Esp;
                            _skipEntryEbp = ctx.Ebp;   // at the callee's entry, still the caller's frame
                            _skipEventLoopKind = EventLoopCallKindAt(_prevVa, ret);
                            _skipRetVa = ret;
                            _skipLoopHeadVa = _skipEventLoopKind == EventLoopEnd ? PlantLoopHeadTemp(ret) : 0;
                            _skipRunning = true;
                            _prevVa = va;
                            return; // TF stays clear → full speed until the temp BP (or a user BP)
                        }
                        // couldn't plant — fall through and keep instruction-stepping
                    }
                }
            }

            // stop check: pause at the next statement boundary appropriate for the mode. Shared with the
            // call-skip return path (OnTempBp) so a boundary that lands on a skipped call's return address
            // is not stepped past and missed. Instruction-granular OverInstr is handled inside IsStepStop.
            bool stop = IsStepStop(va, ctx.Esp);

            if (!stop && _stepCount >= MAX_STEPS)
            {
                Console.WriteLine($"  (step limit reached after {_stepCount} instructions — pausing here)");
                StopStepAndPause(tid, hThread, ref ctx, "step-limit");
                return;
            }
            if (stop)
            {
                // instruction-granular step reports as "stepi" so the host keeps focus in the
                // disassembly view (no jump to the .clw); source-level steps report "step".
                StopStepAndPause(tid, hThread, ref ctx, _mode == StepMode.OverInstr ? "stepi" : "step");
                return;
            }

            // keep stepping
            _prevVa = va;
            ctx.EFlags |= TRAP_FLAG;
            Native.SetThreadContext(hThread, ref ctx);
        }

        /// <summary>Should the active step mode stop at <paramref name="va"/> (ESP <paramref name="esp"/>)?
        /// Shared by the single-step machine and the call-skip return path so the stop decision is identical
        /// whether we arrive at a statement boundary by single-stepping or by a temp-BP at a call's return
        /// address. Stops only at a record boundary (gap==0) for a different statement than the step start;
        /// Over additionally requires the frame to be no deeper than the start.</summary>
        private bool IsStepStop(uint va, uint esp)
        {
            if (_mode == StepMode.None) return false;
            // Instruction-granular step-over (disassembly view): purely address-based, independent of any
            // source mapping — stop as soon as EIP has left the starting instruction (the call-skip brings
            // us back at the return address). Checked before the source-resolution guard below so it stops
            // even in runtime/library code with no .clw record. Same prologue-window bypass as StepMode.Over:
            // a procedure's entry instruction can itself be a single ENTER opcode that both pushes ebp AND
            // reserves the whole local frame (sub esp,N folded in) — that alone can blow past ESP_SLACK in
            // one instruction, so gating on it here would skip stopping right after the entry instruction.
            if (_mode == StepMode.OverInstr)
                return va != _stepStartVa && PassesEspGate(PrologueBypassApplies(va), esp, _startEsp);
            var m = ModuleAt(va);
            uint rva = m != null ? va - m.LoadBase : va;
            int line = 0, mi = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            if (!resolved) return false;
            uint gap = rva - recRva;
            bool newStatement = gap == 0 && (m != _startModule || line != _startLine || mi != _startModIdx);
            switch (_mode)
            {
                case StepMode.Into: return newStatement;
                case StepMode.Over:
                    // Started inside the procedure's own prologue (landed there via a prior Step Into,
                    // before `push ebp/mov ebp,esp/sub esp,N` ran): reserving the local frame legitimately
                    // drops ESP well past ESP_SLACK, but that's this procedure claiming its own frame, not
                    // a nested call — the call-skip logic above already peels off any real nested calls
                    // before we get here. So the ESP gate is bypassed WHILE THE CANDIDATE STOP IS STILL IN
                    // THE PROCEDURE THE STEP BEGAN IN, and nowhere else; see PrologueBypassApplies.
                    return newStatement && PassesEspGate(PrologueBypassApplies(va), esp, _startEsp);
                case StepMode.Out:
                    // esp > _startEsp alone can trip mid-epilogue: a Clarion procedure's frame teardown
                    // (mov esp,ebp / pop ebp / ret) is several instructions all mapped to the SAME
                    // RETURN-statement record, and the first of them already grows esp past the start
                    // value before the actual `ret` has run. Require newStatement too (leaving the
                    // starting record), same guard Into/Over already use, so Out doesn't stop again on
                    // its own epilogue — only once execution has genuinely reached the caller.
                    return esp > _startEsp && gap <= OUT_GAP_MAX && newStatement;
            }
            return false;
        }

        /// <summary>The frame-depth gate both ESP-gated step modes share: a candidate stop is deep enough to
        /// be inside a callee unless ESP has come back up to (within ESP_SLACK of) where the step began.
        ///
        /// It is one named expression rather than two inlined copies so that `ClarionDbg protocolcheck` can
        /// isolate EITHER half with the other intact — the bypass without the gate, and the gate without the
        /// bypass. A guard that only ever runs alongside another guard that happens to cover the same case
        /// is a dead guard whose test still passes; this repo has shipped exactly that bug before.</summary>
        private static bool PassesEspGate(bool bypassApplies, uint esp, uint startEsp)
        {
            return bypassApplies || esp + ESP_SLACK >= startEsp;
        }

        /// <summary>Test seam for <see cref="PassesEspGate"/>.</summary>
        internal static bool PassesEspGateForTest(bool bypassApplies, uint esp, uint startEsp)
        {
            return PassesEspGate(bypassApplies, esp, startEsp);
        }

        /// <summary>Does the prologue ESP-gate bypass apply to a candidate stop at <paramref name="va"/>?
        ///
        /// The ESP gate (<c>esp + ESP_SLACK &gt;= _startEsp</c>) is what stops a Step Over stopping INSIDE a
        /// callee. The bypass exists for one narrow case: the step began in a procedure's prologue, where
        /// that procedure's own `sub esp,N` drops ESP past the slack before any nested call happens.
        ///
        /// It used to be armed by <c>_startAtProcEntry</c> ALONE, which is set once in BeginStep and was
        /// never cleared — so the gate was bypassed for every stop check in the step session, including
        /// candidates in a DIFFERENT procedure. Call-skip normally peels nested calls off first (for Over,
        /// `follow` is always false, so it always tries to plant a temp INT3 at the return address), but
        /// StepMachine has a documented fall-through: "couldn't plant — fall through and keep
        /// instruction-stepping". On that path the ESP gate was the last line of defence, and with the
        /// bypass on, Over stopped at the callee's first statement boundary and degraded into a Step Into.
        ///
        /// So the bypass is now bounded by the procedure as well: it applies only while the candidate stop
        /// still resolves to the SAME symbol the step started in. That keeps the prologue fix exactly (the
        /// intended stop is in the same procedure) and restores the protection everywhere else.
        ///
        /// Uses plain ResolveSymbol, not ResolveSymbolVerified, deliberately and for the same reason
        /// BeginStep does: this is a range check between two addresses, not user-facing frame naming, and
        /// Verified returns false in glue code with no line records — which here would silently disarm the
        /// bypass rather than bound it.</summary>
        private bool PrologueBypassApplies(uint va)
        {
            if (!_startAtProcEntry || _startSymModule == null) return false;
            var m = ModuleAt(va);
            if (m != _startSymModule || m.Dbg == null) return false;
            ProcSymbol sym;
            return m.Dbg.ResolveSymbol(va - m.LoadBase, out sym) && sym.EntryRva == _startSymEntryRva;
        }

        /// <summary>The RVA of the first +0x1C line record belonging to the procedure that owns
        /// <paramref name="entryRva"/>, or 0 when that procedure has no line record of its own.
        ///
        /// This is the precise instrument for "am I still in the prologue". A procedure's entry can PRECEDE
        /// its own first line record — Geir's doc comment on ResolveSymbolVerified establishes exactly that,
        /// and it is what makes the test work: a start address below the first record has not reached any
        /// statement of the procedure yet, which is what a prologue IS. The record must fall inside the
        /// proc's own span [entry, nextEntry), or it belongs to the NEXT procedure and says nothing about
        /// this one.</summary>
        private static uint FirstRecordRvaInProc(LoadedModule m, uint entryRva)
        {
            return FirstRecordRvaInProc(m.Dbg.AddrTable, entryRva,
                                        m.Dbg.NextSymbolEntryRva(entryRva));   // 0 = last symbol in the image
        }

        /// <summary>Is <paramref name="rva"/> in the prologue — below its procedure's own first line record,
        /// and so before any statement of that procedure has run? A procedure with no line record of its own
        /// (<paramref name="firstRecRva"/> 0) is never "in the prologue": there is nothing to measure
        /// against, and the safe answer is the ESP gate every other step gets.</summary>
        internal static bool IsPrologueRva(uint rva, uint firstRecRva)
        {
            return firstRecRva != 0 && rva < firstRecRva;
        }

        /// <summary><see cref="FirstRecordRvaInProc(LoadedModule,uint)"/> with the two lookups already done,
        /// so the rule is a pure function of a record table. This is the half protocolcheck can isolate: the
        /// engine cannot build a TswdDebugInfo without a real binary, but it can hand this a record list.
        /// <paramref name="nextEntryRva"/> of 0 means there is no following symbol.</summary>
        internal static uint FirstRecordRvaInProc(List<AddrRec> table, uint entryRva, uint nextEntryRva)
        {
            if (table == null || table.Count == 0) return 0;
            int lo = 0, hi = table.Count - 1, ans = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (table[mid].Rva >= entryRva) { ans = mid; hi = mid - 1; }
                else lo = mid + 1;
            }
            if (ans < 0) return 0;
            uint rec = table[ans].Rva;
            return (nextEntryRva == 0 || rec < nextEntryRva) ? rec : 0;
        }

        // ------------------------------------------------------------------ the ACCEPT loop's two calls (0f16e12c)
        //
        // ACCEPT compiles to `call [Cla$StartEventLoop]` at its head and `call [Cla$EndEventLoop]; cmp al,0;
        // je <Start's return address>` at its back-edge, and ClaRUN keeps the loop's state ON THE PROCEDURE'S
        // OWN STACK (DebugEngine.SetIp.cs, measured on clbrws 2026-09-23): the body runs about 0xFC below the
        // frame's statement depth, and deeper on the first passes. Both calls are skipped like any other, and
        // two ESP tests then refused them. OnTempBp's recursion guard read Start's LOW return as a deeper frame
        // and re-armed for ever, so Step Over on an ACCEPT line never stopped. And had it been accepted, the
        // Over ESP gate, measured on the ACCEPT line, refused every statement of the body.
        //
        // So for these two calls only:
        //   - "has it returned" is asked of the FRAME: EBP back at the caller's. Clarion code is EBP-relative,
        //     ClaRUN preserves EBP, and a deeper activation of the same procedure through the same return
        //     address has an EBP of its own, so the recursion guard still holds;
        //   - on return, the step's ESP baseline moves to where the call left ESP. That is the frame's
        //     statement depth from here on: the body's after Start, and after End either the next pass's or,
        //     when the loop exits, the frame's own again.
        //   - End has a SECOND way back. When the loop goes round it does not return to its call site at all:
        //     it resumes at the loop head, Start's return address. So skipping End also plants a temp there,
        //     and whichever of the two the frame reaches first ends the skip and takes the other one out.
        // _skipEventLoopKind's values, which are EventLoopImportKind's (DebugEngine.SetIp.cs).
        private const int NotEventLoop = 0;
        private const int EventLoopStart = 1;
        private const int EventLoopEnd = 2;

        private int _skipEventLoopKind;   // the call being skipped: EventLoopStart, EventLoopEnd or NotEventLoop
        private uint _skipEntryEbp;       // EBP at the callee's entry (the caller's frame)
        private uint _skipRetVa;          // the skipped call's return address (its temp INT3, or a user bp's)
        private uint _skipLoopHeadVa;     // End only: the loop head this skip watches (see PlantLoopHeadTemp), or 0

        /// <summary>Plant a temp INT3 at the loop head of the back-edge that follows a `call [End]` returning
        /// to <paramref name="endRet"/>, and return its VA; 0 when there is no back-edge there, or the head
        /// already carries a TEMP (not ours to remove). A head that carries a USER breakpoint is returned
        /// unplanted: that INT3 already catches the frame, and OnUserBp ends the skip on it even when the
        /// breakpoint's gate does not pause (<see cref="IsSkipLanding"/>).</summary>
        private uint PlantLoopHeadTemp(uint endRet)
        {
            uint head = EventLoopBackEdgeTargetAt(endRet);
            byte orig;
            var watch = LoopHeadWatchFor(head, endRet, _armed.ContainsKey(head), _temp.ContainsKey(head));
            if (watch == LoopHeadWatch.None) return 0;
            if (watch == LoopHeadWatch.UserBreakpoint) return head;
            if (!ReadByte(head, out orig))
                return 0;
            WriteByte(head, 0xCC);
            _temp[head] = orig;
            NotePlanted(head, orig);   // a queued hit on it outlives CancelStep (Attach.cs)
            return head;
        }

        internal enum LoopHeadWatch { None, UserBreakpoint, PlantTemp }

        /// <summary><see cref="PlantLoopHeadTemp"/>'s choice, pure so `protocolcheck` can drive it: no head, a
        /// head that is the return itself, or one already holding a temp is not watched; a head holding a user
        /// breakpoint is watched through that breakpoint; any other gets a temp of its own.</summary>
        internal static LoopHeadWatch LoopHeadWatchFor(uint head, uint endRet, bool userBpThere, bool tempThere)
        {
            if (head == 0 || head == endRet || tempThere) return LoopHeadWatch.None;
            return userBpThere ? LoopHeadWatch.UserBreakpoint : LoopHeadWatch.PlantTemp;
        }

        /// <summary>Has the skipped call returned to the stepping frame? For an ordinary call, ESP is back above
        /// the callee's entry. For an event-loop call, whose return ESP is not its call site's, EBP is back at
        /// the caller's frame.</summary>
        private static bool SkipHasReturned(int eventLoopKind, uint esp, uint ebp, uint entryEsp, uint entryEbp)
        {
            return eventLoopKind != NotEventLoop ? ebp == entryEbp : esp >= entryEsp + 4;
        }

        /// <summary>Is a USER breakpoint hit at <paramref name="va"/> the stepping thread's skip landing? A
        /// covered return (StepMachine plants no temp where a user bp already sits) or a loop head carrying a
        /// user bp is caught by the user INT3 alone, so when that breakpoint's gate does NOT pause (a false
        /// condition, an unmet hit count, a tracepoint), OnUserBp must end the skip here, or _skipRunning stays
        /// set, StepMachine never runs again, and the step runs free.</summary>
        private bool IsSkipLanding(uint tid, uint va, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            return _mode != StepMode.None && tid == _stepTid && _skipRunning && haveCtx
                   && (va == _skipRetVa || (_skipLoopHeadVa != 0 && va == _skipLoopHeadVa))
                   && SkipHasReturned(_skipEventLoopKind, ctx.Esp, ctx.Ebp, _skipEntryEsp, _skipEntryEbp);
        }

        /// <summary>The skipped call is back in the stepping frame at <paramref name="va"/>, through a temp INT3
        /// (OnTempBp) or a non-pausing user breakpoint (OnUserBp): end the skip, then either stop there, when it
        /// is a stop boundary, or resume stepping. <paramref name="ctx"/>'s EIP is already <paramref
        /// name="va"/>.</summary>
        private void FinishSkipAt(uint tid, uint va, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            _skipRunning = false;
            EndSkip(va, ctx.Esp, haveCtx);   // before IsStepStop: an event-loop return re-bases its ESP gate
            if (_mode != StepMode.None && haveCtx && IsStepStop(va, ctx.Esp))
            {
                // The skipped call returned straight onto a stop boundary. For source-level Over this is a
                // new-statement record (a call as a line's last op → its return address is the next line's
                // record); for instruction-granular OverInstr it's simply the return address. Stop here
                // rather than resume stepping and trap only at the following instruction (missing it). The
                // INT3 advanced the thread's EIP to va+1, so commit the corrected EIP (=va) before pausing,
                // otherwise the next resume runs from mid-instruction and crashes the target.
                Native.SetThreadContext(hThread, ref ctx);   // commit the corrected EIP (=va)
                StopStepAndPause(tid, hThread, ref ctx, _mode == StepMode.OverInstr ? "stepi" : "step");
            }
            else if (_mode != StepMode.None && haveCtx)
            {
                // back at the caller — resume source-level stepping
                _prevVa = va;
                ctx.EFlags |= TRAP_FLAG;
                Native.SetThreadContext(hThread, ref ctx);
            }
            else if (haveCtx)
            {
                Native.SetThreadContext(hThread, ref ctx); // just fix EIP
            }
        }

        /// <summary>The skipped call has returned: an event-loop call moves the step's ESP baseline to the ESP
        /// it returned with. Every mode, not only Over: Out's `esp &gt; _startEsp` would otherwise read the
        /// loop's exit, which puts ESP back at the frame's depth, as having left the procedure.
        /// <para>The skip is over whichever of its temps the frame reached (<paramref name="va"/>), so an End skip's
        /// other temp is restored and dropped here: left planted, it would fire later in the step as a skip
        /// return with no skip behind it.</para></summary>
        private void EndSkip(uint va, uint esp, bool haveEsp)
        {
            if (_skipEventLoopKind != NotEventLoop && haveEsp) _startEsp = esp;
            uint other = va == _skipLoopHeadVa ? _skipRetVa : _skipLoopHeadVa;
            byte orig;
            if (_skipLoopHeadVa != 0 && other != va && _temp.TryGetValue(other, out orig))
            {
                WriteByte(other, orig);
                _temp.Remove(other);
            }
            _skipEventLoopKind = NotEventLoop;
            _skipLoopHeadVa = 0;
        }

        private void StopStepAndPause(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, string reason)
        {
            CancelStep();
            RestoreIfArmed(tid, ctx.Eip);
            PausedWait(tid, hThread, ref ctx, true, reason);
        }

        private void CancelStep()
        {
            _mode = StepMode.None;
            _skipRunning = false;
            _skipEventLoopKind = NotEventLoop;
            _skipLoopHeadVa = 0;   // a temp's byte is in _temp, which the loop below restores
            // The prologue bypass is step-session state. It was set once in BeginStep and never cleared,
            // so it survived into the NEXT step session and disabled that session's ESP gate too until
            // BeginStep happened to recompute it. Clearing it here means a cancelled step leaves nothing
            // armed behind it.
            _startAtProcEntry = false;
            _startSymModule = null;
            _startSymEntryRva = 0;
            foreach (var kv in _temp) WriteByte(kv.Key, kv.Value);
            _temp.Clear();
            // drop pending TEMP re-plants (their bytes were just restored); user-BP re-plants survive
            var drop = new List<uint>();
            foreach (var kv in _rearm) if (kv.Value.IsTemp) drop.Add(kv.Key);
            foreach (var t in drop) _rearm.Remove(t);
        }

        private void BeginStep(StepMode mode, uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx, bool resolved, int line, int mi, LoadedModule m)
        {
            _mode = mode;
            _stepTid = tid;
            _startEsp = haveCtx ? ctx.Esp : 0;
            _startLine = resolved ? line : -1;
            _startModIdx = resolved ? mi : -1;
            _startModule = m;
            _prevVa = haveCtx ? ctx.Eip : 0;
            _stepStartVa = _prevVa;
            _stepCount = 0;
            _skipRunning = false;
            _skipEventLoopKind = NotEventLoop;
            _skipLoopHeadVa = 0;

            // "Am I starting inside the prologue?" measured with the right instrument.
            //
            // This used to be `rva - sym.EntryRva <= PROLOGUE_WINDOW`, reusing a constant whose DECLARED
            // meaning is "a callee with a line record this close to entry is Clarion code" — a
            // code-identification heuristic, not a prologue predicate. At 0x100 a start point 256 bytes into
            // the procedure BODY still counted as "at entry" and disabled the ESP gate. PROLOGUE_WINDOW
            // keeps its one meaning (StepMachine's `follow` test) and is no longer used for this.
            //
            // The precise test: the start RVA is BELOW the procedure's own first line record. A procedure's
            // entry can precede its first record, so everything in [entry, firstRecord) is prologue — code
            // that has not reached any statement of the procedure yet. A procedure with no record of its own
            // (FirstRecordRvaInProc returns 0) gets no bypass: there is nothing to measure against, and the
            // safe answer is the ESP gate everyone else gets.
            //
            // The old `rva >= sym.EntryRva` conjunct is DROPPED, not kept: ResolveSymbol returns the greatest
            // EntryRva <= rva, so it was always true. The new test subsumes it anyway — rva < firstRecord
            // with firstRecord >= entry is only interesting above the entry.
            _startSymModule = null;
            _startSymEntryRva = 0;
            _startAtProcEntry = false;
            ProcSymbol sym;
            uint rva = (haveCtx && m != null) ? ctx.Eip - m.LoadBase : 0;
            if (haveCtx && m != null && m.Dbg != null && m.Dbg.ResolveSymbol(rva, out sym))
            {
                uint firstRec = FirstRecordRvaInProc(m, sym.EntryRva);
                if (IsPrologueRva(rva, firstRec))
                {
                    _startAtProcEntry = true;
                    _startSymModule = m;
                    _startSymEntryRva = sym.EntryRva;
                }
            }
        }

        // ------------------------------------------------------------------ test seams for the step guards
        //
        // BeginStep needs a live context and a real TswdDebugInfo, so the reset cannot be reached by driving
        // the public path with no debuggee. These arm the bypass state directly and read it back, which is
        // enough to isolate CancelStep's reset — the guard being asserted is "CancelStep clears it", not
        // "BeginStep sets it", and those are separate claims.

        /// <summary>Arm the prologue-bypass FLAG and entry RVA, for asserting that CancelStep clears them.
        /// <para>
        /// NOT A STATE A REAL STEP CAN REACH (f367a04f item 4): BeginStep sets <c>_startAtProcEntry</c> only
        /// together with a non-null <c>_startSymModule</c>, while this leaves the module null.
        /// <see cref="PrologueBypassApplies"/> rejects that combination on its first line, so a stop check
        /// run against an engine armed here sees NO bypass. Use this seam only for the reset claim; a check
        /// on whether the bypass APPLIES needs a module and a real line table, which this does not supply.
        /// </para></summary>
        internal void ArmPrologueBypassForTest(uint entryRva)
        {
            // MUTATES the step-start state a live BeginStep/StepMachine reads.
            RefuseSeamIfAttached("ArmPrologueBypassForTest");
            _startAtProcEntry = true;
            _startSymEntryRva = entryRva;
            _startSymModule = null;   // see the summary: deliberate, and the reason this seam is reset-only
        }

        internal bool PrologueBypassArmedForTest { get { return _startAtProcEntry; } }

        internal uint PrologueBypassEntryRvaForTest { get { return _startSymEntryRva; } }

        /// <summary>CancelStep RESTORES every recorded temp byte through WriteProcessMemory, so against a
        /// live target this seam writes into the debuggee.</summary>
        internal void CancelStepForTest() { RefuseSeamIfAttached("CancelStepForTest"); CancelStep(); }

        /// <summary>Arm an IN-FLIGHT <b>Step Over</b> session the way BeginStep leaves one: the Over mode,
        /// the stepping thread, the previous trap's EIP (<c>_prevVa</c> — the call-entry detector's anchor)
        /// and one call-skip temp INT3 (none when <paramref name="tempVa"/> is 0: a return a user breakpoint
        /// covers gets no temp). BeginStep itself needs a live context and a real line table, and the
        /// property under test is what a breakpoint hit does to a session that is ALREADY in flight, which
        /// is a separate claim.
        /// <para>Named for the ONE mode it arms rather than taking a <c>StepMode</c>: the call-skip temp
        /// INT3 below is Step Over's shape, no caller varies the mode, and a parameter no check varies is
        /// an untested degree of freedom asserting nothing. Widen the seam when a case needs Into or Out,
        /// and widen the name with it.</para></summary>
        internal void ArmStepOverSessionForTest(uint tid, uint prevVa, uint tempVa)
        {
            // MUTATES the in-flight step session. Against a live target the invented temp entry below makes
            // the next CancelStep write 0x90 into the debuggee at an address it never patched.
            RefuseSeamIfAttached("ArmStepOverSessionForTest");
            _mode = StepMode.Over;
            _stepTid = tid;
            _prevVa = prevVa;
            if (tempVa != 0) _temp[tempVa] = 0x90;
        }

        /// <summary>Put an armed Step Over session into its run-to-return state, as StepMachine leaves it after
        /// planting a call-skip temp INT3: the step's ESP baseline, the callee-entry ESP and EBP, which call is
        /// being skipped (<see cref="EventLoopCallKind"/>'s 1/2/0), and the thread running at full speed.
        /// <paramref name="retVa"/> must already be a recorded temp (ArmStepOverSessionForTest) or, for a
        /// return a user breakpoint covers, an armed user breakpoint (ArmUserBpForTest). A non-zero
        /// <paramref name="loopHeadVa"/> is recorded as the End skip's loop head: a temp of its own, unless a
        /// user breakpoint is armed there, as PlantLoopHeadTemp leaves it.</summary>
        internal void ArmCallSkipForTest(uint retVa, uint loopHeadVa, uint startEsp, uint entryEsp, uint entryEbp,
                                         int eventLoopKind)
        {
            RefuseSeamIfAttached("ArmCallSkipForTest");
            if (!_temp.ContainsKey(retVa) && !_armed.ContainsKey(retVa))
                throw new InvalidOperationException("ArmCallSkipForTest: 0x" + retVa.ToString("X8")
                                                    + " is neither a recorded temp INT3 nor an armed user breakpoint");
            _skipRetVa = retVa;
            _skipLoopHeadVa = loopHeadVa;
            if (loopHeadVa != 0 && !_armed.ContainsKey(loopHeadVa)) _temp[loopHeadVa] = 0x90;
            _startEsp = startEsp;
            _skipEntryEsp = entryEsp;
            _skipEntryEbp = entryEbp;
            _skipEventLoopKind = eventLoopKind;
            _skipRunning = true;
        }

        /// <summary>The step's ESP baseline (<c>_startEsp</c>), which the Over and OverInstr gates and Out read.</summary>
        internal uint StartEspForTest { get { return _startEsp; } }

        /// <summary>Is the stepping thread still running at full speed to a call-skip return?</summary>
        internal bool SkipRunningForTest { get { return _skipRunning; } }

        /// <summary>Is a step session still in flight? This is the exact condition OnSingleStep's step-2
        /// guard tests (<c>_mode != StepMode.None</c>) before it runs StepMachine, so a false here means
        /// nothing will stop the target.</summary>
        internal bool StepInFlightForTest { get { return _mode != StepMode.None; } }

        /// <summary>The call-entry detector's anchor (<c>_prevVa</c>).</summary>
        internal uint PrevVaForTest { get { return _prevVa; } }

        /// <summary>How many call-skip temp INT3s are still recorded. CancelStep restores and clears them
        /// all, so this distinguishes a cancelled session from a surviving one independently of the mode.</summary>
        internal int TempBpCountForTest { get { return _temp.Count; } }
    }
}
