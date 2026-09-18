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
                                covered = true;
                            }
                            else if (_temp.ContainsKey(ret))
                                covered = true;
                        }
                        if (covered)
                        {
                            _skipEntryEsp = ctx.Esp;
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

        internal void ArmPrologueBypassForTest(uint entryRva)
        {
            _startAtProcEntry = true;
            _startSymEntryRva = entryRva;
            _startSymModule = null;   // no module needed: the seam below reads the armed flag, not the bound
        }

        internal bool PrologueBypassArmedForTest { get { return _startAtProcEntry; } }

        internal uint PrologueBypassEntryRvaForTest { get { return _startSymEntryRva; } }

        internal void CancelStepForTest() { CancelStep(); }
    }
}
