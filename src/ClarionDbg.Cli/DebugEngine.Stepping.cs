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
                return va != _stepStartVa && (_startAtProcEntry || esp + ESP_SLACK >= _startEsp);
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
                    // Started inside the callee's own prologue window (landed there via a prior Step
                    // Into, before `push ebp/mov ebp,esp/sub esp,N` ran): reserving the local frame
                    // legitimately drops ESP well past ESP_SLACK, but that's this procedure claiming
                    // its own frame, not a nested call — the call-skip logic above already peels off
                    // any real nested calls before we get here. Skip the ESP gate for this first hop.
                    return newStatement && (_startAtProcEntry || esp + ESP_SLACK >= _startEsp);
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

            ProcSymbol sym;
            uint rva = (haveCtx && m != null) ? ctx.Eip - m.LoadBase : 0;
            _startAtProcEntry = haveCtx && m != null && m.Dbg != null
                && m.Dbg.ResolveSymbol(rva, out sym)
                && rva >= sym.EntryRva && rva - sym.EntryRva <= PROLOGUE_WINDOW;
        }
    }
}
