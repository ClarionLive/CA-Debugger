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

            // 3) instruction step (stepi): we asked for exactly one TF step — pause here at the new EIP
            else if (_instrStep && tid == _instrStepTid && haveCtx)
                PausedWait(tid, hThread, ref ctx, haveCtx, "stepi"); // PausedWait clears _instrStep

            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
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

            // stop check: pause at the next statement boundary appropriate for the mode
            int line = 0, mi = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            uint gap = resolved ? rva - recRva : 0;
            bool atRecord = resolved && gap == 0;
            bool newStatement = atRecord && (m != _startModule || line != _startLine || mi != _startModIdx);
            bool stop = false;
            switch (_mode)
            {
                case StepMode.Into:
                    stop = newStatement;
                    break;
                case StepMode.Over:
                    stop = newStatement && ctx.Esp + ESP_SLACK >= _startEsp;
                    break;
                case StepMode.Out:
                    stop = resolved && ctx.Esp > _startEsp && gap <= OUT_GAP_MAX;
                    break;
                case StepMode.OverInstr:
                    // one machine instruction, stepping over calls: stop as soon as EIP has left the
                    // starting instruction (the call-skip above brings us back at the return address).
                    stop = ctx.Eip != _stepStartVa && ctx.Esp + ESP_SLACK >= _startEsp;
                    break;
            }

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

        private void StopStepAndPause(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, string reason)
        {
            CancelStep();
            uint va = ctx.Eip;
            byte orig;
            if (_armed.TryGetValue(va, out orig))
            {
                // landed exactly on a user breakpoint byte — restore it so the instruction can
                // execute on resume, and re-plant after one single-step
                WriteByte(va, orig);
                _rearm[tid] = new Rearm { Va = va, IsTemp = false };
            }
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
        }
    }
}
