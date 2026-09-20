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
        // ------------------------------------------------------------------ breakpoint management

        /// <summary>Resolve module:line to RVAs (snapping to the nearest record line) and register it.
        /// If the owning image is not yet loaded, the breakpoint is held PENDING and resolved when that
        /// image maps (see <see cref="ResolvePendingFor"/>).</summary>
        /// <summary>Apply advanced breakpoint properties (condition / hit count / tracepoint) to a
        /// breakpoint and reset its runtime hit counter (re-configuring restarts the count). Empty
        /// strings normalize to null = "no such property".</summary>
        private static void ApplyBpProps(UserBreakpoint bp, string condition, string hitMode, int hitValue, string trace)
        {
            bp.Condition = string.IsNullOrEmpty(condition) ? null : condition;
            bp.HitMode = (hitMode == "eq" || hitMode == "gte" || hitMode == "mod") ? hitMode : null;
            bp.HitValue = hitValue;
            bp.Trace = string.IsNullOrEmpty(trace) ? null : trace;
            bp.HitCount = 0;
        }

        private void EmitBpSet(UserBreakpoint bp)
        {
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(bp));
        }

        private void AddBreakpoint(string module, int line, string condition = null, string hitMode = null, int hitValue = 0, string trace = null)
        {
            var owner = OwnerOfModule(module);
            if (owner == null)
            {
                // No loaded/known image carries this compiland yet — defer. Arms when its DLL loads.
                foreach (var b in _bps)
                    if (Eq(b.Module, module) && (b.RequestedLine == line || b.Line == line))
                    {
                        // re-add of a pending bp = a properties update; re-apply and re-confirm
                        ApplyBpProps(b, condition, hitMode, hitValue, trace);
                        EmitBpSet(b);
                        return;
                    }
                var pend = new UserBreakpoint { Module = module, ModuleIdx = -1, RequestedLine = line, Line = line };
                ApplyBpProps(pend, condition, hitMode, hitValue, trace);
                _bps.Add(pend);
                Console.WriteLine($"bp: {module}:{line} pending — owning image not loaded yet");
                EmitBpSet(pend);
                return;
            }

            var dbg = owner.Dbg;
            int mi = dbg.FindModuleIdx(module);
            string canon = dbg.ModuleNameForIdx(mi) ?? module;
            int planted = line;
            var rvas = dbg.LineToRvasInModuleIdx(mi, line);
            if (rvas.Count == 0)
            {
                // Clarion's line table is sparse — snap to the nearest line that has a record
                int snapped = NearestIn(dbg.BreakableLinesInModuleIdx(mi), line);
                if (snapped > 0) { planted = snapped; rvas = dbg.LineToRvasInModuleIdx(mi, snapped); }
            }
            if (rvas.Count == 0)
            {
                Console.WriteLine($"bp: no code records in {canon} (line {line})");
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(canon, line, "no code records in module"));
                return;
            }
            // Re-adding the SAME requested line is a no-op (re-confirm so the UI can sync). NOTE: we
            // key this on the REQUESTED line, not the planted line — several distinct gutter lines can
            // snap to one planted line (e.g. blank/comment lines above a statement). Each stays its own
            // logical breakpoint so it can be removed independently; the shared INT3 at the planted
            // address is ref-counted by PlantBp (skips an already-armed VA) and RemoveBreakpoint (only
            // unplants when the last referencing breakpoint is gone). Collapsing on the planted line —
            // the old behaviour — meant removing any of the other gutter lines matched nothing and left
            // the breakpoint planted and firing.
            foreach (var b in _bps)
                if (b.Owner == owner && b.ModuleIdx == mi && b.RequestedLine == line)
                {
                    // re-add of the same line = a properties update; re-apply and re-confirm
                    ApplyBpProps(b, condition, hitMode, hitValue, trace);
                    EmitBpSet(b);
                    return;
                }

            var bp = new UserBreakpoint { Module = canon, ModuleIdx = mi, Owner = owner, RequestedLine = line, Line = planted };
            bp.Rvas.AddRange(rvas);
            ApplyBpProps(bp, condition, hitMode, hitValue, trace);
            _bps.Add(bp);
            if (owner.LoadBase != 0) PlantBp(bp);
            if (planted != line)
                Console.WriteLine($"bp: line {line} has no code record in {canon}; breakpoint moved to nearest line {planted}");
            Console.WriteLine($"bp: set {canon}:{planted} ({bp.Rvas.Count} address(es))");
            EmitBpSet(bp);
        }

        /// <summary>Register a raw RVA (legacy --rva/--entry) as an anonymous EXE breakpoint.</summary>
        private void AddRawBreakpoint(uint rva)
        {
            int line = 0, mi = -1; uint recRva;
            bool resolved = _exe.Dbg != null && _exe.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            var bp = new UserBreakpoint
            {
                Module = resolved ? _exe.Dbg.ModuleNameForIdx(mi) : null,
                ModuleIdx = resolved ? mi : -1,
                Owner = _exe,
                RequestedLine = resolved ? line : 0,
                Line = resolved ? line : 0
            };
            bp.Rvas.Add(rva);
            _bps.Add(bp);
            if (_exe.LoadBase != 0) PlantBp(bp);
        }

        private static bool Eq(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }

        private void RemoveBreakpoint(string module, int line)
        {
            UserBreakpoint found = null;
            // Prefer an exact requested-line match; only fall back to the planted line if nothing
            // requested it. Several logical bps can share one planted Line (distinct gutter lines that
            // snapped to the same record), so a planted-line match alone would remove an arbitrary one.
            foreach (var b in _bps)
                if (Eq(b.Module, module) && b.RequestedLine == line) { found = b; break; }
            if (found == null)
                foreach (var b in _bps)
                    if (Eq(b.Module, module) && b.Line == line) { found = b; break; }
            string canon = found != null ? found.Module : module;
            if (found == null)
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(canon, line, "no such breakpoint"));
                return;
            }
            uint baseVa = found.Owner != null ? found.Owner.LoadBase : 0;
            // Drop the logical breakpoint first so the ref-count check below sees only the survivors.
            _bps.Remove(found);
            foreach (var rva in found.Rvas)
            {
                // Ref-count the physical INT3: another breakpoint (a different gutter line that snapped
                // to the same address in the SAME image) may still need it. Match on Owner — under
                // multi-DLL two images can share a ModuleIdx, so an rva-only check could alias across
                // modules. Only unplant when nothing references it.
                bool stillReferenced = false;
                foreach (var b in _bps)
                    if (b.Owner == found.Owner && b.Rvas.Contains(rva)) { stillReferenced = true; break; }
                if (stillReferenced) continue;

                uint va = baseVa + rva;
                byte orig;
                if (baseVa != 0 && _armed.TryGetValue(va, out orig))
                {
                    // if a thread restored this byte and its re-plant is still pending, cancel the
                    // re-plant instead of writing (the byte is already the original)
                    uint pendingTid = 0; bool pending = false;
                    foreach (var kv in _rearm)
                        if (!kv.Value.IsTemp && kv.Value.Va == va) { pendingTid = kv.Key; pending = true; break; }
                    if (pending) _rearm.Remove(pendingTid);
                    else WriteByte(va, orig);
                    _armed.Remove(va);
                }
            }
            Console.WriteLine($"bp: removed {canon}:{found.Line}");
            // Echo the whole breakpoint, not just its planted line: `canon` IS found.Module here, and the
            // host needs found.RequestedLine to know which of the lines sharing this planted record went.
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpDel(found));
        }

        /// <summary>Plant breakpoints already bound to this exact image (used when a pre-loaded
        /// solution DLL finally maps).</summary>
        private void PlantOwnBps(LoadedModule m)
        {
            foreach (var bp in _bps)
                if (bp.Owner == m && m.LoadBase != 0) PlantBp(bp);
        }

        /// <summary>Plant every breakpoint whose owning image is mapped (LoadBase set).</summary>
        private void PlantAll()
        {
            foreach (var bp in _bps)
                if (bp.Owner != null && bp.Owner.LoadBase != 0) PlantBp(bp);
        }

        private void PlantBp(UserBreakpoint bp)
        {
            if (bp.Owner == null || bp.Owner.LoadBase == 0) return; // pending — owning image not mapped
            uint baseVa = bp.Owner.LoadBase;
            foreach (var rva in bp.Rvas)
            {
                uint va = baseVa + rva;
                if (_armed.ContainsKey(va)) continue;
                byte orig;
                if (!ReadByte(va, out orig))
                {
                    Console.WriteLine($"  WARN: could not read memory at 0x{va:X} (RVA 0x{rva:X}) — breakpoint skipped");
                    continue;
                }
                WriteByte(va, 0xCC);
                _armed[va] = orig;
            }
        }

        /// <summary>After an image maps, resolve+plant any pending breakpoints whose compiland it owns.</summary>
        private void ResolvePendingFor(LoadedModule m)
        {
            if (m == null || m.Dbg == null) return;
            foreach (var bp in _bps)
            {
                if (!bp.Pending) continue;
                int mi = m.Dbg.FindModuleIdx(bp.Module);
                if (mi < 0) continue; // this image doesn't carry that compiland

                int planted = bp.RequestedLine;
                var rvas = m.Dbg.LineToRvasInModuleIdx(mi, planted);
                if (rvas.Count == 0)
                {
                    int snapped = NearestIn(m.Dbg.BreakableLinesInModuleIdx(mi), planted);
                    if (snapped > 0) { planted = snapped; rvas = m.Dbg.LineToRvasInModuleIdx(mi, snapped); }
                }
                if (rvas.Count == 0) continue;

                bp.Owner = m;
                bp.ModuleIdx = mi;
                bp.Module = m.Dbg.ModuleNameForIdx(mi) ?? bp.Module;
                bp.Line = planted;
                bp.Rvas.Clear();
                bp.Rvas.AddRange(rvas);
                if (m.LoadBase != 0) PlantBp(bp);
                Console.WriteLine($"bp: armed pending {bp.Module}:{bp.Line} ({bp.Rvas.Count} address(es)) in {m.Name}");
                EmitBpSet(bp);
            }
        }

        /// <summary>Nearest breakable line: smallest &gt;= line (forward snap), else largest &lt; line.</summary>
        private static int NearestIn(List<int> sorted, int line)
        {
            if (sorted == null || sorted.Count == 0) return -1;
            int fwd = int.MaxValue, back = -1;
            foreach (int v in sorted)
            {
                if (v == line) return line;
                if (v > line && v < fwd) fwd = v;
                if (v < line && v > back) back = v;
            }
            return fwd != int.MaxValue ? fwd : back;
        }

        // ------------------------------------------------------------------ breakpoint hits

        private uint OnUserBp(uint tid, uint va)
        {
            Hits++;
            var m = ModuleAt(va);
            uint rva = m != null ? va - m.LoadBase : va;

            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);

            // un-patch: restore the original byte and back EIP up over the INT3 so the real
            // instruction executes on resume; re-plant after one single-step (persistent BP)
            byte orig = _armed[va];
            WriteByte(va, orig);
            if (haveCtx)
            {
                ctx.Eip = va; // EIP was va+1 after the 0xCC
                Native.SetThreadContext(hThread, ref ctx);
            }
            _rearm[tid] = new Rearm { Va = va, IsTemp = false };

            // Advanced breakpoints: evaluate condition / hit count / tracepoint BEFORE reporting a hit.
            // A non-pausing outcome (condition false, hit-count unmet, or tracepoint logged) resumes
            // silently — re-arming via the same single-step the non-interactive path uses — so the UI
            // never sees a stop for a breakpoint that didn't actually pause.
            var ubp = FindBpAt(m, rva);
            if (ubp != null && (ubp.Condition != null || ubp.HitMode != null || ubp.Trace != null))
            {
                // tid + hThread go in because a condition or a {NAME} token may name THREADed (.cwtls) data,
                // which has one instance PER THREAD: the answer is only meaningful for the thread that hit.
                // Both are already in hand here — hThread is the handle opened above for this hit.
                if (!ShouldPauseAtBp(ubp, tid, hThread))
                {
                    // A SILENTLY RESUMED hit does NOT supersede an in-flight step: the step session is left
                    // exactly as it was, so CancelStep is deliberately not called here (it lives on the
                    // pausing routes below). It used to run unconditionally above this decision, which set
                    // _mode = StepMode.None, restored every call-skip temp INT3 and dropped the temp
                    // re-arms — so OnSingleStep's `_mode != StepMode.None` guard was false on the next trap,
                    // StepMachine never ran, and the user's Step Over became a Continue with the pad still
                    // showing Running.
                    //
                    // Re-anchor the call-entry detector on the hit address. StepMachine tests
                    // `ret > _prevVa && ret - _prevVa <= CALL_WINDOW`; a _prevVa still holding a pre-hit EIP
                    // can make the re-arm trap below read as a call entry and plant a temp INT3 at a bogus
                    // return address. Same assignment, same reason, as the caller-resume path in OnTempBp.
                    _prevVa = va;
                    if (haveCtx)
                    {
                        Native.GetThreadContext(hThread, ref ctx);
                        ctx.EFlags |= TRAP_FLAG;
                        Native.SetThreadContext(hThread, ref ctx);
                    }
                    if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
                    return Native.DBG_CONTINUE;
                }
                EmitBpSet(ubp); // pausing — push the updated live hit count to the breakpoints pane
            }

            // Past every non-pausing outcome, so this hit PAUSES — and a hit that pauses supersedes any
            // in-flight step. Both pausing routes reach here: a plain breakpoint that never entered the gate
            // above (no condition / hit count / tracepoint), and an advanced one whose gate said pause.
            CancelStep(); // drops temp re-arms; the IsTemp=false re-arm set above is not one of them

            ReportHit(m, rva, va, ref ctx, haveCtx);

            if (_once)
            {
                Console.WriteLine("  --once: terminating target after first hit.");
                Native.TerminateProcess(_hProcess, 0);
            }
            else if (_interactive)
            {
                PausedWait(tid, hThread, ref ctx, haveCtx, "breakpoint");
            }
            else if (haveCtx)
            {
                // non-interactive: keep running, but single-step once so the BP re-arms
                Native.GetThreadContext(hThread, ref ctx);
                ctx.EFlags |= TRAP_FLAG;
                Native.SetThreadContext(hThread, ref ctx);
            }

            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        private void ReportHit(LoadedModule m, uint rva, uint va, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            Console.WriteLine();
            Console.WriteLine("*** BREAKPOINT HIT ***");
            Console.WriteLine($"  VA 0x{va:X}  (loadBase 0x{(m != null ? m.LoadBase : 0):X} + RVA 0x{rva:X}{(m != null ? " in " + m.Name : "")})");

            int line = 0, moduleIdx = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out moduleIdx, out recRva);
            string modName = resolved ? m.Dbg.ModuleNameForIdx(moduleIdx) : null;
            string proc = ProcNameAt(m, rva);
            uint gap = resolved ? rva - recRva : 0;
            if (resolved)
            {
                string inProc = proc != null ? $" in {proc}" : "";
                if (gap == 0)
                    Console.WriteLine($"  -> {modName} line {line}{inProc}   (exact line record)");
                else if (gap <= 64)
                    Console.WriteLine($"  -> {modName} line {line}{inProc}   (in statement, +0x{gap:X} into its code)");
                else
                    Console.WriteLine($"  -> nearest line: {modName} line {line}{inProc} (+0x{gap:X} away — likely startup/library code with no Clarion line)");
            }
            else
                Console.WriteLine("  -> (no source line for this address)");

            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Hit(modName, proc, line, rva, va, gap, resolved));

            if (haveCtx)
            {
                Console.WriteLine($"  EAX={ctx.Eax:X8} EBX={ctx.Ebx:X8} ECX={ctx.Ecx:X8} EDX={ctx.Edx:X8}");
                Console.WriteLine($"  ESI={ctx.Esi:X8} EDI={ctx.Edi:X8} EBP={ctx.Ebp:X8} ESP={ctx.Esp:X8}");
                Console.WriteLine($"  EIP={ctx.Eip:X8} EFLAGS={ctx.EFlags:X8}");
            }
            else
                Console.WriteLine("  (could not read thread context)");
        }

        private uint OnTempBp(uint tid, uint va)
        {
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);

            byte orig = _temp[va];
            WriteByte(va, orig);
            if (haveCtx) ctx.Eip = va;

            // recursion guard: the same call-site return address fires for INNER frames too.
            // We've truly returned to our frame only when ESP is back above the callee entry.
            bool returned = haveCtx && ctx.Esp >= _skipEntryEsp + 4;
            if (_mode != StepMode.None && !returned)
            {
                // deeper frame returning through the same code point — re-arm and keep running
                _rearm[tid] = new Rearm { Va = va, IsTemp = true };
                if (haveCtx)
                {
                    ctx.EFlags |= TRAP_FLAG; // one step to get off the restored byte, then re-plant
                    Native.SetThreadContext(hThread, ref ctx);
                }
            }
            else
            {
                _temp.Remove(va);
                _skipRunning = false;
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

            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        // ------------------------------------------------------------------ test seams for the hit handler
        //
        // OnUserBp runs end to end with NO debuggee. An invalid tid makes OpenThread fail, so haveCtx is
        // false and no context is read or written; the byte restore becomes a WriteProcessMemory on a null
        // handle, which fails harmlessly. "NO debuggee" is not left to the caller to remember: every seam
        // here that mutates state or drives the handler calls RefuseSeamIfAttached first, and
        // OnUserBpForTest additionally refuses the --once and interactive engines whose pausing route would
        // terminate a process or block on stdin. What is left is precisely the bookkeeping these seams assert — the
        // step session, the re-arm entry and the call-entry anchor — driven through the REAL OnUserBp rather
        // than a copy of its decision order, because the order IS the thing under test.
        //
        // A live harness cannot readily produce this case: it needs a step already in flight on the same
        // thread at the moment a breakpoint whose gate says "do not pause" fires, which depends on where the
        // debuggee happens to call and how fast the user types.

        /// <summary>Refuse a test seam that MUTATES engine state, or drives a handler that writes to the
        /// debuggee, whenever a target is actually attached. With no target every such write lands on a null
        /// handle and fails harmlessly; with one attached the same call patches, retargets or terminates a
        /// real process. The engine already spells "there is no target" as <c>_hProcess == IntPtr.Zero</c>
        /// (DebugEngine.LibState.cs, DebugEngine.cs RequestPause) — this is that test inverted, so the seam
        /// cannot be misused instead of merely being documented as not-to-be-misused.</summary>
        private void RefuseSeamIfAttached(string seam)
        {
            if (_hProcess != IntPtr.Zero)
                throw new InvalidOperationException(seam + ": refuses to run against an attached debuggee");
        }

        internal uint OnUserBpForTest(uint tid, uint va)
        {
            RefuseSeamIfAttached("OnUserBpForTest");
            // The two remaining caller choices the seam used to trust. Both arms live on OnUserBp's PAUSING
            // route, which any plain breakpoint reaches: --once calls TerminateProcess, and interactive
            // blocks in PausedWait on a command queue nothing is feeding.
            if (_once)
                throw new InvalidOperationException(
                    "OnUserBpForTest: refuses a --once engine — the pausing route calls TerminateProcess");
            if (_interactive)
                throw new InvalidOperationException(
                    "OnUserBpForTest: refuses an interactive engine — the pausing route blocks in PausedWait");
            return OnUserBp(tid, va);
        }

        /// <summary>Register a mapped image (once) plus one armed user breakpoint at <paramref name="va"/>,
        /// with the original byte already recorded in the armed-byte map — the state a real
        /// EXCEPTION_BREAKPOINT arrives in. Advanced properties go through the shipped
        /// <see cref="ApplyBpProps"/>, so "no properties" means what the engine means by it.</summary>
        internal UserBreakpoint ArmUserBpForTest(uint loadBase, uint va, string condition, string hitMode,
                                                 int hitValue, string trace)
        {
            // MUTATES _modules/_bps/_armed. Against a live target the fake armed byte below would later be
            // written into the real process by the un-patch path.
            RefuseSeamIfAttached("ArmUserBpForTest");
            var owner = ModuleAt(va);
            if (owner == null)
            {
                owner = new LoadedModule { Name = "protocolcheck.exe", LoadBase = loadBase, Size = 0x200000 };
                _modules.Add(owner);
            }
            else if (owner.LoadBase != loadBase)
            {
                // The image is registered ONCE and reused, so on every call after the first this seam used
                // to drop `loadBase` on the floor and compute the RVA from the resolved module instead. A
                // caller that passed a different base got a breakpoint at an RVA it never asked for and was
                // told nothing — the argument had become decoration. It is not a detail the caller may be
                // vague about: Rvas is what the un-patch and re-arm paths work from.
                throw new InvalidOperationException(
                    "ArmUserBpForTest: va 0x" + va.ToString("X8") + " already resolves to " + owner.Name
                    + " at load base 0x" + owner.LoadBase.ToString("X8") + ", but was handed 0x"
                    + loadBase.ToString("X8") + " — the RVA would be computed from the resolved base, not "
                    + "the one passed, so the two must agree");
            }
            var bp = new UserBreakpoint
            {
                Module = "pc001.clw", ModuleIdx = -1, Owner = owner, RequestedLine = 100, Line = 100,
            };
            bp.Rvas.Add(va - owner.LoadBase);
            ApplyBpProps(bp, condition, hitMode, hitValue, trace);
            _bps.Add(bp);
            _armed[va] = 0x90;   // the byte the 0xCC replaced
            return bp;
        }

        /// <summary>Is there a pending re-plant for this thread at this VA, and is it the USER-breakpoint
        /// kind (<c>IsTemp = false</c>) that CancelStep must never drop? Without it the breakpoint silently
        /// stops firing after its first hit.</summary>
        internal bool HasUserBpRearmForTest(uint tid, uint va)
        {
            Rearm r;
            return _rearm.TryGetValue(tid, out r) && r.Va == va && !r.IsTemp;
        }
    }
}
