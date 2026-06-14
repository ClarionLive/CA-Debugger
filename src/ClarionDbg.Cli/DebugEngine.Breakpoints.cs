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
        private void AddBreakpoint(string module, int line)
        {
            var owner = OwnerOfModule(module);
            if (owner == null)
            {
                // No loaded/known image carries this compiland yet — defer. Arms when its DLL loads.
                foreach (var b in _bps)
                    if (Eq(b.Module, module) && (b.RequestedLine == line || b.Line == line)) return; // dup
                var pend = new UserBreakpoint { Module = module, ModuleIdx = -1, RequestedLine = line, Line = line };
                _bps.Add(pend);
                Console.WriteLine($"bp: {module}:{line} pending — owning image not loaded yet");
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(module, line, line, pend.Rvas));
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
                    if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(b.Module, line, b.Line, b.Rvas));
                    return;
                }

            var bp = new UserBreakpoint { Module = canon, ModuleIdx = mi, Owner = owner, RequestedLine = line, Line = planted };
            bp.Rvas.AddRange(rvas);
            _bps.Add(bp);
            if (owner.LoadBase != 0) PlantBp(bp);
            if (planted != line)
                Console.WriteLine($"bp: line {line} has no code record in {canon}; breakpoint moved to nearest line {planted}");
            Console.WriteLine($"bp: set {canon}:{planted} ({bp.Rvas.Count} address(es))");
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(canon, line, planted, bp.Rvas));
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
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpDel(canon, found.Line));
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
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(bp.Module, bp.RequestedLine, bp.Line, bp.Rvas));
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
            CancelStep(); // a real BP hit supersedes any in-flight step (drops temp re-arms, not this one)

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
            string proc = ProcNameAt(m, rva, resolved ? moduleIdx : -1);
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
                if (_mode == StepMode.OverInstr && haveCtx)
                {
                    // instruction step-over: the call we stepped has returned — stop AT the return
                    // address (the next instruction), don't single-step through it. The INT3 advanced
                    // the thread's EIP to va+1, so commit the corrected EIP (=va) before pausing,
                    // otherwise the next resume runs from mid-instruction and crashes the target.
                    Native.SetThreadContext(hThread, ref ctx);
                    StopStepAndPause(tid, hThread, ref ctx, "stepi");
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
    }
}
