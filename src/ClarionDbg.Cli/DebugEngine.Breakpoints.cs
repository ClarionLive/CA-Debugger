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

        /// <summary>Register a breakpoint from a parsed spec.
        /// <para>
        /// WHICH IMAGES IT ARMS IN, and why each case is what it is (task af81c054):
        /// </para>
        /// <list type="bullet">
        /// <item>the spec NAMES an image (<c>|img=</c>) — that one, and if it is not mapped yet the
        /// breakpoint stays pending AGAINST THAT NAME rather than binding to whichever image happens to
        /// carry the compiland first.</item>
        /// <item>no image named, ONE image carries the compiland — that one. Identical to the behaviour
        /// before this ticket, and this is every single-DLL app and every non-colliding name, i.e. very
        /// nearly all real usage.</item>
        /// <item>no image named, SEVERAL carry it — ALL of them, one logical breakpoint each. The user
        /// pointed at a source LINE; if that source is compiled into three images it genuinely runs in
        /// three places, and stopping at all three is the honest answer. Picking one silently is not a
        /// smaller version of that answer, it is a different and wrong one delivered with confidence —
        /// and a missing stop is undetectable from inside the debugger while an extra one is explicable
        /// in a second, now that every echo carries its <c>ownerPath</c>.</item>
        /// <item>no image named, several carry it, but the caller asked for ONE target (<c>|one=1</c>) —
        /// the first, AND SAY SO. The log line is the point: an arbitrary choice announced beats the same
        /// choice made silently. Run-to-cursor sent this until wave 7; from 2026-09-25 the host sends its
        /// transient as a plain unqualified add, armed in every image, so a stop in any image ends it
        /// (contract C3). Nothing sends |one=1 now; it is still parsed and honoured.</item>
        /// </list></summary>
        private void AddBreakpoint(BpSpec spec)
        {
            string module = spec.Module;
            int line = spec.Line;

            var owners = OwnersOfModule(module);
            if (!string.IsNullOrEmpty(spec.Image))
            {
                // Narrow to the image the caller named. An empty result is NOT an error: at launch the
                // DLL is simply not mapped yet, and the pending path below binds it when it is.
                var narrowed = new List<LoadedModule>();
                foreach (var m in owners) if (ImageMatches(m, spec.Image)) narrowed.Add(m);
                owners = narrowed;
            }
            else if (spec.One && owners.Count > 1)
            {
                // Single-target by request. Announce the arbitrary pick rather than making it silently -
                // this is the ONE place this ticket knowingly leaves a first-match, so it says so.
                Console.WriteLine($"bp: {module}:{line} is carried by {owners.Count} loaded images; "
                                + $"arming only in {owners[0].Name} (single-target request)");
                owners = new List<LoadedModule> { owners[0] };
            }

            if (owners.Count == 0)
            {
                // No loaded/known image carries this compiland yet — defer. Arms when its DLL loads.
                // The dedupe key includes the IMAGE the caller named: two pre-launch dots in two DLLs are
                // two breakpoints, and before launch nothing is mapped, so THIS is where they used to
                // collapse into one - before any image resolution ran at all.
                foreach (var b in _bps)
                    if (PendingDuplicates(b, module, line, spec.Image))
                    {
                        // re-add of a pending bp = a properties update; re-apply and re-confirm
                        ApplyBpProps(b, spec.Condition, spec.HitMode, spec.HitValue, spec.Trace);
                        EmitBpSet(b);
                        return;
                    }
                var pend = new UserBreakpoint { Module = module, ModuleIdx = -1, RequestedLine = line, Line = line,
                                                OwnerSpec = spec.Image, SingleTargetRequested = spec.One };
                ApplyBpProps(pend, spec.Condition, spec.HitMode, spec.HitValue, spec.Trace);
                _bps.Add(pend);
                Console.WriteLine($"bp: {module}:{line} pending — owning image not loaded yet");
                EmitBpSet(pend);
                return;
            }

            foreach (var owner in owners) AddBreakpointIn(owner, spec);
        }

        /// <summary>Register (or re-confirm) one breakpoint in ONE named image. Split out of
        /// <see cref="AddBreakpoint"/> so arming in several images is a loop over the same body rather
        /// than a second copy of the resolve-snap-plant sequence. Takes the whole spec, not a list of its
        /// fields, so a field added to BpSpec cannot be dropped between the two.</summary>
        private void AddBreakpointIn(LoadedModule owner, BpSpec spec)
        {
            string module = spec.Module;
            int line = spec.Line;
            var dbg = owner.Dbg;
            int mi = dbg.FindModuleIdx(module);
            string canon = dbg.ModuleNameForIdx(mi) ?? module;
            int planted;
            List<uint> rvas;
            if (!TryResolveLine(dbg, mi, line, out planted, out rvas))
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
                    ApplyBpProps(b, spec.Condition, spec.HitMode, spec.HitValue, spec.Trace);
                    EmitBpSet(b);
                    return;
                }

            var bp = new UserBreakpoint { Module = canon, ModuleIdx = mi, Owner = owner, RequestedLine = line, Line = planted,
                                          OwnerSpec = spec.Image, SingleTargetRequested = spec.One };
            bp.Rvas.AddRange(rvas);
            ApplyBpProps(bp, spec.Condition, spec.HitMode, spec.HitValue, spec.Trace);
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

        /// <summary>Is this pending entry already the breakpoint the spec is asking for?
        /// <para>
        /// A NAMED PREDICATE RATHER THAN AN INLINE CONDITION, because this is the site that actually
        /// caused task af81c054. Before launch NOTHING is mapped, so every breakpoint arrives here, and
        /// the key used to be (module, line) alone - so two gutter dots in two different DLLs were folded
        /// into one entry before any image resolution ran, and no amount of correctness further down could
        /// recover the one that was thrown away.
        /// </para>
        /// <para>
        /// THE IMAGE IS PART OF THE KEY. Two entries naming different images are different breakpoints;
        /// two naming NO image are the same one, which is right, because an unqualified breakpoint means
        /// "every image that carries this compiland" and there is no second one of those to keep.
        /// <c>Eq</c> compares two nulls as equal, which is exactly that case.
        /// </para>
        /// <para>
        /// The two-way line test is the PRE-EXISTING behaviour of this branch and is left alone: a pending
        /// entry has Line == RequestedLine (nothing has snapped it yet, because nothing is mapped), so the
        /// second comparison cannot currently differ from the first.
        /// </para></summary>
        private static bool PendingDuplicates(UserBreakpoint b, string module, int line, string image)
        {
            return Eq(b.Module, module) && Eq(b.OwnerSpec, image)
                && (b.RequestedLine == line || b.Line == line);
        }

        /// <summary>Remove the breakpoint(s) a <c>bp del</c> spec names.
        /// <para>
        /// SYMMETRY WITH ADD IS THE RULE. A spec naming an image removes that one; an unqualified spec
        /// removes EVERY image's copy of that module:line, because an unqualified ADD is what armed them
        /// all and one gutter dot is what the user is taking away. Removing only the first would leave the
        /// others armed with nothing on screen accounting for them - the same silent-mismatch failure as
        /// the original defect, pointed the other way.
        /// </para></summary>
        private void RemoveBreakpoint(BpSpec spec)
        {
            string module = spec.Module;
            int line = spec.Line;

            // Prefer an exact requested-line match; only fall back to the planted line if nothing
            // requested it. Several logical bps can share one planted Line (distinct gutter lines that
            // snapped to the same record), so a planted-line match alone would remove an arbitrary one.
            var matches = new List<UserBreakpoint>();
            foreach (var b in _bps)
                if (Eq(b.Module, module) && b.RequestedLine == line && RemovalNames(b, spec.Image)) matches.Add(b);
            if (matches.Count == 0)
                foreach (var b in _bps)
                    if (Eq(b.Module, module) && b.Line == line && RemovalNames(b, spec.Image)) matches.Add(b);

            if (matches.Count == 0)
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(module, line, "no such breakpoint"));
                return;
            }
            foreach (var m in matches) RemoveOne(m, line);
        }

        /// <summary>Whether a del spec naming <paramref name="image"/> reaches breakpoint <paramref name="b"/>.
        /// A spec that names NO image reaches every copy (see <see cref="RemoveBreakpoint"/>); one that names
        /// an image reaches the copy bound to it, or - before that image has mapped - the pending entry that
        /// asked for it.</summary>
        private static bool RemovalNames(UserBreakpoint b, string image)
        {
            if (string.IsNullOrEmpty(image)) return true;
            if (b.Owner != null) return ImageMatches(b.Owner, image);
            return Eq(b.OwnerSpec, image);
        }

        private void RemoveOne(UserBreakpoint found, int line)
        {
            string canon = found.Module;
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
            _plantAllCalls++;   // protocolcheck: an --expect-start refusal must reach no planting at all
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
                NotePlanted(va, orig);   // remembered past its removal: a queued hit on it is still ours (Attach.cs)
            }
        }

        /// <summary>After an image maps, resolve+plant the breakpoints it owns.
        /// <para>
        /// TWO JOBS, and the second one is what actually fixes the reported defect. The first is the
        /// original: bind a PENDING breakpoint to the image that just arrived. The second is that an
        /// already-armed UNQUALIFIED breakpoint gets a COPY armed in this image too, because "no image
        /// named" means every image that carries the compiland (task af81c054) and the images do not all
        /// arrive at once - the second DLL typically maps long after the first has already claimed the
        /// breakpoint.
        /// </para>
        /// <para>
        /// Without the second job the launch case stays broken however well <c>AddBreakpoint</c> behaves:
        /// at launch NOTHING is mapped, so every breakpoint starts pending, the first image to map takes
        /// it, and every later image carrying the same .clw silently gets nothing.
        /// </para></summary>
        private void ResolvePendingFor(LoadedModule m)
        {
            if (m == null || m.Dbg == null) return;
            // ToArray: the copy pass appends to _bps, and the copies must not themselves be re-examined.
            // TWO PASSES, binds before copies (af81c054, pipeline run 1): interleaved in list order, an armed
            // sibling earlier in the list copied itself into m BEFORE a pending entry for the same line was
            // bound here too, and CopyUnqualifiedInto's coverage check could not see an entry not yet bound.
            var snapshot = _bps.ToArray();
            foreach (var bp in snapshot)
                if (bp.Pending) BindPendingTo(m, bp);
            foreach (var bp in snapshot)
                if (!bp.Pending) CopyUnqualifiedInto(m, bp);
        }

        /// <summary>Bind one pending breakpoint to the image that just mapped, if it carries the compiland
        /// and the breakpoint did not ask for a different image. The first job of <see cref="ResolvePendingFor"/>.</summary>
        private void BindPendingTo(LoadedModule m, UserBreakpoint bp)
        {
            if (!string.IsNullOrEmpty(bp.OwnerSpec) && !ImageMatches(m, bp.OwnerSpec)) return; // asked for a different image
            int mi = m.Dbg.FindModuleIdx(bp.Module);
            if (mi < 0) return; // this image doesn't carry that compiland

            int planted;
            List<uint> rvas;
            if (!TryResolveLine(m.Dbg, mi, bp.RequestedLine, out planted, out rvas)) return;

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

        /// <summary>An image just mapped that carries a compiland an UNQUALIFIED breakpoint is already
        /// armed in elsewhere: give this image its own copy. No-op for a breakpoint that named an image,
        /// for one requested single-target, and for a compiland this image does not carry.</summary>
        private void CopyUnqualifiedInto(LoadedModule m, UserBreakpoint bp)
        {
            if (bp.Owner == m || bp.SingleTargetRequested) return;
            if (!string.IsNullOrEmpty(bp.OwnerSpec)) return;   // it named an image; it is not "every image"
            int mi = m.Dbg.FindModuleIdx(bp.Module);
            if (mi < 0) return;

            // Already covered here? A second gutter line that snapped to this same record is a DIFFERENT
            // logical breakpoint and must not suppress this copy, so the check is on the REQUESTED line -
            // the same key AddBreakpointIn dedupes on, for the same reason.
            foreach (var other in _bps)
                if (other.Owner == m && other.ModuleIdx == mi && other.RequestedLine == bp.RequestedLine) return;

            int planted;
            List<uint> rvas;
            if (!TryResolveLine(m.Dbg, mi, bp.RequestedLine, out planted, out rvas))
                return;   // this image carries the name but not the line

            var copy = new UserBreakpoint
            {
                Module = m.Dbg.ModuleNameForIdx(mi) ?? bp.Module,
                ModuleIdx = mi,
                Owner = m,
                RequestedLine = bp.RequestedLine,
                Line = planted,
                OwnerSpec = null,
                SingleTargetRequested = false
            };
            copy.Rvas.AddRange(rvas);
            ApplyBpProps(copy, bp.Condition, bp.HitMode, bp.HitValue, bp.Trace);
            _bps.Add(copy);
            if (m.LoadBase != 0) PlantBp(copy);
            Console.WriteLine($"bp: also armed {copy.Module}:{copy.Line} in {m.Name} "
                            + $"(same .clw name is carried by more than one image)");
            EmitBpSet(copy);
        }

        /// <summary>Resolve a REQUESTED source line to the addresses to plant at in one image's compiland
        /// <paramref name="mi"/>. Clarion's line table is sparse, so a line with no record snaps to the
        /// nearest one that has one (<see cref="NearestIn"/>); <paramref name="planted"/> is the line
        /// actually used. False when neither the line nor any snap target has code, and then the out values
        /// are not to be used. The ONE copy of this sequence: AddBreakpointIn, BindPendingTo and
        /// CopyUnqualifiedInto each carried their own until f367a04f.</summary>
        private static bool TryResolveLine(TswdDebugInfo dbg, int mi, int line, out int planted, out List<uint> rvas)
        {
            planted = line;
            rvas = dbg.LineToRvasInModuleIdx(mi, line);
            if (rvas.Count == 0)
            {
                int snapped = NearestIn(dbg.BreakableLinesInModuleIdx(mi), line);
                if (snapped > 0) { planted = snapped; rvas = dbg.LineToRvasInModuleIdx(mi, snapped); }
            }
            return rvas.Count > 0;
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
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);
            uint status = OnUserBpCore(tid, va, hThread, ref ctx, haveCtx);
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return status;
        }

        /// <summary>The user-breakpoint hit with the thread context already read, so OnUserBpForTest can hand
        /// it a context (a skip landing is decided on ESP/EBP) without a live thread behind it. The caller
        /// owns <paramref name="hThread"/>.</summary>
        private uint OnUserBpCore(uint tid, uint va, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            Hits++;
            var m = ModuleAt(va);
            uint rva = m != null ? va - m.LoadBase : va;

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
                    //
                    // ONLY FOR THE STEPPING THREAD (f367a04f). _prevVa is the anchor of _stepTid's step and
                    // nobody else's: OnSingleStep drives StepMachine for `tid == _stepTid` alone, so a
                    // silent hit on any other thread has no step of its own to re-anchor. Unguarded, a
                    // tracepoint firing on thread B moved thread A's anchor to an address A never ran.
                    //
                    // UNLESS this is the stepping thread's skip landing (IsSkipLanding): a user bp there is the
                    // only INT3 at that address, so the skip ends here exactly as OnTempBp ends it, stopping
                    // if the landing is a stop boundary. Without it _skipRunning stayed set, StepMachine never
                    // ran again, and Step Over over a call (or END) whose landing has a tracepoint ran free.
                    if (IsSkipLanding(tid, va, ref ctx, haveCtx))
                        FinishSkipAt(tid, va, hThread, ref ctx, haveCtx);
                    else
                    {
                        if (tid == _stepTid) _prevVa = va;
                        if (haveCtx)
                        {
                            Native.GetThreadContext(hThread, ref ctx);
                            ctx.EFlags |= TRAP_FLAG;
                            Native.SetThreadContext(hThread, ref ctx);
                        }
                    }
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
            uint status = OnTempBpCore(tid, va, hThread, ref ctx, haveCtx);
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return status;
        }

        /// <summary>The temp-INT3 hit with the thread context already read, so OnTempBpForTest can hand it a
        /// context (the ESP is what the decision turns on) without a live thread behind it.</summary>
        private uint OnTempBpCore(uint tid, uint va, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            byte orig = _temp[va];
            WriteByte(va, orig);
            if (haveCtx) ctx.Eip = va;

            // ANOTHER THREAD ran through the stepping thread's call-skip return address (65931ddd). The temp
            // INT3 sits in shared code, so any thread can execute it, but everything below belongs to
            // _stepTid's step: _skipEntryEsp is ITS callee-entry ESP, _prevVa ITS anchor, _skipRunning ITS
            // run-to-return. Compared with thread B's ESP, `returned` could read true and end A's skip on B's
            // behalf (A's step then ran on as a Continue), or put TF and A's anchor on B. So B gets what a
            // user breakpoint gives a passing thread: the byte back, one TF step off it, and the temp
            // re-planted by OnSingleStep's re-arm if it still exists by then. No step state is touched.
            if (_mode != StepMode.None && tid != _stepTid)
            {
                _rearm[tid] = new Rearm { Va = va, IsTemp = true };
                if (haveCtx)
                {
                    ctx.EFlags |= TRAP_FLAG;
                    Native.SetThreadContext(hThread, ref ctx);
                }
                return Native.DBG_CONTINUE;
            }

            // recursion guard: the same call-site return address fires for INNER frames too.
            // We've truly returned to our frame only when ESP is back above the callee entry - or, for
            // ACCEPT's two event-loop calls, which return with ESP elsewhere, when EBP is back at our frame.
            bool returned = haveCtx && SkipHasReturned(_skipEventLoopKind, ctx.Esp, ctx.Ebp, _skipEntryEsp, _skipEntryEbp);
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
                FinishSkipAt(tid, va, hThread, ref ctx, haveCtx);
            }

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
        /// cannot be misused instead of merely being documented as not-to-be-misused.
        /// "Attached" here means HOLDING ANY DEBUGGEE, launched or attached with `attach &lt;pid&gt;` alike: the
        /// name predates the attach verb (3f2d747f), and the test is the handle, not how it was obtained.</summary>
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

        /// <summary><see cref="OnUserBpForTest(uint,uint)"/> with an invented context: thread
        /// <paramref name="tid"/> hitting <paramref name="va"/> at ESP <paramref name="esp"/> and EBP
        /// <paramref name="ebp"/>, for the skip-landing decision (<see cref="IsSkipLanding"/>). No thread is
        /// opened; SetThreadContext goes to a null handle and fails. Same refusals as the other overload.</summary>
        internal uint OnUserBpForTest(uint tid, uint va, uint esp, uint ebp)
        {
            RefuseSeamIfAttached("OnUserBpForTest");
            if (_once)
                throw new InvalidOperationException(
                    "OnUserBpForTest: refuses a --once engine — the pausing route calls TerminateProcess");
            if (_interactive)
                throw new InvalidOperationException(
                    "OnUserBpForTest: refuses an interactive engine — the pausing route blocks in PausedWait");
            var ctx = NewContext();
            ctx.Esp = esp;
            ctx.Ebp = ebp;
            ctx.Eip = va + 1;   // where the INT3 leaves EIP
            return OnUserBpCore(tid, va, IntPtr.Zero, ref ctx, true);
        }

        /// <summary>Drive the REAL temp-INT3 handler as thread <paramref name="tid"/> arriving at
        /// <paramref name="va"/> with ESP <paramref name="esp"/> and EBP <paramref name="ebp"/>. The context is
        /// invented and no thread is opened, because the stack registers against the recorded callee entry are
        /// the decision under test; SetThreadContext goes to a null handle and fails. The route that PAUSES
        /// needs a line table to reach, and this engine has none, so nothing here can block in PausedWait.</summary>
        internal uint OnTempBpForTest(uint tid, uint va, uint esp, uint ebp)
        {
            RefuseSeamIfAttached("OnTempBpForTest");
            if (!_temp.ContainsKey(va))
                throw new InvalidOperationException("OnTempBpForTest: no temp INT3 recorded at 0x" + va.ToString("X8")
                                                    + " - the dispatcher would never route this hit here");
            var ctx = NewContext();
            ctx.Esp = esp;
            ctx.Ebp = ebp;
            ctx.Eip = va + 1;   // where the INT3 leaves EIP
            return OnTempBpCore(tid, va, IntPtr.Zero, ref ctx, true);
        }

        /// <summary>Is there a pending TEMP re-plant (<c>IsTemp = true</c>) for this thread at this VA?</summary>
        internal bool HasTempRearmForTest(uint tid, uint va)
        {
            Rearm r;
            return _rearm.TryGetValue(tid, out r) && r.Va == va && r.IsTemp;
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

        // ------------------------------------------------------------------ test seams for multi-image breakpoints
        //
        // Contract C3 (wave 7): run-to-cursor is `bp add module:line` with no |one=1, removed with `bp del
        // module:line`, so these drive the REAL bp command and the REAL image-mapped sequence against images
        // whose TSWD protocolcheck builds. An image registered at load base 0 is known but not mapped, as a
        // solution DLL is before launch: breakpoints bind to it and nothing is written to any process.

        /// <summary>Register an image with the given path and debug info, as the module table holds one.</summary>
        internal LoadedModule AddImageForTest(string path, TswdDebugInfo dbg, uint loadBase)
        {
            RefuseSeamIfAttached("AddImageForTest");
            var m = new LoadedModule { Path = path, Name = Path.GetFileName(path).ToLowerInvariant(),
                                       LoadBase = loadBase, Size = 0x200000, Dbg = dbg };
            _modules.Add(m);
            return m;
        }

        /// <summary>One `bp ...` command line, through the real handler.</summary>
        internal void BpCommandForTest(string line)
        {
            RefuseSeamIfAttached("BpCommandForTest");
            HandleBpCommand(line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
        }

        /// <summary>What a LOAD_DLL does for breakpoints once the image is in the table (DebugEngine.Modules.cs):
        /// plant those bound to it, then resolve pending ones and copy unqualified ones into it.</summary>
        internal void ImageMappedForTest(LoadedModule m)
        {
            RefuseSeamIfAttached("ImageMappedForTest");
            PlantOwnBps(m);
            ResolvePendingFor(m);
        }

        /// <summary>Each logical breakpoint as "module:requestedLine@ownerPath" ("(pending)" for no owner).</summary>
        internal List<string> BpsForTest()
        {
            var list = new List<string>();
            foreach (var b in _bps)
                list.Add(b.Module + ":" + b.RequestedLine + "@" + (b.Owner != null ? b.Owner.Path : "(pending)"));
            return list;
        }
    }
}
