// Was DebugEngine.Eval.cs until 337b3222. The old name meant "func-eval": this file used to hijack the
// paused thread to CALL THR$GetInstance. 992d3e4 replaced that with read-only emulation, so no evaluation
// of any kind happens here any more — it resolves a name and reads memory, which is the Watch panel's job
// and nothing else's. Two comments elsewhere still cite the old filename; they are cited to the PM rather
// than edited here, because this branch does not own those lines.
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
        // ------------------------------------------------------------------ THREADed (.cwtls) instances
        //
        // A THREADed variable's link-time address is a TEMPLATE; each Clarion thread gets its own instance,
        // and ClaRUN.dll!THR$GetInstance(EAX = template VA, EBX = .cwtls base) maps one to the other.
        //
        // We resolve it by EMULATING that export read-only (RtlEmulator — the same machinery Library State
        // uses), NOT by hijacking the paused thread to call it. Hijacking resumed the whole process for the
        // call, which:
        //   * never completed when the paused thread sat in a syscall (a Pause with a browse open parks the
        //     thread in GetMessage) — the watch simply never answered and the row stayed on "…",
        //   * returned a corrupt instance when it did finally run (the syscall's own return value lands in
        //     EAX), and read the wrong thread's data,
        //   * left the engine running while the host still believed it was paused, and
        //   * had a single eval slot that another thread's debug event could overwrite mid-flight.
        // Emulation runs no target code, so it answers inline, at any stop, for the thread the user is
        // looking at. THR$GetInstance's fast path is pure: thread object via TlsGetValue, slot index from
        // [.cwtls base], instance from the thread's slot table, result = template + (slot - .cwtls base).
        // Only the FIRST touch of a variable on a thread allocates (a write) — see TryResolveThreadedInstance.

        /// <summary>How a THREADed name resolved on the paused thread.</summary>
        internal enum ThreadedResolve
        {
            Ok,            // instanceVa is this thread's live instance
            Template,      // this thread has no instance of its own: the template itself is what it reads
            Unallocated,   // this thread has not touched the data yet; no instance exists to read
            Failed,        // could not resolve (no import, no TEB, emulator refusal, unreadable result)
        }

        // Per-thread, per-image .cwtls INSTANCE BLOCK base: the address this image's whole .cwtls span maps
        // to on one thread. Every field of every record in an image shares one block, so a whole table
        // expanding costs one emulation instead of one per row. Keyed by (tid, image load base).
        //
        // ONE NOUN, deliberately: what is cached is a .cwtls instance-block base, NOT a TLS base. The TEB's
        // TLS array is how THR$GetInstance FINDS the block; it is not the thing stored here.
        //
        // LIFETIME — a cached block base only means anything while the target is FROZEN at one debug event,
        // so every episode that reads it clears it on the way in: a stop (ClearThreadedBlockCache in
        // PausedWait) and a breakpoint-hit evaluation (ClearThreadedBlockCache in ShouldPauseAtBp). Between
        // two episodes the target ran arbitrary code — a thread can exit and its tid be reused, an image can
        // unload and reload at the same base, the runtime can move a thread's block — so nothing cached is
        // allowed to cross an episode boundary. The per-tid overload is defence in depth on top of that; see
        // its call site on EXIT_THREAD.
        private readonly Dictionary<ulong, uint> _threadedBlockCache = new Dictionary<ulong, uint>();

        private static ulong ThreadedBlockKey(uint tid, uint loadBase) { return ((ulong)tid << 32) | loadBase; }

        /// <summary>Landing pad for the one-byte liveness probe on a cached block base. Reused rather than
        /// allocated per call because that probe runs on EVERY THREADed field read — once per row of a
        /// Variables pane, once per watch, and once per thread per name under `threadscan NAME`.
        ///
        /// Sharing a mutable buffer is only safe when nobody reads it, and nobody does: the probe wants the
        /// COUNT ReadBlock returns, never the byte it landed. It is never handed out, never compared and
        /// never carried across a call, so there is no stale content to inherit. (The engine also does all
        /// of this on the debug-event thread, but that is the weaker of the two reasons and not the one to
        /// rely on.)</summary>
        private readonly byte[] _blockProbeByte = new byte[1];

        private void ClearThreadedBlockCache() { _threadedBlockCache.Clear(); }
        private void ClearThreadedBlockCache(uint tid)
        {
            var dead = new List<ulong>();
            foreach (var k in _threadedBlockCache.Keys) if ((uint)(k >> 32) == tid) dead.Add(k);
            foreach (var k in dead) _threadedBlockCache.Remove(k);
        }

        /// <summary>Map a THREADed template VA to the paused thread's instance by emulating the owning image's
        /// imported THR$GetInstance read-only. No target code runs, so this is safe at any stop and answers
        /// inline. A run that writes THE BLOCK IT THEN RETURNS is the runtime's allocate-on-first-touch path:
        /// the thread has no instance yet, and creating one would be a side effect, so that reports
        /// Unallocated rather than a made-up address. A write ANYWHERE ELSE is not that path and does not
        /// discard the result — it is reported instead, because an emulation nobody can see going wrong is
        /// how a broken read gets shown to the user as a real value.</summary>
        private ThreadedResolve TryResolveThreadedInstance(LoadedModule owner, uint templateVa, uint tid,
                                                           IntPtr hThread, out uint instanceVa, out string reason)
        {
            instanceVa = 0; reason = null;
            uint cwtlsBase = owner.LoadBase + owner.CwtlsLo;

            // one emulation per (thread, image) per episode — every other field resolves off the cached block
            ulong key = ThreadedBlockKey(tid, owner.LoadBase);
            uint cached;
            if (_threadedBlockCache.TryGetValue(key, out cached))
            {
                uint hit = templateVa - cwtlsBase + cached;
                // Probe the cached answer exactly as the freshly-emulated one is probed below. A cached base
                // is an address the TARGET owns, not a fact we derived, and nothing here can promise the
                // block is still mapped. If one byte will not read, drop the entry and re-emulate rather than
                // report Ok for an address the caller would then render as a value.
                if (ReadBlock(hit, _blockProbeByte) >= 1) { instanceVa = hit; return ThreadedResolve.Ok; }
                _threadedBlockCache.Remove(key);
            }

            if (owner.ThrGetInstanceIatRva == 0)
            {
                reason = "THREADed data but the THR$GetInstance import was not found in " + owner.Name;
                return ThreadedResolve.Failed;
            }
            if (hThread == IntPtr.Zero) { reason = "no thread handle for the paused thread"; return ThreadedResolve.Failed; }

            uint helper = ReadU32(owner.LoadBase + owner.ThrGetInstanceIatRva);
            if (helper == 0) { reason = "could not read the THR$GetInstance address from the IAT"; return ThreadedResolve.Failed; }

            var rt = ModuleAt(helper);
            if (rt == null || rt.Pe == null) { reason = "THR$GetInstance is not inside a known loaded image"; return ThreadedResolve.Failed; }

            uint teb = GetTebBase(hThread);
            if (teb == 0) { reason = "could not resolve the thread's TEB"; return ThreadedResolve.Failed; }

            RtlEmulator emu;
            try { emu = BuildEmulator(rt, tid, teb); }
            catch (Exception ex) { reason = "could not build the RTL emulator: " + ex.Message; return ThreadedResolve.Failed; }

            uint result, blockBase;
            var verdict = ClassifyEmulatedInstance(owner, templateVa, emu, helper, out result, out blockBase, out reason);
            if (verdict == ThreadedResolve.Template) instanceVa = templateVa;
            if (verdict != ThreadedResolve.Ok) return verdict;

            var probe = new byte[1];
            if (ReadBlock(result, probe) < 1)
            {
                reason = $"THR$GetInstance returned an unreadable instance (0x{result:X})";
                return ThreadedResolve.Failed;
            }
            _threadedBlockCache[key] = blockBase;

            instanceVa = result;
            return ThreadedResolve.Ok;
        }

        /// <summary>The verdict on ONE emulation of THR$GetInstance: run it, then decide what its result
        /// and its debuggee writes mean. Split out of <see cref="TryResolveThreadedInstance"/> so a harness can
        /// drive these branches: they only run when something has gone wrong, and no live target made them
        /// fire (38b75897). It touches the debuggee only through <paramref name="emu"/>'s own read delegate
        /// and reports through NoteThreadedEmulation. Ok means a CANDIDATE: the caller still probes
        /// <paramref name="result"/> before trusting it, and caches <paramref name="blockBase"/> only then.</summary>
        private ThreadedResolve ClassifyEmulatedInstance(LoadedModule owner, uint templateVa, RtlEmulator emu, uint helper,
                                                         out uint result, out uint blockBase, out string reason)
        {
            result = 0; blockBase = 0; reason = null;
            uint cwtlsBase = owner.LoadBase + owner.CwtlsLo;
            uint delta = templateVa - cwtlsBase;                    // this name's offset inside the .cwtls span
            uint cwtlsSize = owner.CwtlsHi > owner.CwtlsLo ? owner.CwtlsHi - owner.CwtlsLo : 0;

            try
            {
                result = emu.Call(helper, templateVa, cwtlsBase);
            }
            catch (Exception ex)
            {
                // A throw leaves no result, so there is no block to test the write against — the write itself
                // is the only evidence, and the allocate path writes before it loses us. Still report
                // Unallocated, but never SILENTLY: an emulation that is genuinely broken and happens to write
                // first would otherwise reach the user as "not yet used on this thread" with the template's
                // value shown as real. Library State prints every failure it swallows; this used to print none.
                if (emu.WroteDebuggeeMemory)
                {
                    reason = "not yet allocated on this thread";
                    NoteThreadedEmulation(owner, "failed-emulation-reported-unallocated",
                                          "reporting 'not yet allocated' after a failed emulation", ex, emu);
                    return ThreadedResolve.Unallocated;
                }
                reason = ex is RtlEmulator.NotSupported
                    ? "THR$GetInstance is not emulatable on this runtime (" + ex.Message + ")"
                    : "THR$GetInstance emulation failed — " + ex.GetType().Name + ": " + ex.Message;
                return ThreadedResolve.Failed;
            }

            if (result == 0)
            {
                // Nothing came back. With a debuggee write that is the allocate path losing us partway;
                // without one the emulation simply produced no instance.
                if (emu.WroteDebuggeeMemory) { reason = "not yet allocated on this thread"; return ThreadedResolve.Unallocated; }
                reason = "THR$GetInstance returned no instance";
                return ThreadedResolve.Failed;
            }

            // Every formula below subtracts `delta` from the result to get the block base. A result smaller
            // than the offset cannot be this name's instance — the subtraction would wrap and hand the cache a
            // base pointing at nothing.
            if (result < delta)
            {
                reason = $"THR$GetInstance returned 0x{result:X}, below this name's .cwtls offset (0x{delta:X})";
                return ThreadedResolve.Failed;
            }
            blockBase = result - delta;

            // The allocate-on-first-touch discriminator. This USED to be a one-way door: ANY debuggee write
            // discarded the result, so a single incidental scratch write in THR$GetInstance's read path made
            // every THREADed name on the thread report "not yet used on this thread" — a template value shown
            // as this thread's own. A write only means "allocated" when it landed in the block being handed
            // back. Anything else is reported and stepped over, not treated as a verdict.
            if (emu.WroteDebuggeeMemory)
            {
                if (cwtlsSize == 0 || emu.WroteWithin(blockBase, cwtlsSize))
                {
                    // cwtlsSize == 0 means there is no block span to test against, so the cautious old answer
                    // is the only honest one — but say so rather than let it pass for a measurement.
                    reason = "not yet allocated on this thread";
                    if (cwtlsSize == 0)
                        NoteThreadedEmulation(owner, "no-cwtls-span",
                                              "no .cwtls span to test the write against — assuming the allocate path",
                                              null, emu);
                    return ThreadedResolve.Unallocated;
                }
                NoteThreadedEmulation(owner, "write-outside-block",
                    $"kept instance 0x{result:X} despite a debuggee write outside its block (0x{blockBase:X}+0x{cwtlsSize:X})",
                    null, emu);
            }

            // A thread that is not a Clarion thread (or an image whose data isn't really threaded) legitimately
            // gets the TEMPLATE back — that IS what code on that thread reads, so the value is real and worth
            // showing. But it is shared, not this thread's own: writing it would change what every future
            // thread starts from, the same reason the Unallocated branch refuses to write. So it gets its own
            // outcome rather than passing for an instance, and it is never cached — the cache maps a whole
            // image's block for a thread that HAS one.
            if (result == templateVa)
            {
                reason = "no thread instance — shared template value";
                return ThreadedResolve.Template;
            }

            return ThreadedResolve.Ok;
        }

        /// <summary>Test seam for `protocolcheck` (38b75897): the REAL post-emulation verdict, run on an
        /// emulator the harness built over its own memory and code. The fault is injected through what the
        /// harness hands in, never through a switch a production caller could set; this touches no target.</summary>
        internal ThreadedResolve ClassifyEmulatedInstanceForTest(LoadedModule owner, uint templateVa, RtlEmulator emu,
                                                                 uint helper, out uint result, out string reason)
        {
            uint blockBase;
            return ClassifyEmulatedInstance(owner, templateVa, emu, helper, out result, out blockBase, out reason);
        }

        /// <summary>Report an emulation whose outcome the user will never see stated in the value itself — a
        /// failure swallowed behind "Unallocated", a debuggee write we decided NOT to treat as the allocate
        /// path, or a span we could not test. None of these change what is displayed, which is exactly why
        /// none of them may be silent: a broken emulation that happens to write first would otherwise pass for
        /// "not yet used on this thread" with the template's value shown as real. Mirrors Library State, which
        /// prints every getter it could not run. The emulator's own trace goes with it (capped — a block-sized
        /// REP STOS is one line, but a long call chain is not) because "wrote 0x…" is the whole question.</summary>
        private void NoteThreadedEmulation(LoadedModule owner, string reasonKey, string what,
                                           Exception ex, RtlEmulator emu)
        {
            // Once per (image, reason) per session. Every one of these fires per FIELD READ, so a
            // conditional breakpoint over an image with no .cwtls span buries the console in identical
            // notes — and the trace below is up to 12 lines each. What the second one adds is nothing.
            //
            // The key is reasonKey, a constant from the call site, NOT `what`: `what` interpolates the
            // instance address and the block span, so keying on the message would dedup nothing at all and
            // would look like it was working. The suffix is on the line so the reader can tell "happened
            // once" from "happens constantly and is being suppressed" — the whole point of this reporter is
            // that it is never silent, and dropping repeats without saying so is a quieter way of being it.
            if (!FirstReportOf("threaded|" + owner.Name + "|" + reasonKey)) return;

            Console.WriteLine($"  threaded {owner.Name}: {what}"
                              + (ex != null ? $" — {ex.GetType().Name}: {ex.Message}" : "") + ONCE_SUFFIX);
            const int cap = 12;
            int n = 0;
            foreach (var t in emu.Trace)
            {
                if (n++ == cap) { Console.WriteLine($"      emu: … ({emu.Trace.Count - cap} more)"); break; }
                Console.WriteLine("      emu: " + t);
            }
        }

        /// <summary>Test seam driving the REAL reporter, not just the predicate under it. Whether these
        /// notes dedup correctly is decided by how the KEY IS BUILT here, and a check that only exercised
        /// FirstReportOf would pass just as happily against a version that keyed on the message text — which
        /// interpolates addresses and would therefore dedup nothing while looking like it worked.
        ///
        /// The emulator is real but never run, so its Trace is empty and the note is one line.</summary>
        internal void NoteThreadedEmulationForTest(string image, string reasonKey, string what)
        {
            var owner = new LoadedModule { Name = image };
            var emu = new RtlEmulator(null, null, 0, 0, null, null, 0x00100000);
            NoteThreadedEmulation(owner, reasonKey, what, null, emu);
        }

        // ------------------------------------------------------------------ watch (by name)

        /// <summary>
        /// watch NAME — resolve a data name and read its CURRENT value on the paused thread. Every outcome
        /// emits a watch event keyed by the name (value, miss, or error), so a row the host is showing as
        /// pending always resolves to something instead of waiting forever. Answers inline: nothing here
        /// runs target code, so the caller always stays in the pause loop.
        /// </summary>
        private void HandleWatchCommand(string[] parts, uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (parts.Length < 2) { EmitError("watch expects: watch NAME"); return; }
            string name = parts[1];

            // A procedure-local shadows a same-named global while we are paused inside its frame, so resolve the
            // CURRENT frame's locals FIRST. Locals live on the stack (never .cwtls), so this is a direct read.
            uint slotVa; LocalSym lsym; LoadedModule lowner;
            if (TryResolveLocalInCurrentFrame(ref ctx, haveCtx, hThread, name, out slotVa, out lsym, out lowner))
            {
                EmitWatchValue(tid, name, slotVa, slotVa, false, lsym.TypeCode, lsym.Size, lsym.Target, lsym.Places);
                return;
            }

            // What the rest reads: a global's template address and type, or a global-headed watch PATH's
            // member. target/places stay 0 for a plain global, whose DataLocation does not carry them.
            // spanSize is what the symbol OCCUPIES, which differs from the render size for a &STRING member
            // (a 4-byte pointer that renders its referent's length).
            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            uint templateVa, size, spanSize; byte typeCode, target = 0; int places = 0;
            if (ResolveDataAcrossModules(name, out owner, out loc))
            {
                templateVa = owner.LoadBase + loc.Rva;
                typeCode = loc.TypeCode; size = loc.Size; spanSize = loc.Size;
            }
            else
            {
                // A watch PATH (GROUP.MEMBER) is tried only here, after both lookups above missed, so no
                // name that resolves today changes meaning (a restored watch list reads as it did).
                var path = TryWatchPath(name, tid, ref ctx, haveCtx, hThread, out owner, out templateVa, out typeCode, out target,
                                        out size, out places, out spanSize);
                if (path == PathResolve.Answered) return;
                if (path == PathResolve.NoHead)
                {
                    // Not a current-frame local and not a global. If it IS a local of some other procedure, it is
                    // merely out of scope right now (we are paused elsewhere) — flag that so the Watch row reads
                    // "(out of scope)" rather than the misleading "(not found)" used for genuinely unknown names.
                    bool outOfScope = haveCtx && IsKnownLocalName(name);
                    EmitThreadEvent(tid, Json.WatchMiss(name, outOfScope));
                    Console.WriteLine($"  watch {name}: {(outOfScope ? "out of scope" : "not found")}");
                    return;
                }
                // PathResolve.GlobalMember: a member's TEMPLATE address, classified over its own span below
                // and mapped to this thread's instance like any other THREADed name.
            }
            // Over the symbol's SPAN, through the shared test (ef0a941d): a start-only test showed a symbol
            // straddling into the template as ordinary data, a silent wrong value with a pencil.
            var span = ClassifyTemplateSpan(owner, templateVa, spanSize);

            if (span == TemplateSpan.Outside)
            {
                EmitWatchValue(tid, name, templateVa, templateVa, false, typeCode, size, target, places);
                return;
            }
            if (span == TemplateSpan.Straddling)
            {
                // Same words and same permission as the module-data panel's straddling row (Locals.cs), so
                // one name at one stop never reads two ways.
                EmitWatchValue(tid, name, templateVa, templateVa, true, typeCode, size, target, places,
                               note: "partly in the shared " + owner.Name + " template — not this thread's own data",
                               editable: false);
                return;
            }

            uint instanceVa; string reason;
            switch (TryResolveThreadedInstance(owner, templateVa, tid, hThread, out instanceVa, out reason))
            {
                case ThreadedResolve.Ok:
                    EmitWatchValue(tid, name, templateVa, instanceVa, true, typeCode, size, target, places);
                    break;

                case ThreadedResolve.Unallocated:
                    // The thread has never touched this data, so there is no instance to read. Its first touch
                    // will start from the template's initial value, so show that — read-only, since writing the
                    // template would change what EVERY future thread starts from.
                    EmitWatchValue(tid, name, templateVa, templateVa, true, typeCode, size, target, places,
                                   note: "not yet used on this thread — initial value", editable: false);
                    break;

                case ThreadedResolve.Template:
                    // Not a Clarion thread (e.g. a pause that landed on a worker or the injected break thread):
                    // the template IS what code here reads, so show it — but it is shared data, not this
                    // thread's own, and writing it would change what every future thread starts from.
                    EmitWatchValue(tid, name, templateVa, templateVa, true, typeCode, size, target, places,
                                   note: reason, editable: false);
                    break;

                default:
                    EmitWatchError(tid, name, reason);
                    break;
            }
        }

        // ------------------------------------------------------------------ watch (by path)

        /// <summary>What <see cref="WalkWatchPath"/> made of a path.</summary>
        internal enum WatchPathOutcome
        {
            /// <summary>Every member resolved; the leaf's address and type are set.</summary>
            Ok,
            /// <summary>A member is not declared there (or a segment is empty): an ordinary "(not found)".</summary>
            Miss,
            /// <summary>The path goes through something a name path does not follow: a reference below the
            /// head, a class reference, a global reference head, or an array. Reported as a watch ERROR, so
            /// the row says why instead of "(not found)" for a name that plainly exists.</summary>
            Unsupported,
            /// <summary>The head is a reference and holds null, or its pointer could not be read.</summary>
            BadReference,
        }

        internal const string PathUnsupported = "path through a reference/array is not supported";
        internal const string PathClassRef = "path through a class reference is not supported";
        internal const string PathNullRef = "reference is null";
        internal const string PathUnreadableRef = "could not read the reference";

        /// <summary>
        /// Walk the MEMBERS of a watch path (HEAD.MEMBER[.MEMBER]) from its head's layout, adding each
        /// member's byte offset. Pure: no process is touched except through <paramref name="readPointer"/>,
        /// so protocolcheck drives this exact function with a hand-built type.
        ///
        /// The head is a DIRECT GROUP/QUEUE, read at <paramref name="headVa"/> + offsets, or (a LOCAL only)
        /// a reference to a GROUP/QUEUE: the one hop the Owner allowed (3a0c915d, 2026-09-23). Then
        /// <paramref name="headVa"/> is the frame SLOT, and the members are read from the pointer it holds,
        /// fetched here on every call. That is the point of a name path: nothing is stored between pauses,
        /// so a stack frame re-entered at a new address or a queue buffer the runtime moved is read where it
        /// is now. Below the head only direct groups are followed.
        /// </summary>
        /// <param name="headCode">the head symbol's type code; 0x16 marks it by-reference even when its type
        /// record points straight at a group (the same test NodeJson uses to draw the lazy node).</param>
        /// <param name="readPointer">reads a u32 from the target, or null when it cannot be read.</param>
        internal static WatchPathOutcome WalkWatchPath(ClarionType headType, byte headCode, bool headIsLocal, uint headVa,
                                                       IList<string> members, Func<uint, uint?> readPointer,
                                                       out uint leafVa, out ClarionType leafType, out string error)
        {
            leafVa = 0; leafType = null; error = null;
            if (members == null || members.Count == 0) return WatchPathOutcome.Miss;

            ClarionType g;
            uint baseVa;
            bool byRef = headCode == 0x16 || (headType != null && headType.Kind == TypeKind.Reference);
            if (byRef)
            {
                g = GroupTypeOf(headType);
                // A global reference head is out of scope (3a0c915d); so is a reference to anything but a group.
                if (!headIsLocal || g == null) { error = PathUnsupported; return WatchPathOutcome.Unsupported; }
                if (LooksLikeClassLayout(g)) { error = PathClassRef; return WatchPathOutcome.Unsupported; }
                uint? ptr = readPointer(headVa);
                if (!ptr.HasValue) { error = PathUnreadableRef; return WatchPathOutcome.BadReference; }
                if (ptr.Value == 0) { error = PathNullRef; return WatchPathOutcome.BadReference; }
                baseVa = ptr.Value;
            }
            else if (headType != null && headType.Kind == TypeKind.Group)
            {
                g = headType;
                baseVa = headVa;
            }
            else if (headType != null && headType.Kind == TypeKind.Array)
            {
                error = PathUnsupported; return WatchPathOutcome.Unsupported;
            }
            else return WatchPathOutcome.Miss;   // a scalar (or untyped) head declares no members

            for (int i = 0; i < members.Count; i++)
            {
                // IsValidWatchName lets "A." and ".A" through. An empty segment needs no test of its own:
                // no member is named "", so it misses below (a guard here was mutated away on 2026-09-23
                // and nothing went red).
                string seg = members[i];
                TypeMember hit = null;
                if (g.Members != null)
                    foreach (var mb in g.Members)
                        if (string.Equals(mb.Name, seg, StringComparison.OrdinalIgnoreCase)) { hit = mb; break; }
                if (hit == null || hit.Type == null) return WatchPathOutcome.Miss;

                uint va = (uint)((long)baseVa + hit.Offset);
                var t = hit.Type;
                if (t.Kind == TypeKind.Array) { error = PathUnsupported; return WatchPathOutcome.Unsupported; }
                if (i == members.Count - 1)
                {
                    leafVa = va; leafType = t;
                    return WatchPathOutcome.Ok;
                }
                if (t.Kind == TypeKind.Group) { g = t; baseVa = va; continue; }
                if (t.Kind == TypeKind.Reference || t.Tag == 0x16 || t.Tag == 0x26 || t.Tag == 0x29)
                {
                    error = PathUnsupported; return WatchPathOutcome.Unsupported;
                }
                return WatchPathOutcome.Miss;   // a scalar member has no members of its own
            }
            return WatchPathOutcome.Miss;
        }

        /// <summary>A class instance starts with its VMT pointer, so its first data member sits at +4; a
        /// GROUP or QUEUE record starts at +0. The TSWD type record carries no class flag: WINRESIZE (a
        /// WindowResizeClass reference) and QUEUE:BROWSE:1 both decode as a 0x16 reference to a 0x08 group
        /// (measured on clbrws.exe BrowseJobs, 2026-09-23: WINRESIZE's members begin at +4, the queue's at
        /// +0). A heuristic, so it errs one way: a layout with no member at +0 is refused.</summary>
        internal static bool LooksLikeClassLayout(ClarionType g)
        {
            if (g == null || g.Members == null) return true;
            foreach (var mb in g.Members)
                if (mb.Offset == 0) return false;
            return true;
        }

        /// <summary>What <see cref="TryWatchPath"/> left for its caller.</summary>
        private enum PathResolve
        {
            /// <summary>The head is neither a current-frame local nor a global: the caller's ordinary miss
            /// decides "(out of scope)" by the head's name.</summary>
            NoHead,
            /// <summary>A reply was emitted here (a local-headed value, a miss or an error).</summary>
            Answered,
            /// <summary>A global-headed member: its template address and type are in the out parameters, for
            /// the caller's shared THREADed classification.</summary>
            GlobalMember,
        }

        /// <summary>watch HEAD.MEMBER[.MEMBER]: resolve the head as a current-frame local, then as a global
        /// data symbol, and walk to the leaf (see <see cref="WalkWatchPath"/>). A local-headed leaf is
        /// answered here: a local lives on the stack, and a reference head's buffer on the heap, never in
        /// .cwtls. A global-headed leaf goes back to HandleWatchCommand, so the span classification and the
        /// instance mapping stay the one copy every global goes through.</summary>
        private PathResolve TryWatchPath(string name, uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx, IntPtr hThread,
                                         out LoadedModule owner, out uint templateVa, out byte code, out byte target,
                                         out uint size, out int places, out uint spanSize)
        {
            owner = null; templateVa = 0; code = 0; target = 0; size = 0; places = 0; spanSize = 0;
            if (name.IndexOf('.') < 0) return PathResolve.NoHead;   // a plain name is not a path
            string[] parts = name.Split('.');
            string head = parts[0];
            if (head.Length == 0) return PathResolve.NoHead;
            var members = new List<string>(parts.Length - 1);
            for (int i = 1; i < parts.Length; i++) members.Add(parts[i]);
            Func<uint, uint?> readPointer = va =>
            {
                var b = new byte[4];
                return ReadBlock(va, b) == 4 ? BitConverter.ToUInt32(b, 0) : (uint?)null;
            };

            uint leafVa; ClarionType leafType; string error;
            WatchPathOutcome outcome;

            uint slotVa; LocalSym lsym; LoadedModule lowner;
            if (TryResolveLocalInCurrentFrame(ref ctx, haveCtx, hThread, head, out slotVa, out lsym, out lowner))
            {
                outcome = WalkWatchPath(lsym.Type, lsym.TypeCode, true, slotVa, members, readPointer,
                                        out leafVa, out leafType, out error);
                if (outcome != WatchPathOutcome.Ok) { EmitPathFailure(tid, name, outcome, error); return PathResolve.Answered; }
                CodeForType(leafType, out code, out target, out size, out places);
                EmitWatchValue(tid, name, leafVa, leafVa, false, code, size, target, places);
                return PathResolve.Answered;
            }

            DataSymbol ds = null;
            if (_exe != null && _exe.Dbg != null && _exe.Dbg.TryGetDataSymbol(head, out ds)) owner = _exe;
            else
                foreach (var m in _modules)
                    if (m != _exe && m.Dbg != null && m.Dbg.TryGetDataSymbol(head, out ds)) { owner = m; break; }
            if (owner == null) return PathResolve.NoHead;

            outcome = WalkWatchPath(ds.Type, ds.TypeCode, false, owner.LoadBase + ds.Rva, members, readPointer,
                                    out leafVa, out leafType, out error);
            if (outcome != WatchPathOutcome.Ok) { EmitPathFailure(tid, name, outcome, error); return PathResolve.Answered; }
            CodeForType(leafType, out code, out target, out size, out places);
            templateVa = leafVa;
            spanSize = leafType.Size != 0 ? leafType.Size : size;
            return PathResolve.GlobalMember;
        }

        private void EmitPathFailure(uint tid, string name, WatchPathOutcome outcome, string error)
        {
            if (outcome == WatchPathOutcome.Miss)
            {
                EmitThreadEvent(tid, Json.WatchMiss(name, false));
                Console.WriteLine($"  watch {name}: not found");
            }
            else EmitWatchError(tid, name, error);
        }

        /// <summary>A watch that could not be read. Emitted against the NAME so the host can resolve that row
        /// instead of leaving it pending — the failure the old EmitError path never delivered.</summary>
        private void EmitWatchError(uint tid, string name, string reason)
        {
            EmitThreadEvent(tid, Json.WatchError(name, reason));
            Console.WriteLine($"  watch {name}: {reason}");
        }

        /// <summary>Read and report a watch value (instanceVa = templateVa for non-threaded data). <paramref
        /// name="target"/>/<paramref name="places"/> carry a frame local's referent-type and DECIMAL scale so
        /// &amp;STRING locals deref correctly and DECIMAL locals render/edit at the right scale; both default to 0
        /// for global/static data (whose DataLocation does not carry them). <paramref name="note"/> annotates a
        /// value that is real but qualified (an unallocated thread instance), and <paramref name="editable"/>
        /// can veto the edit pencil for a value that must not be written back.</summary>
        private void EmitWatchValue(uint tid, string name, uint templateVa, uint instanceVa, bool threaded, byte typeCode, uint size,
                                    byte target = 0, int places = 0, string note = null, bool editable = true)
        {
            int len = (int)Math.Min(Math.Max(size, 1), 4096);
            var buf = new byte[len];
            int read;
            Native.ReadProcessMemory(_hProcess, Ptr(instanceVa), buf, len, out read);
            if (read < 0) read = 0;
            // unified rendering: same engine-side type label + value formatter the Locals panel uses
            string value = FormatValueAt(typeCode, target, size, places, instanceVa);
            bool isNullRef = typeCode == 0x16 && value == "(null)";
            string tn = ClarionTypeLabel(typeCode, target, size, places, isNullRef);
            EmitThreadEvent(tid, Json.Watch(name, true, templateVa, instanceVa, threaded, typeCode, tn, size, places, value, buf, read, editable && IsEditableCode(typeCode), note));
            Console.WriteLine($"  watch {name}: {(tn ?? $"type 0x{typeCode:X2}")} size {size} at 0x{instanceVa:X}{(threaded ? $" (threaded; template 0x{templateVa:X})" : "")}{(note != null ? " — " + note : "")}");
            for (int row = 0; row < read; row += 16)
            {
                int n = Math.Min(16, read - row);
                var hex = new System.Text.StringBuilder(48);
                var asc = new System.Text.StringBuilder(16);
                for (int i = 0; i < n; i++)
                {
                    byte v = buf[row + i];
                    hex.Append(v.ToString("X2")).Append(' ');
                    asc.Append(v >= 0x20 && v < 0x7F ? (char)v : '.');
                }
                Console.WriteLine($"    0x{instanceVa + (uint)row:X8}: {hex.ToString().PadRight(48)} {asc}");
            }
        }
    }
}
