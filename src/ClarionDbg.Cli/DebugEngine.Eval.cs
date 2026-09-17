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
        private enum ThreadedResolve
        {
            Ok,            // instanceVa is this thread's live instance
            Template,      // this thread has no instance of its own: the template itself is what it reads
            Unallocated,   // this thread has not touched the data yet; no instance exists to read
            Failed,        // could not resolve (no import, no TEB, emulator refusal, unreadable result)
        }

        // Per-thread, per-image .cwtls instance base, cached for the duration of one stop: every field of
        // every record in an image shares one instance block, so a whole table expanding costs one emulation
        // instead of one per row. Keyed by (tid, image load base); dropped when the thread exits and at each
        // new stop, so a reused tid can never inherit a dead thread's block.
        private readonly Dictionary<ulong, uint> _tlsBaseCache = new Dictionary<ulong, uint>();

        private static ulong TlsCacheKey(uint tid, uint loadBase) { return ((ulong)tid << 32) | loadBase; }

        private void ClearThreadedCache() { _tlsBaseCache.Clear(); }
        private void ClearThreadedCache(uint tid)
        {
            var dead = new List<ulong>();
            foreach (var k in _tlsBaseCache.Keys) if ((uint)(k >> 32) == tid) dead.Add(k);
            foreach (var k in dead) _tlsBaseCache.Remove(k);
        }

        /// <summary>Map a THREADed template VA to the paused thread's instance by emulating the owning image's
        /// imported THR$GetInstance read-only. No target code runs, so this is safe at any stop and answers
        /// inline. A run that writes debuggee memory is the runtime's allocate-on-first-touch path: the thread
        /// has no instance yet, and creating one would be a side effect, so that reports Unallocated rather
        /// than a made-up address.</summary>
        private ThreadedResolve TryResolveThreadedInstance(LoadedModule owner, uint templateVa, uint tid,
                                                           IntPtr hThread, out uint instanceVa, out string reason)
        {
            instanceVa = 0; reason = null;
            uint cwtlsBase = owner.LoadBase + owner.CwtlsLo;

            // one emulation per (thread, image) per stop — every field resolves off the cached block
            uint cached;
            if (_tlsBaseCache.TryGetValue(TlsCacheKey(tid, owner.LoadBase), out cached))
            {
                instanceVa = templateVa - cwtlsBase + cached;
                return ThreadedResolve.Ok;
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

            uint result;
            try
            {
                result = emu.Call(helper, templateVa, cwtlsBase);
            }
            catch (Exception ex)
            {
                // The allocate path writes before it fails us; that write is the tell-tale, whatever the
                // emulator choked on afterwards.
                if (emu.WroteDebuggeeMemory) { reason = "not yet allocated on this thread"; return ThreadedResolve.Unallocated; }
                reason = ex is RtlEmulator.NotSupported
                    ? "THR$GetInstance is not emulatable on this runtime (" + ex.Message + ")"
                    : "THR$GetInstance emulation failed — " + ex.GetType().Name + ": " + ex.Message;
                return ThreadedResolve.Failed;
            }

            if (emu.WroteDebuggeeMemory) { reason = "not yet allocated on this thread"; return ThreadedResolve.Unallocated; }
            if (result == 0) { reason = "THR$GetInstance returned no instance"; return ThreadedResolve.Failed; }

            // A thread that is not a Clarion thread (or an image whose data isn't really threaded) legitimately
            // gets the TEMPLATE back — that IS what code on that thread reads, so the value is real and worth
            // showing. But it is shared, not this thread's own: writing it would change what every future
            // thread starts from, the same reason the Unallocated branch refuses to write. So it gets its own
            // outcome rather than passing for an instance, and it is never cached — the cache maps a whole
            // image's block for a thread that HAS one.
            if (result == templateVa)
            {
                instanceVa = templateVa;
                reason = "no thread instance — shared template value";
                return ThreadedResolve.Template;
            }

            var probe = new byte[1];
            if (ReadBlock(result, probe) < 1)
            {
                reason = $"THR$GetInstance returned an unreadable instance (0x{result:X})";
                return ThreadedResolve.Failed;
            }
            _tlsBaseCache[TlsCacheKey(tid, owner.LoadBase)] = result - (templateVa - cwtlsBase);

            instanceVa = result;
            return ThreadedResolve.Ok;
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
            if (TryResolveLocalInCurrentFrame(ref ctx, haveCtx, name, out slotVa, out lsym, out lowner))
            {
                EmitWatchValue(name, slotVa, slotVa, false, lsym.TypeCode, lsym.Size, lsym.Target, lsym.Places);
                return;
            }

            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            if (!ResolveDataAcrossModules(name, out owner, out loc))
            {
                // Not a current-frame local and not a global. If it IS a local of some other procedure, it is
                // merely out of scope right now (we are paused elsewhere) — flag that so the Watch row reads
                // "(out of scope)" rather than the misleading "(not found)" used for genuinely unknown names.
                bool outOfScope = haveCtx && IsKnownLocalName(name);
                if (EmitJson) Console.WriteLine("@JSON " + Json.WatchMiss(name, outOfScope));
                Console.WriteLine($"  watch {name}: {(outOfScope ? "out of scope" : "not found")}");
                return;
            }
            uint templateVa = owner.LoadBase + loc.Rva;
            bool threaded = loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi && owner.CwtlsHi != 0;

            if (!threaded)
            {
                EmitWatchValue(name, templateVa, templateVa, false, loc.TypeCode, loc.Size);
                return;
            }

            uint instanceVa; string reason;
            switch (TryResolveThreadedInstance(owner, templateVa, tid, hThread, out instanceVa, out reason))
            {
                case ThreadedResolve.Ok:
                    EmitWatchValue(name, templateVa, instanceVa, true, loc.TypeCode, loc.Size);
                    break;

                case ThreadedResolve.Unallocated:
                    // The thread has never touched this data, so there is no instance to read. Its first touch
                    // will start from the template's initial value, so show that — read-only, since writing the
                    // template would change what EVERY future thread starts from.
                    EmitWatchValue(name, templateVa, templateVa, true, loc.TypeCode, loc.Size,
                                   note: "not yet used on this thread — initial value", editable: false);
                    break;

                case ThreadedResolve.Template:
                    // Not a Clarion thread (e.g. a pause that landed on a worker or the injected break thread):
                    // the template IS what code here reads, so show it — but it is shared data, not this
                    // thread's own, and writing it would change what every future thread starts from.
                    EmitWatchValue(name, templateVa, templateVa, true, loc.TypeCode, loc.Size,
                                   note: reason, editable: false);
                    break;

                default:
                    EmitWatchError(name, reason);
                    break;
            }
        }

        /// <summary>A watch that could not be read. Emitted against the NAME so the host can resolve that row
        /// instead of leaving it pending — the failure the old EmitError path never delivered.</summary>
        private void EmitWatchError(string name, string reason)
        {
            if (EmitJson) Console.WriteLine("@JSON " + Json.WatchError(name, reason));
            Console.WriteLine($"  watch {name}: {reason}");
        }

        /// <summary>Read and report a watch value (instanceVa = templateVa for non-threaded data). <paramref
        /// name="target"/>/<paramref name="places"/> carry a frame local's referent-type and DECIMAL scale so
        /// &amp;STRING locals deref correctly and DECIMAL locals render/edit at the right scale; both default to 0
        /// for global/static data (whose DataLocation does not carry them). <paramref name="note"/> annotates a
        /// value that is real but qualified (an unallocated thread instance), and <paramref name="editable"/>
        /// can veto the edit pencil for a value that must not be written back.</summary>
        private void EmitWatchValue(string name, uint templateVa, uint instanceVa, bool threaded, byte typeCode, uint size,
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
            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Watch(name, true, templateVa, instanceVa, threaded, typeCode, tn, size, places, value, buf, read, editable && IsEditableCode(typeCode), note));
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
