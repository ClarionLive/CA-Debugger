using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------ Library State (per-thread RTL state)
        //
        // The legacy Clarion debugger's "Library State" window: per-thread RTL values (ERROR/EVENT/FIELD/…)
        // read by CALLING the matching ClaRUN.dll getter export (Cla$ERRORCODE, Cla$EVENT, …) ON the paused
        // thread — so each value is automatically that thread's. We resolve each export's address from the
        // runtime DLL's export table, then func-eval the whole batch: hijack the thread to call getter[0],
        // trap its return at the magic address, record EAX, call getter[1], … and when the batch drains,
        // restore the genuine pause state and emit one `libstate` event. Reuses the THR$GetInstance eval
        // machinery (EVAL_TRAP_VA + the saved-context restore), extended to a sequential queue.

        private enum LibKind { Num, UNum, Str }

        private sealed class LibGetter
        {
            public string Group;    // panel section: Error | Event | Other
            public string Name;     // display name (ERRORCODE)
            public string Export;   // ClaRUN export to call (Cla$ERRORCODE)
            public LibKind Kind;    // how to read the return: signed/unsigned EAX, or EAX as a char*
            public uint Va;         // resolved live VA (filled per-request)
        }

        // v1 getter set: Carl Barnes' Error + Event groups + the "suggest new" extras. Side-effect-free
        // getters only (LONGPATH clears the error code, CLIPBOARD locks the clipboard — both excluded).
        private static readonly LibGetter[] LibGetters =
        {
            new LibGetter{Group="Error", Name="ERRORCODE",     Export="Cla$ERRORCODE",     Kind=LibKind.Num},
            new LibGetter{Group="Error", Name="ERROR",         Export="Cla$StackErrstr",   Kind=LibKind.Str},
            new LibGetter{Group="Error", Name="ERRORFILE",     Export="Cla$ERRORFILE",     Kind=LibKind.Str},
            new LibGetter{Group="Error", Name="FILEERRORCODE", Export="Cla$FILEERRORCODE", Kind=LibKind.Str},
            new LibGetter{Group="Error", Name="FILEERROR",     Export="Cla$FILEERRORMSG",  Kind=LibKind.Str},

            new LibGetter{Group="Event", Name="EVENT",      Export="Cla$EVENT",      Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="ACCEPTED",   Export="Cla$ACCEPTED",   Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="FIELD",      Export="Cla$FIELD",      Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="FOCUS",      Export="Cla$FOCUS",      Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="FIRSTFIELD", Export="Cla$FIRSTFIELD", Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="LASTFIELD",  Export="Cla$LASTFIELD",  Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="KEYCODE",    Export="Cla$KEYCODE",    Kind=LibKind.Num},
            new LibGetter{Group="Event", Name="THREAD",     Export="Cla$THREAD",     Kind=LibKind.Num},

            new LibGetter{Group="Other", Name="RUNCODE",     Export="Cla$RUNCODE",     Kind=LibKind.Num},
            new LibGetter{Group="Other", Name="REJECTCODE",  Export="Cla$REJECTCODE",  Kind=LibKind.Num},
            new LibGetter{Group="Other", Name="SELECTED",    Export="Cla$SELECTED",    Kind=LibKind.Num},
            new LibGetter{Group="Other", Name="KEYCHAR",     Export="Cla$KEYCHAR",     Kind=LibKind.UNum},
            new LibGetter{Group="Other", Name="KEYSTATE",    Export="Cla$KEYSTATE",    Kind=LibKind.UNum},
            new LibGetter{Group="Other", Name="GETEXITCODE", Export="Cla$GETEXITCODE", Kind=LibKind.Num},
            new LibGetter{Group="Other", Name="TODAY",       Export="Cla$TODAY",       Kind=LibKind.Num},
            new LibGetter{Group="Other", Name="CLOCK",       Export="Cla$CLOCK",       Kind=LibKind.Num},
        };

        // active batch state (single eval runs at a time — the target is paused while we drive it)
        private bool _libstateActive;
        private string _libstateReqId;
        private int _libstateIdx;
        private List<LibGetter> _libstateBatch;
        private List<string> _libstateRows;

        /// <summary>The loaded ClaRUN runtime DLL — the image that exports the Cla$ getters. Null when the
        /// app is locally-linked (RTL baked into the EXE, no separate clarun.dll): Library State is then
        /// unavailable. Detected by export presence, not file name, so version/renames don't matter.</summary>
        private LoadedModule RuntimeModule()
        {
            foreach (var m in _modules)
                if (m != null && m.Pe != null && m.LoadBase != 0 && m.Pe.FindExportRva("Cla$EVENT") != 0)
                    return m;
            return null;
        }

        /// <summary>libstate reqId — read the paused thread's RTL "Library State" by func-evaling each ClaRUN
        /// getter on it. Returns true when it kicked the first call (caller must leave the pause loop so the
        /// target can run); false when it answered inline (no runtime DLL / no thread context).</summary>
        private bool HandleLibStateCommand(string[] parts, uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            string reqId = parts.Length > 1 ? parts[1] : "0";
            var rt = RuntimeModule();
            if (rt == null) { EmitLibStateError(reqId, "RTL not dynamically linked (no ClaRUN.dll) — Library State needs a DLL-runtime build"); return false; }
            if (!haveCtx)   { EmitLibStateError(reqId, "no thread context for func-eval"); return false; }

            // Only call getters when paused at a SAFE point: the thread must be in the user's own Clarion
            // code (a TSWD image that isn't the runtime), i.e. between RTL calls. If it's paused INSIDE the
            // runtime/OS (idle in the ACCEPT message pump, mid-syscall, …), hijacking it to call a getter
            // re-enters the RTL on a thread already inside it and/or clobbers a syscall frame — which raises
            // the RTL's internal exception and GPFs the app. Refuse cleanly instead.
            var em = ModuleAt(ctx.Eip);
            if (em == null || em.Dbg == null || em == rt)
            {
                EmitLibStateError(reqId, "can't read here — the thread is inside the runtime/OS, not your code. Pause at a source breakpoint in your own procedure to read Library State.");
                return false;
            }

            var batch = new List<LibGetter>();
            foreach (var g in LibGetters)
            {
                uint rva = rt.Pe.FindExportRva(g.Export);
                if (rva == 0) continue;   // this runtime doesn't export it — skip
                batch.Add(new LibGetter { Group = g.Group, Name = g.Name, Export = g.Export, Kind = g.Kind, Va = rt.LoadBase + rva });
            }
            if (batch.Count == 0) { EmitLibStateError(reqId, "no Library State getters resolved in " + rt.Name); return false; }

            _libstateBatch = batch; _libstateRows = new List<string>(); _libstateIdx = 0; _libstateReqId = reqId;

            // save the genuine paused state ONCE; every getter call starts from a fresh copy of it so a
            // call's stack/register churn never leaks into the next (or into the restored pause state).
            _evalSavedCtx = CloneContext(ref ctx);
            _evalHadRearm = _rearm.TryGetValue(tid, out _evalSavedRearm);
            if (_evalHadRearm) _rearm.Remove(tid);

            KickLibStateCall(hThread, batch[0].Va);
            _libstateActive = true; _evalActive = true; _evalTid = tid;
            return true;
        }

        /// <summary>Hijack the paused thread to call a zero-arg getter at <paramref name="fnVa"/>: on a fresh
        /// copy of the saved context (keeping the thread's real registers, so a getter that reads a
        /// thread-context register still resolves), push the magic trap as the return address, set EIP,
        /// clear the trap flag.</summary>
        private void KickLibStateCall(IntPtr hThread, uint fnVa)
        {
            var e = CloneContext(ref _evalSavedCtx);
            e.Esp = _evalSavedCtx.Esp - 4;
            WriteU32(e.Esp, EVAL_TRAP_VA);
            e.Eip = fnVa;
            e.EFlags &= ~TRAP_FLAG;
            Native.SetThreadContext(hThread, ref e);
        }

        /// <summary>A getter call returned cleanly (trap at the magic address): record EAX (numeric) or
        /// EAX deref'd as a CSTRING (string getters), then advance.</summary>
        private uint OnLibStateEvalComplete(uint tid)
        {
            IntPtr hThread = OpenThreadForContext(tid);
            var c = NewContext();
            bool ok = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref c);
            _libstateRows.Add(LibStateRow(_libstateBatch[_libstateIdx], ok ? c.Eax : 0));
            return AdvanceLibState(tid, hThread);
        }

        /// <summary>A getter call FAULTED (RTL internal exception or AV) — mark it unavailable, swallow the
        /// exception (the AdvanceLibState restore/kick keeps it off the app), and move to the next getter.
        /// Each getter is attempted from the clean saved context, so one fault doesn't lose the rest.</summary>
        private uint OnLibStateEvalFault(uint tid, uint exCode, uint exAddr)
        {
            var g = _libstateBatch[_libstateIdx];
            _libstateRows.Add("{\"group\":" + Json.Str(g.Group) + ",\"name\":" + Json.Str(g.Name)
                + ",\"value\":" + Json.Str("<unavailable>") + ",\"kind\":\"err\"}");
            if (!EmitJson) Console.WriteLine($"  libstate: {g.Name} ({g.Export}) faulted (code 0x{exCode:X} at 0x{exAddr:X}) — skipped");
            return AdvanceLibState(tid, OpenThreadForContext(tid));
        }

        /// <summary>Move to the next getter, or finish the batch: restore the genuine pause state, emit the
        /// `libstate` event, and re-enter the command loop. Each getter's call starts from a fresh copy of
        /// the saved context (KickLibStateCall), so this doubles as the post-fault recovery.</summary>
        private uint AdvanceLibState(uint tid, IntPtr hThread)
        {
            _libstateIdx++;
            if (_libstateIdx < _libstateBatch.Count)
            {
                KickLibStateCall(hThread, _libstateBatch[_libstateIdx].Va);
                if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
                return Native.DBG_CONTINUE;   // run the next getter
            }

            // batch complete — restore the real pause state, report, resume the command loop
            if (hThread != IntPtr.Zero) Native.SetThreadContext(hThread, ref _evalSavedCtx);
            if (_evalHadRearm) { _rearm[tid] = _evalSavedRearm; _evalHadRearm = false; }
            _libstateActive = false; _evalActive = false;
            EmitLibStateRows(_libstateReqId, _libstateRows);
            PausedWait(tid, hThread, ref _evalSavedCtx, true, "libstate", emitPaused: false);
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        /// <summary>One getter result as a JSON row. Numeric getters take EAX directly (signed/unsigned);
        /// string getters treat EAX as a char* and read the NUL-terminated text from the target.</summary>
        private string LibStateRow(LibGetter g, uint eax)
        {
            string value;
            if (g.Kind == LibKind.Str)   value = eax == 0 ? "" : ReadCStringAt(eax, 512);
            else if (g.Kind == LibKind.UNum) value = eax.ToString();
            else                         value = ((int)eax).ToString();
            return "{\"group\":" + Json.Str(g.Group) + ",\"name\":" + Json.Str(g.Name)
                 + ",\"value\":" + Json.Str(value) + ",\"kind\":" + Json.Str(g.Kind.ToString().ToLowerInvariant()) + "}";
        }

        /// <summary>Read a NUL-terminated ASCII string from the target at <paramref name="va"/> (capped).</summary>
        private string ReadCStringAt(uint va, int cap)
        {
            var buf = new byte[cap];
            int got = ReadBlock(va, buf);
            if (got <= 0) return "";
            int n = Array.IndexOf(buf, (byte)0, 0, got);
            if (n < 0) n = got;
            return Encoding.ASCII.GetString(buf, 0, n);
        }

        private void EmitLibStateRows(string reqId, List<string> rows)
        {
            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"libstate\",\"reqId\":" + Json.Str(reqId)
                    + ",\"items\":[" + string.Join(",", rows) + "]}");
            else
                foreach (var r in rows) Console.WriteLine("  " + r);
        }

        private void EmitLibStateError(string reqId, string error)
        {
            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"libstate\",\"reqId\":" + Json.Str(reqId)
                    + ",\"error\":" + Json.Str(error) + ",\"items\":[]}");
            else
                Console.WriteLine("  libstate: " + error);
        }
    }
}
