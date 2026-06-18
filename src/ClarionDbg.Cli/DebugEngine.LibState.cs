using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------ Library State (per-thread RTL state)
        //
        // The legacy Clarion debugger's "Library State" window: per-thread RTL values (ERROR/EVENT/FIELD/…).
        //
        // We read each value by EMULATING the matching ClaRUN.dll getter export (Cla$ERRORCODE, Cla$EVENT, …)
        // with a READ-ONLY x86 emulator (RtlEmulator) — we do NOT call the getter on the stopped thread.
        // Calling re-enters the RTL's per-thread machinery; when the thread is parked inside the ACCEPT/
        // TakeEvent loop (exactly when EVENT/FIELD/FOCUS are interesting) the RTL detects the re-entrancy and
        // raises its internal fatal 0x6BEF5E4C on the next resume, killing the debuggee. The emulator runs the
        // getter's real code but every debuggee access is a ReadProcessMemory, writes go to a copy-on-write
        // shadow (the target is never modified), and the imports that matter are intrinsics (TlsGetValue ->
        // TEB.TlsSlots, GetCurrentThreadId -> stopped tid, …). No hijack, no func-eval, no re-entrancy — safe
        // to read while parked ANYWHERE, including mid-TakeEvent. It's synchronous (just memory reads), so —
        // unlike the old getter-calling path — it answers inline without leaving the pause loop.

        private enum LibKind { Signed, Unsigned, Str, Date, Time }

        private sealed class LibGetter
        {
            public LibGetter(string group, string name, string export, LibKind kind)
            { Group = group; Name = name; Export = export; Kind = kind; }
            public readonly string Group;    // panel section: Error | Event | Other
            public readonly string Name;     // display name (ERRORCODE)
            public readonly string Export;   // ClaRUN export whose body we emulate (Cla$ERRORCODE)
            public readonly LibKind Kind;    // how to interpret the result
        }

        // The getter set. Deliberately excludes the side-effecting exports: Cla$LONGPATH/Cla$SHORTPATH clear
        // the error code, Cla$CLIPBOARD locks the clipboard. FILEERRORCODE returns a string here
        // (Cla$FILEERRORCODE) per the runtime's own ABI. TODAY/CLOCK don't read thread state, so they're
        // computed from the host clock (same machine as the debuggee) rather than emulated.
        private static readonly LibGetter[] LibGetters =
        {
            new LibGetter("Error", "ERRORCODE",     "Cla$ERRORCODE",     LibKind.Signed),
            new LibGetter("Error", "ERROR",         "Cla$StackErrstr",   LibKind.Str),
            new LibGetter("Error", "ERRORFILE",     "Cla$ERRORFILE",     LibKind.Str),
            new LibGetter("Error", "FILEERRORCODE", "Cla$FILEERRORCODE", LibKind.Str),
            new LibGetter("Error", "FILEERROR",     "Cla$FILEERRORMSG",  LibKind.Str),

            new LibGetter("Event", "EVENT",      "Cla$EVENT",      LibKind.Signed),
            new LibGetter("Event", "ACCEPTED",   "Cla$ACCEPTED",   LibKind.Signed),
            new LibGetter("Event", "FIELD",      "Cla$FIELD",      LibKind.Signed),
            new LibGetter("Event", "FOCUS",      "Cla$FOCUS",      LibKind.Signed),
            new LibGetter("Event", "FIRSTFIELD", "Cla$FIRSTFIELD", LibKind.Signed),
            new LibGetter("Event", "LASTFIELD",  "Cla$LASTFIELD",  LibKind.Signed),
            new LibGetter("Event", "KEYCODE",    "Cla$KEYCODE",    LibKind.Signed),
            new LibGetter("Event", "THREAD",     "Cla$THREAD",     LibKind.Signed),

            new LibGetter("Other", "RUNCODE",     "Cla$RUNCODE",     LibKind.Signed),
            new LibGetter("Other", "REJECTCODE",  "Cla$REJECTCODE",  LibKind.Signed),
            new LibGetter("Other", "SELECTED",    "Cla$SELECTED",    LibKind.Signed),
            new LibGetter("Other", "KEYCHAR",     "Cla$KEYCHAR",     LibKind.Unsigned),
            new LibGetter("Other", "KEYSTATE",    "Cla$KEYSTATE",    LibKind.Unsigned),
            new LibGetter("Other", "GETEXITCODE", "Cla$GETEXITCODE", LibKind.Signed),
            new LibGetter("Other", "TODAY",       "Cla$TODAY",       LibKind.Date),
            new LibGetter("Other", "CLOCK",       "Cla$CLOCK",       LibKind.Time),
        };

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

        /// <summary>libstate reqId — read the paused thread's RTL "Library State" by EMULATING each ClaRUN
        /// getter read-only (no hijack, no re-entrancy → safe at any stop, including inside TakeEvent). Answers
        /// inline; the caller stays in the pause loop.</summary>
        private void HandleLibStateCommand(string[] parts, uint tid, IntPtr hThread)
        {
            string reqId = parts.Length > 1 ? parts[1] : "0";
            var rt = RuntimeModule();
            if (rt == null) { EmitLibStateError(reqId, "RTL not dynamically linked (no ClaRUN.dll) — Library State needs a DLL-runtime build"); return; }
            if (_hProcess == IntPtr.Zero) { EmitLibStateError(reqId, "no running process"); return; }
            if (hThread == IntPtr.Zero)   { EmitLibStateError(reqId, "no thread handle for the paused thread"); return; }

            uint teb = GetTebBase(hThread);
            if (teb == 0) { EmitLibStateError(reqId, "could not resolve the thread's TEB"); return; }

            RtlEmulator emu;
            try { emu = BuildEmulator(rt, tid, teb); }
            catch (Exception ex) { EmitLibStateError(reqId, "could not build the RTL emulator: " + ex.Message); return; }

            var rows = new List<string>();
            foreach (var g in LibGetters)
            {
                string value; LibKind kind = g.Kind; bool ok = true;
                try
                {
                    if (g.Kind == LibKind.Date) value = ClarionDate(DateTime.Today);
                    else if (g.Kind == LibKind.Time) value = ClarionClock(DateTime.Now);
                    else
                    {
                        uint rva = rt.Pe.FindExportRva(g.Export);
                        if (rva == 0) { value = "<unavailable>"; ok = false; }   // this runtime doesn't export it
                        else if (g.Kind == LibKind.Str)
                        {
                            uint p = emu.Call(rt.LoadBase + rva);
                            value = emu.ReadCStringResult(p, 512);
                        }
                        else
                        {
                            uint v = emu.Call(rt.LoadBase + rva);
                            value = g.Kind == LibKind.Unsigned ? v.ToString() : ((int)v).ToString();
                            if (g.Name == "EVENT" && v != 0)
                            {
                                string nm = ClarionEvents.Name(v);
                                if (nm != null) value = value + "  (" + nm + ")";
                            }
                        }
                    }
                }
                catch (RtlEmulator.NotSupported)
                {
                    value = "<unavailable>"; ok = false;
                    if (!EmitJson) Console.WriteLine($"  libstate: {g.Name} ({g.Export}) not emulatable on this runtime — skipped");
                }
                rows.Add(LibStateRow(g.Group, g.Name, value, kind, ok));
            }

            EmitLibStateRows(reqId, rows);
        }

        /// <summary>Build the read-only emulator over the runtime DLL: debuggee reads via ReadBlock, TLS via
        /// the stopped thread's TEB, GetCurrentThreadId == the stopped tid, and the IAT name map so import
        /// thunks (TlsGetValue/…) resolve to intrinsics.</summary>
        private RtlEmulator BuildEmulator(LoadedModule rt, uint tid, uint teb)
        {
            // IAT slot VA -> bare import function name (BuildIatNameMap keys are slot RVAs, values "dll!func").
            var imports = new Dictionary<uint, string>();
            foreach (var kv in rt.Pe.BuildIatNameMap())
            {
                string fn = kv.Value;
                int bang = fn.IndexOf('!');
                imports[rt.LoadBase + kv.Key] = bang >= 0 ? fn.Substring(bang + 1) : fn;
            }
            return new RtlEmulator(
                readMem: (addr, n) => ReadBytesExact(addr, n),
                tlsGetValue: idx => ReadTlsSlot(teb, idx),
                curThreadId: tid,
                teb: teb,
                importAtSlot: slot => imports.TryGetValue(slot, out var nm) ? nm : null,
                isCode: va => ModuleAt(va) != null);
        }

        /// <summary>Read exactly <paramref name="n"/> bytes from the debuggee, or fewer at a guard page /
        /// unreadable boundary (the emulator throws NotSupported when short, surfacing as &lt;unavailable&gt;).</summary>
        private byte[] ReadBytesExact(uint va, int n)
        {
            var buf = new byte[n];
            int got = ReadBlock(va, buf);
            if (got == n) return buf;
            var t = new byte[got < 0 ? 0 : got];
            Array.Copy(buf, t, t.Length);
            return t;
        }

        /// <summary>The stopped thread's TEB base via NtQueryInformationThread(ThreadBasicInformation). 0 on
        /// failure. THREAD_BASIC_INFORMATION (32-bit): ExitStatus(+0), TebBaseAddress(+4), …</summary>
        private uint GetTebBase(IntPtr hThread)
        {
            var buf = new byte[28];
            int retLen;
            return Native.NtQueryInformationThread(hThread, 0, buf, buf.Length, out retLen) == 0
                ? BitConverter.ToUInt32(buf, 4) : 0;
        }

        /// <summary>Read a TLS slot from a 32-bit TEB: TlsSlots[64] @ 0xE10, TlsExpansionSlots ptr @ 0xF94.</summary>
        private uint ReadTlsSlot(uint teb, uint index)
        {
            if (index < 64) return ReadU32(teb + 0xE10 + index * 4);
            uint exp = ReadU32(teb + 0xF94);
            return exp == 0 ? 0 : ReadU32(exp + (index - 64) * 4);
        }

        // Clarion DATE = days since 1800-12-28; TIME = centiseconds-since-midnight + 1.
        private static string ClarionDate(DateTime d) =>
            ((int)(d.Date - new DateTime(1800, 12, 28)).TotalDays).ToString();
        private static string ClarionClock(DateTime t) =>
            ((int)(t.TimeOfDay.TotalMilliseconds / 10) + 1).ToString();

        /// <summary>One Library State result as a JSON row. The addin special-cases kind "str" (quotes the
        /// value); every numeric kind maps to "num", and a read that couldn't run maps to "err".</summary>
        private string LibStateRow(string group, string name, string value, LibKind kind, bool ok)
        {
            string k = !ok ? "err" : kind == LibKind.Str ? "str" : "num";
            return "{\"group\":" + Json.Str(group) + ",\"name\":" + Json.Str(name)
                 + ",\"value\":" + Json.Str(value) + ",\"kind\":" + Json.Str(k) + "}";
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
