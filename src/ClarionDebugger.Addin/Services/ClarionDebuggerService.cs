using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;

namespace ClarionDebugger.Services
{
    /// <summary>Debug session run-state (Phase 2 interactive engine).</summary>
    public enum DebugSessionState
    {
        Idle,       // no engine process
        Launching,  // engine started, target not yet loaded
        Running,    // target executing
        Paused      // target suspended at a breakpoint / step
    }

    /// <summary>A breakpoint hit reported by the ClarionDbg helper engine.</summary>
    public sealed class DebugHit
    {
        public bool Resolved;
        public string Module;
        public int Line;
        public string Rva;
        public string Va;
        public int Gap;
        public bool Exact;

        /// <summary>Full path to the source module, resolved via the active .red redirection (or null).</summary>
        public string ResolvedPath;
    }

    /// <summary>The target paused (breakpoint hit, step complete, or step-limit).</summary>
    public sealed class DebugPause
    {
        public string Reason;       // "breakpoint" | "step" | "step-limit"
        public bool Resolved;
        public string Module;
        public string Proc;         // demangled symbol containing the pause address (or null)
        public int Line;
        public string Rva;
        public string Va;
        public int Gap;
        public bool Exact;
        /// <summary>Runtime location for a pause in non-TSWD code (e.g. "ClaRUN.dll!Cla$PushLong+0x7"), or null.</summary>
        public string Sym;
        /// <summary>x86 registers as hex strings keyed by name (eax..eflags), or null.</summary>
        public Dictionary<string, string> Regs;
        /// <summary>Full path to the source module, resolved via the active .red redirection (or null).</summary>
        public string ResolvedPath;
    }

    /// <summary>An image (EXE or DLL) mapped into / out of the target (module-loaded / module-unloaded).</summary>
    public sealed class DebugModule
    {
        public string Name;        // image file name, lowercased (e.g. myapp.dll)
        public string Path;        // full disk path (null on unload / when unresolved)
        public string Base;        // load base as a hex string (e.g. 0x65D70000)
        public string Size;        // image size (PE SizeOfImage) as a hex string
        public bool HasDebug;      // TSWD present — engine can resolve lines/symbols in this image

        /// <summary>Resolved when at least one of this image's compilands maps to real source via the
        /// .red (Tier 1 = full source debugging vs Tier 2 = symbols/stack only). Set by the service.</summary>
        public bool HasSource;
    }

    /// <summary>One logical breakpoint as confirmed by the engine (bp-set / bp-list).</summary>
    public sealed class DebugBreakpoint
    {
        public string Module;
        public int RequestedLine;
        public int Line;            // line actually planted (snapped to nearest code record)
        public string Path;         // full .clw path from the IDE gutter bookmark (null if unknown)

        // ---- advanced breakpoint properties (conditional / hit count / tracepoint) ----
        public string Condition;    // expression; pause only when true (null/empty = unconditional)
        public string HitMode;      // null | "eq" (=N) | "gte" (>=N) | "mod" (every Nth)
        public int HitValue;        // N for the hit-count rule
        public string Trace;        // non-null ⇒ tracepoint: {var}-interpolated message logged on hit, never pauses
        public int HitCount;        // engine-reported hit count (display only; updated via bp-set)
    }

    /// <summary>One resolved call-stack frame (Phase 3 'stack' command). proc/module null = unknown.</summary>
    public sealed class DebugStackFrame
    {
        public int Frame;
        public string Proc;
        public string Kind;         // procedure | method | routine | other
        public string Module;
        public int Line;
        public string Rva;
        public string Va;           // frame instruction VA (for per-frame locals resolution)
        public string Ebp;          // frame base pointer (for reading the frame's locals); "0x0" = unknown
        public string ResolvedPath; // generated .clw path via the active .red (or null)
    }

    /// <summary>One decoded x86 instruction (EXPERIMENT: disassembly view).</summary>
    public sealed class DebugDisasmInstr
    {
        public string Va;        // instruction VA (hex)
        public string Bytes;     // raw bytes (hex)
        public string Text;      // formatted mnemonic + operands
        public bool Current;     // true = this is the current EIP
        public string Module;    // .clw it maps to (or null)
        public int Line;         // source line (0 = none)
        public string ResolvedPath; // generated .clw path via the active .red (or null)
        public string Target;    // SPIKE: name a `call` invokes (e.g. ClaRUN.dll!CLIP), or null
        public string Func;      // containing function for no-source/runtime code (e.g. clarun.dll!Cla$PushLong)
    }

    /// <summary>A watch-by-name result (Phase 3 'watch' command), value already rendered for display.</summary>
    public sealed class DebugWatch
    {
        public string Name;
        public bool Found;
        public bool Threaded;
        public string TypeName;     // GROUP/SHORT/BYTE/STRING or null (unproven code)
        public string Value;        // rendered display string (or null when not found)
        public string Va;           // live instance VA (hex)
        public string TypeCode;     // raw Clarion type code as hex (e.g. "0x11") — for edit-variable-value
        public int Size;            // byte width — for edit-variable-value
        public int Places;          // DECIMAL scale (watch reports 0; correct places only for frame locals)
        public bool OutOfScope;     // a known frame local, but execution is paused outside its procedure
    }

    /// <summary>One procedure/method definition for the Procedures list: demangled name + owning module
    /// (.clw basename) + definition line. From a static parse of the EXE (engine 'symbols' command).</summary>
    public sealed class DebugProcedure
    {
        public string Name;     // demangled, e.g. SELECTJOBS, INICLASS.UPDATE
        public string Module;   // owning .clw basename, e.g. clbrws011.clw
        public int Line;        // 1-based definition line
    }

    /// <summary>
    /// Non-invasive driver for the standalone x86 debug engine (ClarionDbg.exe). Launches it with
    /// --interactive --json, streams its @JSON events, raises typed events, and forwards commands
    /// (continue / step / breakpoints / memory reads) over the engine's stdin. Runs the engine in a
    /// separate process so a debugger fault can never destabilize the IDE.
    /// </summary>
    public sealed class ClarionDebuggerService
    {
        /// <summary>The service instance that currently owns (or last owned) a live engine session. Set by
        /// <see cref="StartSession(string,IEnumerable{DebugBreakpoint},IEnumerable{string})"/>, so an observer
        /// pad (the native disassembly view) can attach to the running session without the pad that started it
        /// needing to know it exists. Null until the first session starts.</summary>
        public static ClarionDebuggerService Active { get; private set; }

        /// <summary>Raised (on the caller of StartSession) when <see cref="Active"/> changes — lets an
        /// already-open observer pad rebind its event handlers to the new session's service instance.</summary>
        public static event Action ActiveChanged;

        private Process _proc;
        private string _targetDir; // target EXE's directory — anchors relative .red redirection paths
        private readonly object _stateLock = new object();
        private DebugSessionState _state = DebugSessionState.Idle;
        private readonly List<DebugBreakpoint> _breakpoints = new List<DebugBreakpoint>();

        // ---- events (raised on a threadpool thread — marshal to UI in handlers) ----
        public event Action<DebugSessionState> StateChanged;
        public event Action<DebugHit> HitReceived;
        public event Action<DebugPause> Paused;
        public event Action<string> Resumed;                       // resume mode: continue/step/stepover/stepout
        public event Action<DebugBreakpoint> BreakpointSet;
        public event Action<string, int> BreakpointRemoved;        // module, line
        public event Action<string, int, string> BreakpointError;  // module, line, error
        public event Action<string, int, string, int> Traced;      // tracepoint fired: module, line, interpolated message, hit count
        public event Action<List<DebugBreakpoint>> BreakpointListReceived;
        public event Action<uint, int, byte[]> MemoryReceived;     // addr, requested len, bytes
        public event Action<List<DebugStackFrame>> StackReceived;  // resolved call stack
        public event Action<string, string> ModuleDataReceived; // current module's module-scope data (module, raw items JSON)
        public event Action<string, string> ExpandedReceived;   // lazy reference expansion (reqId, raw items JSON)
        public event Action<string, string> FrameLocalsReceived; // one call-stack frame's locals (reqId, raw items JSON)
        public event Action<string, string, string> LibStateReceived; // per-thread Library State (reqId, error-or-null, raw items JSON)
        public event Action<string, List<DebugDisasmInstr>> DisasmReceived; // EXPERIMENT: disassembly listing (tag, instrs)
        public event Action<DebugWatch> WatchReceived;             // watch-by-name value
        public event Action<string, bool, string, string> VariableSet; // edit result: va, ok, re-read value, error
        public event Action<DebugModule> ModuleLoaded;             // image mapped (EXE or DLL)
        public event Action<DebugModule> ModuleUnloaded;           // image unmapped
        public event Action<string> EngineError;                   // engine-reported error event
        public event Action<string> LogReceived;
        public event Action<int> Exited;

        public bool IsRunning { get { return _proc != null && !_proc.HasExited; } }

        public DebugSessionState State
        {
            get { lock (_stateLock) return _state; }
        }

        /// <summary>EIP (hex) at the current pause, or null when running/idle. Lets a pad that opens
        /// mid-session (e.g. the Disassembly tab reopened while paused) fetch at the live location
        /// instead of waiting for the next step.</summary>
        public string CurrentVa { get; private set; }

        /// <summary>Combined address span of all loaded images [MemLo, MemHi) — the navigable code
        /// range for the disassembly view's coarse "all-memory" scrollbar. 0 until modules load.</summary>
        public uint MemLo { get; private set; }
        public uint MemHi { get; private set; }

        private void TrackModuleSpan(DebugModule m)
        {
            uint b = ParseHexU32(m.Base);
            if (b == 0) return;
            uint sz = ParseHexU32(m.Size);
            uint end = b + (sz != 0 ? sz : 0x100000u);
            if (MemLo == 0 || b < MemLo) MemLo = b;
            if (end > MemHi) MemHi = end;
        }

        /// <summary>Engine-confirmed breakpoints (snapshot).</summary>
        public DebugBreakpoint[] Breakpoints
        {
            get { lock (_breakpoints) return _breakpoints.ToArray(); }
        }

        /// <summary>Locate ClarionDbg.exe: next to this addin first, then a dev build fallback.</summary>
        public static string FindEngine()
        {
            try
            {
                string addinDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                string local = Path.Combine(addinDir, "ClarionDbg.exe");
                if (File.Exists(local)) return local;
            }
            catch { }

            string dev = @"H:\DevLaptop\Projects\ClarionDebugger\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe";
            return File.Exists(dev) ? dev : null;
        }

        // ------------------------------------------------------------------ session lifecycle

        /// <summary>
        /// Start an interactive debug session: launch <paramref name="targetExe"/> under the engine
        /// with zero or more module:line breakpoints. The engine pauses at each hit and waits for
        /// Continue/Step*/Quit. Breakpoints can be added/removed at any time via Add/RemoveBreakpoint.
        /// </summary>
        public void StartSession(string targetExe, IEnumerable<DebugBreakpoint> breakpoints)
        {
            StartSession(targetExe, breakpoints, null);
        }

        /// <summary>
        /// Start an interactive debug session, additionally pre-loading the solution's output DLLs so
        /// breakpoints set in DLL source bind before launch (multi-DLL apps). DLLs not listed here are
        /// still picked up automatically by the engine as they load.
        /// </summary>
        public void StartSession(string targetExe, IEnumerable<DebugBreakpoint> breakpoints, IEnumerable<string> solutionDlls)
        {
            // This pad now owns the live session; let observer pads (the disassembly view) rebind to it.
            if (!ReferenceEquals(Active, this)) { Active = this; ActiveChanged?.Invoke(); }
            MemLo = MemHi = 0;   // fresh module span for this session (drives the disasm coarse scrollbar)
            var args = new System.Text.StringBuilder();
            args.Append("break \"").Append(targetExe).Append("\" --interactive --json");
            if (breakpoints != null)
                foreach (var bp in breakpoints)
                {
                    if (!IsValidModuleName(bp.Module)) continue; // blocks argument smuggling via module text
                    // spec = module:line plus any advanced props (condition/hit count/tracepoint), base64'd
                    args.Append(" --bp ").Append(BuildBpSpec(bp));
                }
            if (solutionDlls != null)
                foreach (var dll in solutionDlls)
                {
                    // dll paths are project-model derived (repo-controlled), like targetExe; the engine
                    // validates existence. Quote for spaces; reject embedded quotes defensively.
                    if (string.IsNullOrEmpty(dll) || dll.IndexOf('"') >= 0) continue;
                    args.Append(" --solution-dll \"").Append(dll).Append('"');
                }
            Launch(targetExe, args.ToString(), true);
        }

        /// <summary>
        /// Legacy one-shot session (Phase 1e pad): single module:line breakpoint, no interactivity.
        /// </summary>
        public void Start(string targetExe, string module, int line, bool once)
        {
            string args = "break \"" + targetExe + "\" --line " + line + " --module " + module + " --json --timeout 60000";
            if (once) args += " --once";
            Launch(targetExe, args, false);
        }

        private void Launch(string targetExe, string args, bool interactive)
        {
            if (IsRunning) throw new InvalidOperationException("A debug session is already running.");

            string engine = FindEngine();
            if (engine == null) throw new FileNotFoundException("ClarionDbg.exe not found next to the addin or in the dev build output.");
            if (string.IsNullOrEmpty(targetExe) || !File.Exists(targetExe))
                throw new FileNotFoundException("Target executable not found: " + targetExe);

            lock (_breakpoints) _breakpoints.Clear();
            string newTargetDir = Path.GetDirectoryName(Path.GetFullPath(targetExe));
            if (!string.Equals(newTargetDir, _targetDir, StringComparison.OrdinalIgnoreCase))
                _redFallback = null; // different target → its local .red may differ; re-resolve lazily
            _targetDir = newTargetDir;

            var psi = new ProcessStartInfo(engine, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = interactive,
                WorkingDirectory = Path.GetDirectoryName(targetExe)
            };

            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _proc.OutputDataReceived += (s, e) => { if (e.Data != null) OnLine(e.Data); };
            _proc.ErrorDataReceived += (s, e) => { if (e.Data != null) LogReceived?.Invoke(e.Data); };
            _proc.Exited += (s, e) =>
            {
                int code = 0;
                try { code = _proc.ExitCode; } catch { }
                SetState(DebugSessionState.Idle);
                Exited?.Invoke(code);
            };

            SetState(DebugSessionState.Launching);
            _proc.Start();
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();
        }

        /// <summary>
        /// Authoritative teardown barrier. When this returns, the engine/target process is GONE and State is
        /// Idle — every code path (graceful quit, forced kill, or already-dead) guarantees both before return.
        /// Prefers a clean engine-side quit (which also kills the target); on timeout it Kills and confirms the
        /// process actually exited via WaitForExit (bounded so a wedged process can't hang the teardown thread
        /// forever). Always drives State=Idle synchronously at the end — the async _proc.Exited / "exited" path
        /// that also sets Idle is idempotent (SetState's `changed` guard), so the double-set is harmless.
        ///
        /// BLOCKS (WaitForExit) — must be called OFF the UI thread when a session is live. Current callers comply
        /// (CmdStop and Dispose's live path both dispatch via Task.Run; Dispose's already-idle path runs it
        /// synchronously but there is no live process to wait on, so it returns immediately).
        /// </summary>
        public void Stop()
        {
            try
            {
                if (IsRunning)
                {
                    // A successful pipe write does NOT prove the engine consumed 'quit', so verify exit and fall
                    // back to Kill. After Kill, WaitForExit confirms the OS has actually reaped the process
                    // (Kill only requests termination) before we declare teardown complete.
                    bool exited = SendCommand("quit") && _proc.WaitForExit(1500);
                    if (!exited && IsRunning)
                    {
                        try { _proc.Kill(); } catch { }
                        try { _proc.WaitForExit(3000); } catch { } // bounded — don't hang forever on a wedged process
                    }
                }
            }
            catch { }
            finally
            {
                // Authoritative: once Stop() returns, the session is over. Synchronous so a teardown driver
                // (Dispose -> NotifyStopped) sees Idle deterministically without waiting on the async Exited.
                SetState(DebugSessionState.Idle);
            }
        }

        // ------------------------------------------------------------------ execution control

        public bool Continue() { return SendCommand("continue"); }
        public bool StepInto() { return SendCommand("step"); }
        public bool StepOver() { return SendCommand("stepover"); }
        public bool StepOut() { return SendCommand("stepout"); }
        /// <summary>EXPERIMENT: step exactly one machine instruction (for the disassembly view).</summary>
        public bool StepInstr() { return SendCommand("stepi"); }      // one instruction, into calls
        public bool StepInstrOver() { return SendCommand("nexti"); }   // one instruction, over calls
        /// <summary>Break into a running target (inject a breakpoint and pause at its current location).</summary>
        public bool Pause() { return SendCommand("pause"); }

        /// <summary>Valid Clarion module file name (e.g. clbrws011.clw) — also blocks argument
        /// smuggling and command injection through the engine command line / stdin protocol.</summary>
        public static bool IsValidModuleName(string module)
        {
            return !string.IsNullOrEmpty(module)
                && Regex.IsMatch(module, @"^[A-Za-z0-9_.\-]+$")
                && !module.Contains("..");
        }

        /// <summary>Add a breakpoint (engine snaps to the nearest code-record line and replies bp-set).</summary>
        public bool AddBreakpoint(string module, int line)
        {
            return IsValidModuleName(module) && SendCommand("bp add " + module + ":" + line);
        }

        /// <summary>Remove a breakpoint by module:line (planted or requested line both match).</summary>
        public bool RemoveBreakpoint(string module, int line)
        {
            return IsValidModuleName(module) && SendCommand("bp del " + module + ":" + line);
        }

        /// <summary>Add or update a breakpoint together with its advanced properties (condition / hit count
        /// / tracepoint). Re-adding an existing module:line on the engine re-applies the properties, so this
        /// doubles as the "edit properties" path for a live session. The spec is base64-encoded for free-text
        /// fields, so it is a single space-free token safe for the line/space-split stdin protocol.</summary>
        public bool SetBreakpoint(DebugBreakpoint bp)
        {
            return bp != null && IsValidModuleName(bp.Module) && SendCommand("bp add " + BuildBpSpec(bp));
        }

        public bool RequestBreakpointList() { return SendCommand("bp list"); }

        /// <summary>Read target memory while paused; result arrives via MemoryReceived.</summary>
        public bool ReadMemory(uint address, int length)
        {
            return SendCommand("mem 0x" + address.ToString("X") + " " + length);
        }

        /// <summary>Request the resolved call stack (paused only); result arrives via StackReceived.</summary>
        public bool RequestStack() { return SendCommand("stack"); }

        /// <summary>EXPERIMENT: request the current module's module-scope data (paused only); via ModuleDataReceived.</summary>
        public bool RequestModuleData() { return SendCommand("moduledata"); }

        /// <summary>Request the paused thread's RTL "Library State" (ERROR/EVENT/FIELD/…) — the engine
        /// func-evals each ClaRUN getter on the paused thread. Result arrives via LibStateReceived keyed
        /// by <paramref name="reqId"/>. Paused only.</summary>
        public bool RequestLibState(int reqId) { return SendCommand("libstate " + reqId); }

        /// <summary>Lazily expand a reference node: ask the engine to deref <paramref name="addrHex"/> and render
        /// the referent type's members. Result arrives via ExpandedReceived keyed by <paramref name="reqId"/>.
        /// Args are validated to block command/arg injection over the space-split stdin protocol.</summary>
        public bool RequestExpand(int reqId, string module, uint typeRef, string addrHex)
        {
            if (!IsValidModuleName(module)) return false;
            if (string.IsNullOrEmpty(addrHex) || !Regex.IsMatch(addrHex, "^0x[0-9A-Fa-f]+$")) return false;
            return SendCommand("expand " + reqId + " " + module + " " + typeRef + " " + addrHex);
        }

        /// <summary>Request the locals of ONE call-stack frame (Call-Stack-driven Variables): the engine reads
        /// the frame's symbol locals at <paramref name="ebpHex"/>. Result arrives via FrameLocalsReceived keyed
        /// by <paramref name="reqId"/>. Args are validated to block injection over the space-split stdin protocol.</summary>
        public bool RequestFrameLocals(int reqId, string vaHex, string ebpHex)
        {
            if (string.IsNullOrEmpty(vaHex) || !Regex.IsMatch(vaHex, "^0x[0-9A-Fa-f]+$")) return false;
            if (string.IsNullOrEmpty(ebpHex) || !Regex.IsMatch(ebpHex, "^0x[0-9A-Fa-f]+$")) return false;
            return SendCommand("framelocals " + reqId + " " + vaHex + " " + ebpHex);
        }

        /// <summary>EXPERIMENT: request a disassembly listing at the current EIP (paused only);
        /// result arrives via DisasmReceived.</summary>
        public bool RequestDisasm() { return SendCommand("disasm"); }

        /// <summary>EXPERIMENT: request a disassembly window starting at a specific VA (hex like
        /// 0x441109). Used to keep a stable .asm view while instruction-stepping.</summary>
        public bool RequestDisasmAt(string vaHex, int count, string tag = null, int before = 0)
        {
            if (string.IsNullOrEmpty(vaHex) || !Regex.IsMatch(vaHex, "^0x[0-9A-Fa-f]+$")) return false;
            // 'before' needs a tag slot ahead of it in the command; default to "win" so positions line up.
            string t = string.IsNullOrEmpty(tag) ? (before > 0 ? "win" : "") : tag;
            string cmd = "disasm " + vaHex + " " + count + (string.IsNullOrEmpty(t) ? "" : " " + t);
            if (before > 0) cmd += " " + before;
            return SendCommand(cmd);
        }

        /// <summary>A valid Clarion data-symbol name for watch-by-name (blocks command/arg injection).
        /// Allows letters, digits, and the Clarion separators _ : $ . (e.g. JOB:JOB_DESC,
        /// BRW1::LastSortOrder, JOBS$JOB:RECORD). No spaces/newlines — the protocol is line/space-split.</summary>
        public static bool IsValidWatchName(string name)
        {
            return !string.IsNullOrEmpty(name) && name.Length <= 128
                && Regex.IsMatch(name, @"^[A-Za-z0-9_:$.]+$") && !name.Contains("..");
        }

        /// <summary>Watch a data symbol by name (global, file record buffer, or field). Resolves the
        /// current thread's live value (incl. THREADed); result arrives via WatchReceived.</summary>
        public bool Watch(string name) { return IsValidWatchName(name) && SendCommand("watch " + name); }

        /// <summary>Edit-variable-value: write <paramref name="value"/> into the live variable at
        /// <paramref name="vaHex"/> (interpreted per <paramref name="typeCodeHex"/>/<paramref name="size"/>/
        /// <paramref name="places"/>). Valid only while paused. The value is base64-encoded so any text (with
        /// spaces) survives the line/space-split stdin protocol; va and type code are validated as hex to block
        /// command injection. Result arrives via <see cref="VariableSet"/>.</summary>
        public bool SetVariable(string vaHex, string typeCodeHex, int size, int places, string value)
        {
            if (State != DebugSessionState.Paused) return false;
            if (string.IsNullOrEmpty(vaHex) || !Regex.IsMatch(vaHex, "^0x[0-9A-Fa-f]+$")) return false;
            if (string.IsNullOrEmpty(typeCodeHex) || !Regex.IsMatch(typeCodeHex, "^0x[0-9A-Fa-f]+$")) return false;
            if (size <= 0 || size > 4096) return false;
            string b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value ?? string.Empty));
            return SendCommand("setval " + vaHex + " " + typeCodeHex + " " + size + " " + places + " " + b64);
        }

        /// <summary>Send a raw command line to the engine's stdin. False if no session / stdin closed.
        /// Rejects embedded newlines — the protocol is line-oriented, so a \n would inject a second command.</summary>
        private readonly object _stdinLock = new object();   // serialize stdin writes — multiple pads now send

        public bool SendCommand(string command)
        {
            try
            {
                if (command == null || command.IndexOf('\n') >= 0 || command.IndexOf('\r') >= 0) return false;
                if (!IsRunning || !_proc.StartInfo.RedirectStandardInput) return false;
                // The disassembly pad and the WebView share one engine connection; without this lock two
                // threads' WriteLine calls could interleave characters and corrupt a command line.
                lock (_stdinLock)
                {
                    _proc.StandardInput.WriteLine(command);
                    _proc.StandardInput.Flush();
                }
                return true;
            }
            catch { return false; }
        }

        // ------------------------------------------------------------------ breakable lines (static query)

        /// <summary>
        /// Synchronously ask the engine for a module's breakable lines (lines that carry a code
        /// record — the only lines a breakpoint binds to exactly). Clarion's TSWD line table is
        /// sparse, so this lets the UI show which lines actually work. Empty array on any failure.
        /// </summary>
        public static int[] GetBreakableLines(string targetExe, string module)
        {
            return GetBreakableLines(targetExe, module, null);
        }

        /// <summary>
        /// As <see cref="GetBreakableLines(string,string)"/>, but a module owned by a solution DLL
        /// (not the EXE) is resolved by also searching <paramref name="solutionDlls"/> — the EXE's
        /// TSWD only carries its own compilands. Returns the first image that yields lines.
        /// </summary>
        public static int[] GetBreakableLines(string targetExe, string module, IEnumerable<string> solutionDlls)
        {
            if (string.IsNullOrEmpty(module) || !IsValidModuleName(module)) return new int[0];
            string engine = FindEngine();
            if (engine == null) return new int[0];

            // EXE first (the common case), then each solution DLL until one carries the compiland.
            var lines = LinesForImage(engine, targetExe, module);
            if (lines.Length > 0 || solutionDlls == null) return lines;
            foreach (var dll in solutionDlls)
            {
                lines = LinesForImage(engine, dll, module);
                if (lines.Length > 0) return lines;
            }
            return new int[0];
        }

        private static int[] LinesForImage(string engine, string imagePath, string module)
        {
            try
            {
                if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath)) return new int[0];
                string args = "lines \"" + imagePath + "\" --module " + module + " --json";
                var psi = new ProcessStartInfo(engine, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(imagePath)
                };
                using (var p = Process.Start(psi))
                {
                    string outp = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    return ParseLinesJson(outp);
                }
            }
            catch { return new int[0]; }
        }

        // Pull the integer array out of the engine's "@LINES {...,"lines":[...]}" output.
        private static int[] ParseLinesJson(string stdout)
        {
            if (string.IsNullOrEmpty(stdout)) return new int[0];
            int at = stdout.IndexOf("@LINES", StringComparison.Ordinal);
            if (at < 0) return new int[0];
            int lb = stdout.IndexOf('[', at);
            int rb = lb >= 0 ? stdout.IndexOf(']', lb) : -1;
            if (lb < 0 || rb < 0) return new int[0];
            string body = stdout.Substring(lb + 1, rb - lb - 1).Trim();
            if (body.Length == 0) return new int[0];
            var list = new List<int>();
            foreach (var s in body.Split(','))
            {
                int v;
                if (int.TryParse(s.Trim(), out v)) list.Add(v);
            }
            return list.ToArray();
        }

        // ------------------------------------------------------------------ event stream parsing

        private void OnLine(string line)
        {
            if (!line.StartsWith("@JSON ", StringComparison.Ordinal))
            {
                LogReceived?.Invoke(line);
                return;
            }

            string json = line.Substring(6);
            string evt = GetStr(json, "event");
            switch (evt)
            {
                case "loaded":
                    SetState(DebugSessionState.Running);
                    break;

                case "module-loaded":
                    var ml = new DebugModule
                    {
                        Name = GetStr(json, "name"),
                        Path = GetStr(json, "path"),
                        Base = GetStr(json, "base"),
                        Size = GetStr(json, "size"),
                        HasDebug = GetBool(json, "hasDebug")
                    };
                    TrackModuleSpan(ml);
                    ModuleLoaded?.Invoke(ml);
                    break;

                case "module-unloaded":
                    ModuleUnloaded?.Invoke(new DebugModule
                    {
                        Name = GetStr(json, "name"),
                        Base = GetStr(json, "base")
                    });
                    break;

                case "hit":
                    var hit = ParseHit(json);
                    if (hit != null)
                    {
                        hit.ResolvedPath = ResolveModulePath(hit.Module);
                        HitReceived?.Invoke(hit);
                    }
                    break;

                case "paused":
                    var pause = ParsePause(json);
                    if (pause != null)
                    {
                        pause.ResolvedPath = ResolveModulePath(pause.Module);
                        // a 'watch' pause is a transient func-eval round-trip — don't record its trap VA
                        if (!string.Equals(pause.Reason, "watch", StringComparison.OrdinalIgnoreCase))
                            CurrentVa = pause.Va;
                        SetState(DebugSessionState.Paused);
                        Paused?.Invoke(pause);
                    }
                    break;

                case "resumed":
                    CurrentVa = null;
                    SetState(DebugSessionState.Running);
                    Resumed?.Invoke(GetStr(json, "mode"));
                    break;

                case "bp-set":
                    var bp = ParseBpFields(json, GetStr(json, "module"));
                    lock (_breakpoints)
                    {
                        DebugBreakpoint known = null;
                        foreach (var b in _breakpoints)
                            if (b.Module == bp.Module && b.Line == bp.Line) { known = b; break; }
                        if (known == null) _breakpoints.Add(bp);
                        else CopyBpProps(bp, known);   // refresh props/hit count on a re-confirm (properties edit)
                    }
                    BreakpointSet?.Invoke(bp);
                    break;

                case "bp-del":
                    string delMod = GetStr(json, "module");
                    int delLine = GetInt(json, "line");
                    lock (_breakpoints)
                        _breakpoints.RemoveAll(b => b.Module == delMod && b.Line == delLine);
                    BreakpointRemoved?.Invoke(delMod, delLine);
                    break;

                case "bp-error":
                    BreakpointError?.Invoke(GetStr(json, "module"), GetInt(json, "line"), GetStr(json, "error"));
                    break;

                case "trace":   // tracepoint fired in the engine — surface in the console, target keeps running
                    Traced?.Invoke(GetStr(json, "module"), GetInt(json, "line"), GetStr(json, "message"), GetInt(json, "hitCount"));
                    break;

                case "bp-list":
                    var list = ParseBpList(json);
                    lock (_breakpoints)
                    {
                        _breakpoints.Clear();
                        _breakpoints.AddRange(list);
                    }
                    BreakpointListReceived?.Invoke(list);
                    break;

                case "mem":
                    uint addr = ParseHexU32(GetStr(json, "addr"));
                    int memLen = GetInt(json, "len");
                    byte[] bytes = ParseHexBytes(GetStr(json, "bytes"));
                    if (bytes != null) MemoryReceived?.Invoke(addr, memLen, bytes);
                    break;

                case "disasm":
                    var dlist = ParseDisasm(json);
                    // Resolve each instruction's .clw to a real path (once per distinct module) so the
                    // disasm view can pull the actual source line text, not just module:line.
                    var dpaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var di in dlist)
                    {
                        if (string.IsNullOrEmpty(di.Module)) continue;
                        string rp;
                        if (!dpaths.TryGetValue(di.Module, out rp)) { rp = ResolveModulePath(di.Module); dpaths[di.Module] = rp; }
                        di.ResolvedPath = rp;
                    }
                    DisasmReceived?.Invoke(GetStr(json, "tag"), dlist);
                    break;

                case "stack":
                    var frames = ParseStack(json);
                    foreach (var f in frames) f.ResolvedPath = ResolveModulePath(f.Module);
                    StackReceived?.Invoke(frames);
                    break;

                case "moduledata":
                    ModuleDataReceived?.Invoke(GetStr(json, "module"), ExtractArrayBalanced(json, "items"));
                    break;

                case "expanded":
                    ExpandedReceived?.Invoke(GetStr(json, "reqId"), ExtractArrayBalanced(json, "items"));
                    break;

                case "framelocals":
                    FrameLocalsReceived?.Invoke(GetStr(json, "reqId"), ExtractArrayBalanced(json, "items"));
                    break;

                case "libstate":
                    LibStateReceived?.Invoke(GetStr(json, "reqId"), GetStr(json, "error"), ExtractArrayBalanced(json, "items"));
                    break;

                case "watch":
                    var w = ParseWatch(json);
                    if (w != null) WatchReceived?.Invoke(w);
                    break;

                case "varset":   // edit-variable-value result
                    VariableSet?.Invoke(GetStr(json, "va"), GetBool(json, "ok"), GetStr(json, "value"), GetStr(json, "error"));
                    break;

                case "sym":
                    // 'sym' is a static lookup echo — log it; 'watch' carries the live value
                    LogReceived?.Invoke(line);
                    break;

                case "regs":
                    // standalone regs reply — surface as a log line for now (paused carries regs too)
                    LogReceived?.Invoke(line);
                    break;

                case "error":
                    EngineError?.Invoke(GetStr(json, "message"));
                    break;

                case "exited":
                    CurrentVa = null;
                    SetState(DebugSessionState.Idle);
                    break;

                default:
                    LogReceived?.Invoke(line);
                    break;
            }
        }

        private void SetState(DebugSessionState s)
        {
            bool changed;
            lock (_stateLock)
            {
                changed = _state != s;
                _state = s;
            }
            if (changed) StateChanged?.Invoke(s);
        }

        private RedFileService _redFallback;

        /// <summary>
        /// The effective .red service. RedFileService.Active is only populated when the chat
        /// assistant pane initializes — a session that only uses the debugger pad would otherwise
        /// have NO redirection loaded and every module→source resolution would fail. Self-load the
        /// effective .red for the target (local project .red supersedes the version-level one).
        /// </summary>
        private RedFileService GetRedService()
        {
            var red = RedFileService.Active;
            if (red != null) return red;
            if (_redFallback != null) return _redFallback;
            try
            {
                var info = ClarionVersionService.Detect();
                var cfg = info != null ? info.GetCurrentConfig() : null;
                if (cfg == null) return null;
                var svc = new RedFileService();
                if (svc.LoadForProject(_targetDir, cfg)) _redFallback = svc;
                return _redFallback;
            }
            catch { return null; }
        }

        private string ResolveModulePath(string module)
        {
            if (string.IsNullOrEmpty(module)) return null;
            // Module names come from the debuggee's TSWD debug info — UNTRUSTED when debugging a
            // hostile EXE. A name carrying path separators or ".." would traverse out of the .red
            // redirection dir (Path.Combine + GetFullPath normalize it) and open an arbitrary file.
            if (module != Path.GetFileName(module) || module.Contains("..")) return null;
            try
            {
                var red = GetRedService();
                if (red == null) return null;
                // Relative .red entries (".", "..\obj", …) are relative to the app, not the IDE's
                // CWD — anchor them to the target EXE's directory and search the same section list
                // the app-data reader uses (ClarionAppDataReader: ResolveFrom with baseDir).
                return red.ResolveFrom(module, _targetDir, "Debug32", "Release32", "Debug", "Release", "Common")
                    ?? red.ResolveFrom(module, _targetDir, "Common")
                    ?? (_targetDir != null && File.Exists(Path.Combine(_targetDir, module))
                        ? Path.Combine(_targetDir, module) : null); // generated source often sits next to the EXE
            }
            catch { return null; }
        }

        /// <summary>Public module→source-path resolver (via the active/effective .red) so the host can
        /// resolve clickable source links — Procedures list, call-stack frames — the same way stack-frame
        /// paths already resolve. Null when unresolved. Safe to call off the UI thread.</summary>
        public string ResolveSourcePath(string module) { return ResolveModulePath(module); }

        /// <summary>Prime the module→source resolver for a known target EXE BEFORE a session starts, so
        /// pre-run source links (the Procedures list) resolve via the target's .red instead of failing on
        /// a null _targetDir. Sets _targetDir (the anchor for relative .red paths) the same way Launch does,
        /// resetting the cached .red on a target change. No-op for a null/empty/missing path.</summary>
        public void PrimeTarget(string targetExe)
        {
            try
            {
                // NEVER repoint a live session's resolver: _targetDir and the cached .red belong to the
                // running target and drive its pause/stack/source resolution. Require BOTH an Idle state AND
                // the engine process truly gone — Stop() publishes Idle in its finally before Kill/WaitForExit
                // prove the child exited, so a refresh during a slow teardown could otherwise repoint the
                // resolver while the old session can still emit late events. Pre-run priming only when idle
                // (Launch sets _targetDir authoritatively at session start).
                if (State != DebugSessionState.Idle || IsRunning) return;
                if (string.IsNullOrEmpty(targetExe) || !File.Exists(targetExe)) return;
                string dir = Path.GetDirectoryName(Path.GetFullPath(targetExe));
                if (!string.Equals(dir, _targetDir, StringComparison.OrdinalIgnoreCase)) _redFallback = null;
                _targetDir = dir;
            }
            catch { }
        }

        // The event JSON has a fixed shape; extract fields directly rather than pulling in a JSON dep.
        private static DebugHit ParseHit(string json)
        {
            try
            {
                return new DebugHit
                {
                    Resolved = GetBool(json, "resolved"),
                    Module = GetStr(json, "module"),
                    Line = GetInt(json, "line"),
                    Rva = GetStr(json, "rva"),
                    Va = GetStr(json, "va"),
                    Gap = GetInt(json, "gap"),
                    Exact = GetBool(json, "exact"),
                };
            }
            catch { return null; }
        }

        private static DebugPause ParsePause(string json)
        {
            try
            {
                var p = new DebugPause
                {
                    Reason = GetStr(json, "reason"),
                    Resolved = GetBool(json, "resolved"),
                    Module = GetStr(json, "module"),
                    Proc = GetStr(json, "proc"),
                    Line = GetInt(json, "line"),
                    Rva = GetStr(json, "rva"),
                    Va = GetStr(json, "va"),
                    Gap = GetInt(json, "gap"),
                    Exact = GetBool(json, "exact"),
                    Sym = GetStr(json, "sym"),
                };
                // regs block: {"eax":"0x...",...} — flat unique keys, extract directly
                if (json.Contains("\"regs\":{"))
                {
                    p.Regs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var reg in new[] { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags" })
                    {
                        string v = GetStr(json, reg);
                        if (v != null) p.Regs[reg] = v;
                    }
                }
                return p;
            }
            catch { return null; }
        }

        private static List<DebugStackFrame> ParseStack(string json)
        {
            var list = new List<DebugStackFrame>();
            try
            {
                // each frame is a flat object inside "frames":[ ... ] — split on objects
                foreach (Match m in Regex.Matches(json, "\\{[^{}]*\\}"))
                {
                    string f = m.Value;
                    if (!f.Contains("\"frame\":")) continue;
                    list.Add(new DebugStackFrame
                    {
                        Frame = GetInt(f, "frame"),
                        Proc = GetStr(f, "proc"),
                        Kind = GetStr(f, "kind"),
                        Module = GetStr(f, "module"),
                        Line = GetInt(f, "line"),
                        Rva = GetStr(f, "rva"),
                        Va = GetStr(f, "va"),
                        Ebp = GetStr(f, "ebp"),
                    });
                }
            }
            catch { }
            return list;
        }

        /// <summary>Slice out one named JSON array's body honouring nested brackets and quoted strings — e.g.
        /// the rows of <c>methodItems</c> when those rows themselves contain <c>children:[...]</c> arrays.
        /// Returns the text between the array's outer [ and its matching ] (exclusive). Robust to '[' / ']' /
        /// '"' that appear inside string values (engine strings are escaped).</summary>
        private static string ExtractArrayBalanced(string json, string key)
        {
            if (string.IsNullOrEmpty(json)) return "";
            int i = json.IndexOf("\"" + key + "\":[", StringComparison.Ordinal);
            if (i < 0) return "";
            int open = i + key.Length + 3;       // index of the opening '['
            int depth = 0; bool inStr = false, esc = false;
            for (int p = open; p < json.Length; p++)
            {
                char c = json[p];
                if (inStr)
                {
                    if (esc) esc = false;
                    else if (c == '\\') esc = true;
                    else if (c == '"') inStr = false;
                    continue;
                }
                if (c == '"') inStr = true;
                else if (c == '[') depth++;
                else if (c == ']') { depth--; if (depth == 0) return json.Substring(open + 1, p - open - 1); }
            }
            return "";
        }

        private static List<DebugDisasmInstr> ParseDisasm(string json)
        {
            var list = new List<DebugDisasmInstr>();
            try
            {
                foreach (Match m in Regex.Matches(json, "\\{[^{}]*\\}"))
                {
                    string o = m.Value;
                    if (!o.Contains("\"va\":") || !o.Contains("\"text\":")) continue;
                    list.Add(new DebugDisasmInstr
                    {
                        Va = GetStr(o, "va"),
                        Bytes = GetStr(o, "bytes"),
                        Text = GetStr(o, "text"),
                        Current = GetBool(o, "current"),
                        Module = GetStr(o, "module"),
                        Line = GetInt(o, "line"),
                        Target = GetStr(o, "target"),
                        Func = GetStr(o, "func"),
                    });
                }
            }
            catch { }
            return list;
        }

        private static DebugWatch ParseWatch(string json)
        {
            try
            {
                var w = new DebugWatch { Name = GetStr(json, "name"), Found = GetBool(json, "found") };
                if (!w.Found) { w.OutOfScope = GetBool(json, "outOfScope"); return w; }
                w.Threaded = GetBool(json, "threaded");
                w.TypeName = GetStr(json, "typeName");
                w.Va = GetStr(json, "va");
                w.TypeCode = GetStr(json, "type");   // raw code as hex ("0x11") for edit-variable-value
                w.Size = GetInt(json, "size");
                w.Places = GetInt(json, "places");   // 0 when absent (watch doesn't carry DECIMAL scale)
                // Value is now formatted engine-side by the shared Clarion value renderer (same one the
                // Locals panel uses) and shipped ready-to-display — no separate client-side formatting.
                w.Value = GetStr(json, "value");
                return w;
            }
            catch { return null; }
        }

        /// <summary>Synchronously query the EXE's static data symbols (globals + file record buffers
        /// with fields) as the engine's @GLOBALS JSON, for populating the Variables tree. "" on failure.</summary>
        public static string GetGlobalsJson(string targetExe)
        {
            try
            {
                string engine = FindEngine();
                if (engine == null || string.IsNullOrEmpty(targetExe) || !File.Exists(targetExe)) return "";
                var psi = new ProcessStartInfo(engine, "globals \"" + targetExe + "\" --json")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(targetExe)
                };
                using (var p = Process.Start(psi))
                {
                    string outp = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    int at = outp.IndexOf("@GLOBALS ", StringComparison.Ordinal);
                    return at >= 0 ? outp.Substring(at + 9).Trim() : "";
                }
            }
            catch { return ""; }
        }

        /// <summary>Synchronously enumerate the EXE's procedures + methods (static parse via the engine's
        /// 'symbols' command), each with its owning module (.clw basename) and definition line. Used to
        /// populate the Procedures list before/while running. Routines, 'other', and entries with no
        /// resolvable source line are dropped. Empty list on failure. Sorted by name (case-insensitive).</summary>
        public static List<DebugProcedure> GetProcedures(string targetExe)
        {
            var list = new List<DebugProcedure>();
            try
            {
                string engine = FindEngine();
                if (engine == null || string.IsNullOrEmpty(targetExe) || !File.Exists(targetExe)) return list;
                var psi = new ProcessStartInfo(engine, "symbols \"" + targetExe + "\" --json")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(targetExe)
                };
                string outp;
                using (var p = Process.Start(psi))
                {
                    // Both pipes are read on workers so a hostile/corrupt EXE can neither deadlock nor
                    // exhaust memory: stderr is drained-and-DISCARDED through a fixed buffer (content unused),
                    // and stdout is read with a hard byte ceiling that kills the child on overflow.
                    // WaitForExit+Kill also bounds a wedged child that never closes its pipes.
                    var errTask = System.Threading.Tasks.Task.Run(() =>
                    {
                        try { var eb = new char[8192]; while (p.StandardError.Read(eb, 0, eb.Length) > 0) { } } catch { }
                    });
                    var sb = new System.Text.StringBuilder();
                    const int MaxChars = 16 * 1024 * 1024;   // 16M-char ceiling on the @SYMBOLS payload
                    var readTask = System.Threading.Tasks.Task.Run(() =>
                    {
                        try
                        {
                            var buf = new char[8192]; int rd;
                            while ((rd = p.StandardOutput.Read(buf, 0, buf.Length)) > 0)
                            {
                                sb.Append(buf, 0, rd);
                                if (sb.Length > MaxChars) { try { p.Kill(); } catch { } break; }
                            }
                        }
                        catch { }
                    });
                    if (!p.WaitForExit(10000)) { try { p.Kill(); } catch { } }
                    bool drained = false; try { drained = readTask.Wait(2000); } catch { }
                    try { errTask.Wait(500); } catch { }     // drained; content unused
                    // Read sb only once the worker has finished — never ToString() while it might still be
                    // Appending (StringBuilder isn't thread-safe). If it didn't drain in time, take nothing.
                    outp = drained ? sb.ToString() : "";
                }
                int at = outp.IndexOf("@SYMBOLS ", StringComparison.Ordinal);
                if (at < 0) return list;
                string json = outp.Substring(at + "@SYMBOLS ".Length);
                // Each symbol is a brace-delimited object with no nested braces, so a simple {...} match
                // yields one object at a time (and skips the array wrapper, which contains '['). Cap the
                // count to bound DOM/memory if a hostile or pathological EXE emits a huge symbol set.
                const int MaxProcedures = 20000;
                foreach (Match m in Regex.Matches(json, "\\{[^{}]*\\}"))
                {
                    if (list.Count >= MaxProcedures) break;
                    string obj = m.Value;
                    string kind = GetStr(obj, "kind");
                    if (kind != "procedure" && kind != "method") continue;
                    int line = GetInt(obj, "line");
                    if (line <= 0) continue;
                    list.Add(new DebugProcedure { Name = GetStr(obj, "name"), Module = GetStr(obj, "module"), Line = line });
                }
                list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
            }
            catch { }
            return list;
        }

        private static List<DebugBreakpoint> ParseBpList(string json)
        {
            var list = new List<DebugBreakpoint>();
            try
            {
                // Each bp object begins with {"module": — split on that boundary and parse fields per chunk.
                // (GetStr/GetInt match the first occurrence within a chunk; brace chars inside a trace value
                // like "count={count}" are harmless because the string regex stops at the closing quote.)
                int idx = json.IndexOf("\"bps\"", StringComparison.Ordinal);
                string arr = idx >= 0 ? json.Substring(idx) : json;
                foreach (var chunk in Regex.Split(arr, "(?=\\{\"module\":)"))
                {
                    if (chunk.IndexOf("\"module\":", StringComparison.Ordinal) < 0) continue;
                    string mod = GetStr(chunk, "module");
                    if (mod == null) continue;
                    list.Add(ParseBpFields(chunk, mod));
                }
            }
            catch { }
            return list;
        }

        /// <summary>Build a breakpoint (location + advanced properties) from a single bp-set / bp-list
        /// JSON object. Shared so bp-set and bp-list decode identically.</summary>
        private static DebugBreakpoint ParseBpFields(string json, string module)
        {
            return new DebugBreakpoint
            {
                Module = module,
                Line = GetInt(json, "line"),
                RequestedLine = GetInt(json, "requestedLine"),
                Condition = GetStr(json, "condition"),
                HitMode = GetStr(json, "hitMode"),
                HitValue = GetInt(json, "hitValue"),
                Trace = GetStr(json, "trace"),
                HitCount = GetInt(json, "hitCount")
            };
        }

        /// <summary>Copy the advanced properties + live hit count from a freshly parsed breakpoint onto an
        /// existing list entry (a re-confirmed bp-set is how a properties edit reaches the host).</summary>
        private static void CopyBpProps(DebugBreakpoint from, DebugBreakpoint to)
        {
            to.Condition = from.Condition;
            to.HitMode = from.HitMode;
            to.HitValue = from.HitValue;
            to.Trace = from.Trace;
            to.HitCount = from.HitCount;
        }

        /// <summary>Build one space-free engine breakpoint spec token from a breakpoint's location +
        /// properties: <c>module:line</c> optionally followed by <c>|c=&lt;b64&gt;|hm=eq|hv=5|t=&lt;b64&gt;</c>.
        /// Free-text fields are base64(UTF-8) so they survive the line/space-split CLI + stdin protocol.</summary>
        public static string BuildBpSpec(DebugBreakpoint bp)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append(bp.Module).Append(':').Append(bp.RequestedLine > 0 ? bp.RequestedLine : bp.Line);
            if (!string.IsNullOrEmpty(bp.Condition)) sb.Append("|c=").Append(B64(bp.Condition));
            if (bp.HitMode == "eq" || bp.HitMode == "gte" || bp.HitMode == "mod")
                sb.Append("|hm=").Append(bp.HitMode).Append("|hv=").Append(bp.HitValue);
            if (!string.IsNullOrEmpty(bp.Trace)) sb.Append("|t=").Append(B64(bp.Trace));
            return sb.ToString();
        }

        private static string B64(string s) { return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s ?? string.Empty)); }

        private static uint ParseHexU32(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            uint v;
            return uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v) ? v : 0;
        }

        private static byte[] ParseHexBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return null;
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = HexVal(hex[i * 2]), lo = HexVal(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return null;
                bytes[i] = (byte)((hi << 4) | lo);
            }
            return bytes;
        }

        private static int HexVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        private static string GetStr(string json, string key)
        {
            var m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
            return m.Success ? m.Groups[1].Value : null;
        }
        private static int GetInt(string json, string key)
        {
            var m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*(-?\\d+)");
            return m.Success ? int.Parse(m.Groups[1].Value) : 0;
        }
        private static bool GetBool(string json, string key)
        {
            var m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*(true|false)");
            return m.Success && m.Groups[1].Value == "true";
        }
    }
}
