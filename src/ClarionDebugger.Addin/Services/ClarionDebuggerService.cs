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
        /// <summary>The thread the engine stopped on, or null from an engine that doesn't name it. Lets the
        /// pad mark the stopped thread from the stop itself, rather than only from the 'threads' reply that
        /// follows it — which can fail or be overtaken.</summary>
        public uint? Tid;
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

        private int? _requestedLine;

        /// <summary>The line the user asked for, or null when the engine's echo carried no
        /// <c>requestedLine</c> member AT ALL (a build older than that protocol change).
        /// <para>
        /// ABSENT IS NOT 0. 0 is a real requested line — an unresolved raw (--rva) breakpoint has one —
        /// which is exactly why <c>bp-del</c> has always read this field with <c>GetIntOrNull</c>. Reading it
        /// with <c>GetInt</c> gave every breakpoint in a module the same requested line of 0 against an older
        /// engine, and <see cref="ClarionDebuggerService.SameBpIdentity"/> then merged them all into one pane
        /// row. Host-built entries (the IDE gutter, a pending entry the pad adds before the engine confirms)
        /// always know the line they asked for, so only a parsed echo can leave this null.
        /// </para></summary>
        public int? RequestedLineOrNull
        {
            get { return _requestedLine; }
            set { _requestedLine = value; }
        }

        /// <summary>The requested line when there is one, else the PLANTED line — the best line this
        /// breakpoint can be shown or re-specified by. Every display, gutter and spec-building reader wants
        /// this; nothing may use it for IDENTITY, which goes through
        /// <see cref="ClarionDebuggerService.SameBpIdentity"/> so an absent requested line falls back
        /// explicitly instead of comparing as 0. Assigning it records the line AS PRESENT, which is what a
        /// host-built entry means.</summary>
        public int RequestedLine
        {
            get { return _requestedLine ?? Line; }
            set { _requestedLine = value; }
        }

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
        public bool Uncertain;      // recovered by the raw-stack-scan fallback, not the EBP chain — may be stale
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

    /// <summary>One thread of the paused target, as the engine's 'threads' command reports it.
    /// <para>
    /// <see cref="Proc"/>/<see cref="Module"/>/<see cref="Line"/> describe the TOPMOST CLARION FRAME on the
    /// thread's stack, not its raw EIP: with the app idle, every UI thread sits in win32u!NtUserGetMessage,
    /// so an EIP-derived label would name the same syscall for all of them and the list would be unreadable.
    /// </para></summary>
    public sealed class DebugThread
    {
        /// <summary>The Win32 thread id — a DWORD, so it is carried unsigned all the way to the page.</summary>
        public uint Tid;
        /// <summary>The Clarion thread number when the RTL can give it, else null. Never invented.</summary>
        public int? ClarionThread;
        public string Proc;            // topmost Clarion procedure, or null
        public string Module;          // that frame's .clw, or null
        public int Line;
        /// <summary>"clarion" (EIP in mapped Clarion code) | "rtl" | "syscall" | "unknown".</summary>
        public string State;
        public int ClarionFrames;      // how many Clarion frames the stack walk found
        public bool Stopped;           // this is the thread the engine stopped on
        public bool Selected;          // this is the thread the read paths currently target
    }

    /// <summary>The engine's thread inventory for the current stop: which thread it stopped on, which one
    /// the read paths are currently pointed at, and the list itself (stopped thread first).</summary>
    public sealed class DebugThreadList
    {
        public uint StoppedTid;
        public uint SelectedTid;
        public List<DebugThread> Threads = new List<DebugThread>();
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
        public string Error;        // resolved by name but unreadable (e.g. a THREADed instance the RTL wouldn't yield)
        public string Note;         // a real but qualified value (e.g. a THREADed variable this thread hasn't used yet)
        /// <summary>The thread this value was read on, or null from an engine that doesn't stamp replies.
        /// The pad drops a reply whose Tid isn't the thread it is currently showing.</summary>
        public uint? Tid;
    }

    /// <summary>One procedure/method definition for the Procedures list: demangled name + owning module
    /// (.clw basename) + definition line. From a static parse of the EXE (engine 'symbols' command).</summary>
    public sealed class DebugProcedure
    {
        public string Name;     // demangled, e.g. SELECTJOBS, INICLASS.UPDATE
        public string Module;   // owning .clw basename, e.g. clbrws011.clw
        public int Line;        // 1-based definition line
        /// <summary>"procedure", "method" or "routine". ROUTINEs are carried so a breakpoint can name the
        /// ROUTINE it sits in and the procedure that encloses it; the Procedures PANEL filters them back out
        /// (a routine is not independently navigable the way a procedure is).</summary>
        public string Kind;
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
        public event Action<string, int> BreakpointRemoved;        // module, requested line (planted line
                                                                  // only from a pre-requestedLine engine)
        public event Action<string, int, string> BreakpointError;  // module, line, error
        public event Action<string, int, string, int> Traced;      // tracepoint fired: module, line, interpolated message, hit count
        public event Action<List<DebugBreakpoint>> BreakpointListReceived;
        // Thread-scoped replies carry the tid they were read on (null from an engine that predates the
        // per-event stamp). The pad uses it to DROP a reply for a thread it is no longer showing: a thread
        // switch leaves the previous thread's replies in flight, and painting one into the new thread's
        // panels would show one thread's values under another thread's name.
        public event Action<List<DebugStackFrame>, uint?> StackReceived;  // resolved call stack (frames, tid)
        public event Action<string, string, uint?> ModuleDataReceived; // current module's module-scope data (module, raw items JSON, tid)
        public event Action<string, string> ExpandedReceived;   // lazy reference expansion (reqId, raw items JSON)
        public event Action<string, string, uint?> FrameLocalsReceived; // one call-stack frame's locals (reqId, raw items JSON, tid)
        public event Action<string, string, string, uint?> LibStateReceived; // per-thread Library State (reqId, error-or-null, raw items JSON, tid)
        public event Action<Dictionary<string, string>, uint?> RegsReceived; // standalone regs reply (regs, tid)
        public event Action<DebugThreadList> ThreadsReceived;      // thread inventory for the current stop
        // 'thread <tid>' result. The tid is the thread that was ASKED FOR (null when the request was
        // malformed and named none); on ok:false the engine's selection is UNCHANGED, so a consumer keeps
        // the selection it had and asks 'threads' for the authoritative one.
        public event Action<uint?, bool, string> ThreadSelected;
        // Disassembly listing (tag, instrs, tid). The tid is the thread the engine actually DECODED, and it
        // was the one thread-scoped reply whose invoke dropped it while the decoder below already parsed it
        // — so the view could only ever gate on its own bookkeeping, never on the engine's own answer.
        public event Action<string, List<DebugDisasmInstr>, uint?> DisasmReceived;
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

        /// <summary>True when the engine process is CONFIRMED gone — no process at all, or the OS says this
        /// one has exited. A HasExited that throws answers FALSE: "cannot tell" must never be reported as
        /// "dead", which is the whole point of the postcondition below.</summary>
        private bool ProcessConfirmedDead()
        {
            var p = _proc;
            if (p == null) return true;
            try { return p.HasExited; }
            catch (Exception ex)
            {
                LogReceived?.Invoke("[stop] cannot confirm engine exit: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Teardown barrier. Prefers a clean engine-side quit (which also kills the target); on timeout it Kills
        /// and waits. It then ASKS whether the process is dead rather than assuming the above worked, and
        /// returns that answer: true means <see cref="IsRunning"/> is confirmed false and State is Idle.
        ///
        /// A false return means the engine process could NOT be confirmed dead inside the bounded waits. On that
        /// path State is deliberately NOT driven to Idle: publishing Idle over a live process is what would
        /// re-enable Start (the toolbar and pad both reach Idle through DebugSessionController, which reads this
        /// state via IDebugSessionTarget.IsSessionIdle) and let a new session launch against a target still owned
        /// by the old process. _proc.Exited stays subscribed and drives Idle if and when the process does die.
        /// Callers that need the guarantee must check the result; callers that ignore it are no worse off than
        /// before, because the state they would have seen as Idle now simply stays where it was.
        ///
        /// Known remaining path that reports Idle without a process check: the engine's "exited" event (the
        /// DEBUGGEE finished), handled in OnJson, sets Idle while the engine process itself may still be alive
        /// for a short window. That is a separate lifecycle from this one and is not addressed here.
        ///
        /// BLOCKS (WaitForExit) — must be called OFF the UI thread when a session is live. Current callers comply
        /// (CmdStop and Dispose's live path both dispatch via Task.Run; Dispose's already-idle path runs it
        /// synchronously but there is no live process to wait on, so it returns immediately).
        /// </summary>
        public bool Stop()
        {
            try
            {
                if (IsRunning)
                {
                    // A successful pipe write does NOT prove the engine consumed 'quit', so verify exit and fall
                    // back to Kill. After Kill, WaitForExit confirms the OS has actually reaped the process
                    // (Kill only requests termination).
                    bool exited = SendCommand("quit") && _proc.WaitForExit(1500);
                    if (!exited && IsRunning)
                    {
                        // Escalate deliberately: wait -> kill -> verify. A Kill that throws is information the
                        // caller needs (the handle may be denied, or the process already reaped), so it is
                        // surfaced instead of swallowed. Neither failure decides the outcome on its own — the
                        // check below does.
                        try { _proc.Kill(); }
                        catch (Exception ex) { LogReceived?.Invoke("[stop] kill failed: " + ex.Message); }
                        try { _proc.WaitForExit(3000); }   // bounded — don't hang forever on a wedged process
                        catch (Exception ex) { LogReceived?.Invoke("[stop] wait after kill failed: " + ex.Message); }
                    }
                }
            }
            catch (Exception ex) { LogReceived?.Invoke("[stop] teardown error: " + ex.Message); }

            // The postcondition, asked as a question. Nothing above is trusted to have worked: this single check
            // is what decides whether the session may be reported over.
            bool dead = ProcessConfirmedDead();
            if (dead) SetState(DebugSessionState.Idle);
            else LogReceived?.Invoke("[stop] engine process did not exit within the teardown timeout — "
                                   + "session NOT reported idle, Start stays disabled until it does");
            return dead;
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

        /// <summary>Request the resolved call stack (paused only); result arrives via StackReceived.</summary>
        public bool RequestStack() { return SendCommand("stack"); }

        /// <summary>EXPERIMENT: request the current module's module-scope data (paused only); via ModuleDataReceived.</summary>
        public bool RequestModuleData() { return SendCommand("moduledata"); }

        /// <summary>Request the thread inventory for the current stop (paused only); via ThreadsReceived.</summary>
        public bool RequestThreads() { return SendCommand("threads"); }

        /// <summary>Point the engine's READ paths (stack, framelocals, moduledata, watch, regs, libstate,
        /// disasm) at <paramref name="tid"/> for the rest of this stop; result via ThreadSelected. Resume-type
        /// commands always act on the STOPPED thread and reset this, and the engine drops the selection at
        /// every new stop — the pad never has to carry it across stops.</summary>
        public bool SelectThread(uint tid)
        {
            return tid > 0 && SendCommand("thread " + tid.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>Re-read the selected thread's registers (paused only); via RegsReceived. The 'paused'
        /// event carries the STOPPED thread's registers, so this is how the pane follows a thread switch.</summary>
        public bool RequestRegs() { return SendCommand("regs"); }

        /// <summary>Request the paused thread's RTL "Library State" (ERROR/EVENT/FIELD/…) — the engine
        /// EMULATES each ClaRUN getter read-only (no code runs in the debuggee, so this is safe at any
        /// stop, including inside TakeEvent). Result arrives via LibStateReceived keyed by
        /// <paramref name="reqId"/>. Paused only.</summary>
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

        /// <summary>EXPERIMENT: request a disassembly listing at the SELECTED thread's EIP (paused only);
        /// result arrives via DisasmReceived, stamped with the thread the engine decoded.</summary>
        public bool RequestDisasm() { return SendCommand("disasm"); }

        /// <summary>EXPERIMENT: request a disassembly window starting at a specific VA (hex like
        /// 0x441109). Used to keep a stable .asm view while instruction-stepping.</summary>
        public bool RequestDisasmAt(string vaHex, int count, string tag = null, int before = 0)
        {
            if (string.IsNullOrEmpty(vaHex) || !Regex.IsMatch(vaHex, "^0x[0-9A-Fa-f]+$")) return false;
            // The tag is POSITIONAL: it occupies its own space-separated slot ahead of `before`. A tag
            // containing whitespace would push `before` into the wrong argument and silently change the
            // request — so it is validated HERE, in the writer every caller goes through, rather than left
            // to each caller's own care. This was safe while every tag was a literal constant; it stopped
            // being safe the moment the disassembly view began generating them (it appends an epoch).
            if (tag != null && !Regex.IsMatch(tag, @"^[A-Za-z0-9_#.-]{0,32}$")) return false;
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
        public bool SetVariable(string vaHex, string typeCodeHex, int size, int places, string value, uint? tid = null)
        {
            if (State != DebugSessionState.Paused) return false;
            if (string.IsNullOrEmpty(vaHex) || !Regex.IsMatch(vaHex, "^0x[0-9A-Fa-f]+$")) return false;
            if (string.IsNullOrEmpty(typeCodeHex) || !Regex.IsMatch(typeCodeHex, "^0x[0-9A-Fa-f]+$")) return false;
            if (size <= 0 || size > 4096) return false;
            string b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value ?? string.Empty));
            string cmd = "setval " + vaHex + " " + typeCodeHex + " " + size + " " + places + " " + b64;
            // Optional trailing arg: the thread the address was read on. An address is only meaningful on
            // the thread whose instance it came from, so the engine can refuse a write whose thread is no
            // longer the selected one instead of writing another thread's memory. Trailing so an engine
            // that doesn't know about it is unaffected.
            if (tid.HasValue) cmd += " " + tid.Value.ToString(CultureInfo.InvariantCulture);
            return SendCommand(cmd);
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
                        // Identity is the line the USER asked for, not the record the engine snapped to:
                        // two gutter lines can snap to one planted line and they are two breakpoints, not
                        // one. Keying this on Line collapsed them into a single pane row.
                        DebugBreakpoint known = null;
                        foreach (var b in _breakpoints)
                            if (SameBpIdentity(b, bp)) { known = b; break; }
                        if (known == null) _breakpoints.Add(bp);
                        else
                        {
                            known.Line = bp.Line;      // a re-plant can snap the same requested line elsewhere
                            CopyBpProps(bp, known);    // refresh props/hit count on a re-confirm (properties edit)
                        }
                    }
                    BreakpointSet?.Invoke(bp);
                    break;

                case "bp-del":
                    string delMod = GetStr(json, "module");
                    int delLine = GetInt(json, "line");
                    // The engine removed exactly ONE logical breakpoint and names it by its requested line.
                    // GetIntOrNull, not GetInt: absent must stay distinguishable from 0, because 0 is a real
                    // RequestedLine for an unresolved raw breakpoint.
                    int? delRequested = GetIntOrNull(json, "requestedLine");
                    lock (_breakpoints)
                        _breakpoints.RemoveAll(b => BpDelMatches(b, delMod, delRequested, delLine));
                    BreakpointRemoved?.Invoke(delMod, delRequested ?? delLine);
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
                    // Same absent-aware reader every other thread-scoped reply uses: an engine that does not
                    // stamp disasm yields null, which means UNKNOWN — never 0, which a consumer would read
                    // as a real thread.
                    DisasmReceived?.Invoke(GetStr(json, "tag"), dlist, GetUIntOrNull(json, "tid"));
                    break;

                case "stack":
                    var frames = ParseStack(json);
                    foreach (var f in frames) f.ResolvedPath = ResolveModulePath(f.Module);
                    StackReceived?.Invoke(frames, GetUIntOrNull(json, "tid"));
                    break;

                case "moduledata":
                    ModuleDataReceived?.Invoke(GetStr(json, "module"), ExtractArrayBalanced(json, "items"), GetUIntOrNull(json, "tid"));
                    break;

                case "expanded":
                    ExpandedReceived?.Invoke(GetStr(json, "reqId"), ExtractArrayBalanced(json, "items"));
                    break;

                case "framelocals":
                    FrameLocalsReceived?.Invoke(GetStr(json, "reqId"), ExtractArrayBalanced(json, "items"), GetUIntOrNull(json, "tid"));
                    break;

                case "libstate":
                    LibStateReceived?.Invoke(GetStr(json, "reqId"), GetStr(json, "error"), ExtractArrayBalanced(json, "items"), GetUIntOrNull(json, "tid"));
                    break;

                case "threads":
                    var tl = ParseThreads(json);
                    if (tl != null) ThreadsReceived?.Invoke(tl);
                    break;

                case "threadselected":
                    // The tid is the thread that was ASKED FOR, and a malformed request carries none at all
                    // — passed through as null rather than 0, because 0 would be a sentinel the pad reads
                    // as a real thread id. Absent is the only way to say "unknown".
                    ThreadSelected?.Invoke(GetUIntOrNull(json, "tid"), GetBool(json, "ok"), GetStr(json, "error"));
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
                    // Standalone regs reply. The 'paused' event carries the stopped thread's registers, so
                    // this arrives when the pane has to follow something else — a thread switch.
                    RegsReceived?.Invoke(ParseRegs(json), GetUIntOrNull(json, "tid"));
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
                    Tid = GetUIntOrNull(json, "tid"),
                };
                p.Regs = ParseRegs(json);
                return p;
            }
            catch { return null; }
        }

        /// <summary>The x86 register block of a 'paused' or a standalone 'regs' event: {"eax":"0x...",...}
        /// — flat unique keys, extracted directly. Null when the event carries no register block.</summary>
        private static Dictionary<string, string> ParseRegs(string json)
        {
            if (string.IsNullOrEmpty(json) || json.IndexOf("\"regs\":{", StringComparison.Ordinal) < 0) return null;
            var regs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var reg in new[] { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags" })
            {
                string v = GetStr(json, reg);
                if (v != null) regs[reg] = v;
            }
            return regs;
        }

        /// <summary>The engine's thread inventory ('threads' event). The top-level stopped/selected tids are
        /// read from the text BEFORE the array, so a row's own "stopped":true can't be mistaken for them.</summary>
        private static DebugThreadList ParseThreads(string json)
        {
            try
            {
                var list = new DebugThreadList();
                int arr = json.IndexOf("\"threads\":[", StringComparison.Ordinal);
                string head = arr > 0 ? json.Substring(0, arr) : json;
                list.StoppedTid = GetUIntOrNull(head, "stopped") ?? 0u;
                list.SelectedTid = GetUIntOrNull(head, "selected") ?? 0u;
                foreach (Match m in Regex.Matches(ExtractArrayBalanced(json, "threads"), "\\{[^{}]*\\}"))
                {
                    string t = m.Value;
                    if (!t.Contains("\"tid\":")) continue;
                    list.Threads.Add(new DebugThread
                    {
                        Tid = GetUIntOrNull(t, "tid") ?? 0u,
                        ClarionThread = GetIntOrNull(t, "clarionThread"),
                        Proc = GetStr(t, "proc"),
                        Module = GetStr(t, "module"),
                        Line = GetInt(t, "line"),
                        State = GetStr(t, "state"),
                        ClarionFrames = GetInt(t, "clarionFrames"),
                        Stopped = GetBool(t, "stopped"),
                        Selected = GetBool(t, "selected"),
                    });
                }
                return list;
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
                        Uncertain = GetBool(f, "uncertain"),
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
                // The thread this name was resolved on. Carried on BOTH outcomes: a miss for the thread the
                // pad has stopped showing must be dropped just as firmly as a hit, or a late "(not found)"
                // from the previous thread wipes a row that the new thread answered correctly.
                w.Tid = GetUIntOrNull(json, "tid");
                if (!w.Found)
                {
                    w.OutOfScope = GetBool(json, "outOfScope");
                    w.Error = GetStr(json, "error");   // a read that failed, as opposed to a name that isn't known
                    return w;
                }
                w.Note = GetStr(json, "note");
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
                    // Routines come through as well as procedures/methods: they are what lets a breakpoint
                    // inside a ROUTINE name both it and its enclosing procedure. The engine already orders
                    // them together with their parent by definition line, so containment falls out of the
                    // line order — no extra symbol work. The Procedures panel filters routines back out on
                    // the client, so this does not change what that list shows.
                    if (kind != "procedure" && kind != "method" && kind != "routine") continue;
                    int line = GetInt(obj, "line");
                    if (line <= 0) continue;
                    list.Add(new DebugProcedure { Name = GetStr(obj, "name"), Module = GetStr(obj, "module"), Line = line, Kind = kind });
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
        /// JSON object. Shared so bp-set and bp-list decode identically — which is also why the
        /// absent-vs-zero care below only has to be taken once: this is the single place either event's
        /// <c>requestedLine</c> is read, so no caller can bypass it.
        /// <para>
        /// GetIntOrNull, not GetInt, for the same reason the bp-del arm uses it: GetInt answers 0 for an
        /// absent field, and 0 is a real requested line. Against an engine build that omits
        /// <c>requestedLine</c>, GetInt gave every breakpoint in a module an identity of (module, 0) and
        /// SameBpIdentity merged them into one pane row.
        /// </para></summary>
        private static DebugBreakpoint ParseBpFields(string json, string module)
        {
            return new DebugBreakpoint
            {
                Module = module,
                Line = GetInt(json, "line"),
                RequestedLineOrNull = GetIntOrNull(json, "requestedLine"),
                Condition = GetStr(json, "condition"),
                HitMode = GetStr(json, "hitMode"),
                HitValue = GetInt(json, "hitValue"),
                Trace = GetStr(json, "trace"),
                HitCount = GetInt(json, "hitCount")
            };
        }

        /// <summary>Whether a bp-set echo names a breakpoint the host already lists. Identity is
        /// (module, requested line): the planted line is where the engine SNAPPED the breakpoint, and
        /// two distinct gutter lines can snap to the same record, so keying identity on it merges two
        /// breakpoints into one row and loses one of them.
        /// <para>
        /// Requested lines are comparable only when BOTH sides have one. When either is absent — an engine
        /// build older than that protocol change, which reports no <c>requestedLine</c> — this falls back to
        /// the planted line, exactly as <see cref="BpDelMatches"/> does and for the same reason: an old
        /// engine cannot say which of two gutter lines that snapped to one record it means, so the planted
        /// line is all there is to key on. That fallback still merges two breakpoints sharing a record, which
        /// is the pre-existing cost of talking to an old engine; what it does NOT do is merge every
        /// breakpoint in the module, which is what comparing an absent line as 0 did.
        /// </para>
        /// <para>
        /// Both sides come from the same engine build in a live session, so both-present and both-absent are
        /// the reachable cases; the mixed case is defined rather than left to a 0 default, and is asserted in
        /// tools/test-addin-json.ps1 against a present requested line of 0.
        /// </para></summary>
        internal static bool SameBpIdentity(DebugBreakpoint a, DebugBreakpoint b)
        {
            if (a.Module != b.Module) return false;
            int? ra = a.RequestedLineOrNull, rb = b.RequestedLineOrNull;
            return (ra.HasValue && rb.HasValue) ? ra.Value == rb.Value : a.Line == b.Line;
        }

        /// <summary>Which host entries one bp-del removes. The engine deletes exactly one logical
        /// breakpoint and names it by <c>requestedLine</c>, so this matches that one and leaves any
        /// neighbour sharing its planted line alone. Only when the echo carries NO requestedLine — an
        /// engine build older than this protocol change — does it fall back to the planted line, which
        /// can still match several: that is the old behaviour, kept deliberately so an old engine keeps
        /// deleting something rather than silently deleting nothing.
        /// <para>
        /// Requested lines are comparable only when BOTH sides have one, exactly as in
        /// <see cref="SameBpIdentity"/>, which was written to mirror this function. Reading the entry's line
        /// through the substituting <c>RequestedLine</c> getter instead compared the entry's PLANTED line
        /// against the echo's REQUESTED one whenever the entry came from an engine build that reports no
        /// <c>requestedLine</c> — which both removes a row the engine did not delete (the two lines happen to
        /// be equal) and leaves the named one behind (they happen not to be). A stale entry from an earlier
        /// session is enough to reach that mix. So the absent case falls back to the planted line here too:
        /// over-broad, and the documented cost of an old echo, rather than silently wrong.
        /// </para></summary>
        internal static bool BpDelMatches(DebugBreakpoint b, string module, int? requestedLine, int plantedLine)
        {
            if (b.Module != module) return false;
            int? rb = b.RequestedLineOrNull;
            return (requestedLine.HasValue && rb.HasValue) ? rb.Value == requestedLine.Value
                                                           : b.Line == plantedLine;
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
        /// <summary>An integer field of THIS object that may legitimately be absent or JSON null — "0" is a
        /// real value for some of these (a Clarion thread number the RTL couldn't give is null, NOT 0), so
        /// GetInt's zero-for-absent answer can't be used to tell the two apart.</summary>
        private static int? GetIntOrNull(string json, string key)
        {
            string tok = ScanNumberToken(json, key);
            int v;
            return (tok != null && int.TryParse(tok, NumberStyles.Integer, CultureInfo.InvariantCulture, out v))
                ? (int?)v : null;
        }

        /// <summary>A Win32 thread id field. Thread ids are DWORDs: a real one can exceed Int32.MaxValue, and
        /// reading it as a signed int would return null for it — which the pad reads as "no tid", i.e. an
        /// UNSCOPED reply that it then accepts. That is the absent-means-unknown rule broken from the other
        /// side: a reply the engine did stamp would be taken as one it didn't, for one thread in two.</summary>
        private static uint? GetUIntOrNull(string json, string key)
        {
            string tok = ScanNumberToken(json, key);
            uint v;
            return (tok != null && uint.TryParse(tok, NumberStyles.Integer, CultureInfo.InvariantCulture, out v))
                ? (uint?)v : null;
        }

        /// <summary>The raw digits of a numeric field belonging to THIS object, or null when it is absent,
        /// JSON null, or not a number.
        /// <para>
        /// Only the object's OWN keys count: nested arrays and objects (a stack's frames, a moduledata item
        /// list, a string value that happens to contain the same text) are skipped, so an event's "tid" can
        /// never be picked up from something buried in its payload. Getting that wrong would mean dropping
        /// replies as "another thread's", which is exactly the failure this field exists to prevent.
        /// </para></summary>
        private static string ScanNumberToken(string json, string key)
        {
            if (string.IsNullOrEmpty(json)) return null;
            string quoted = "\"" + key + "\"";
            int depth = 0; bool inStr = false, esc = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inStr)
                {
                    if (esc) esc = false;
                    else if (c == '\\') esc = true;
                    else if (c == '"') inStr = false;
                    continue;
                }
                if (c == '"')
                {
                    if (depth == 1 && i + quoted.Length <= json.Length
                        && string.CompareOrdinal(json, i, quoted, 0, quoted.Length) == 0)
                    {
                        int p = i + quoted.Length;
                        while (p < json.Length && char.IsWhiteSpace(json[p])) p++;
                        if (p < json.Length && json[p] == ':')
                        {
                            p++;
                            while (p < json.Length && char.IsWhiteSpace(json[p])) p++;
                            int s = p;
                            if (p < json.Length && json[p] == '-') p++;
                            int digits = p;
                            while (p < json.Length && char.IsDigit(json[p])) p++;
                            // present but not a number (JSON null, or a bare '-') — same answer as absent
                            return p > digits ? json.Substring(s, p - s) : null;
                        }
                    }
                    inStr = true; continue;
                }
                if (c == '{' || c == '[') depth++;
                else if (c == '}' || c == ']') depth--;
            }
            return null;
        }
        private static bool GetBool(string json, string key)
        {
            var m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*(true|false)");
            return m.Success && m.Groups[1].Value == "true";
        }
    }
}
