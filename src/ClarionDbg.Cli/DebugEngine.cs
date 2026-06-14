using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>A requested breakpoint location (module:line), resolved and planted by the engine.</summary>
    internal sealed class BpSpec
    {
        public readonly string Module;
        public readonly int Line;
        public BpSpec(string module, int line) { Module = module; Line = line; }
    }

    /// <summary>One resolved call-stack frame (frame 0 = current EIP, rest = return addresses).</summary>
    internal sealed class StackFrame
    {
        public uint Rva;
        public uint Va;
        public uint StackAddr;     // stack slot holding the return address (0 for frame 0)
        public string Proc;        // demangled symbol, null when unknown
        public string Kind;        // procedure | method | routine | other, null when unknown
        public string Module;      // .clw name, null when unresolved
        public int Line;
    }

    /// <summary>One logical user breakpoint: a module:line bound to its code RVAs in the owning image.</summary>
    internal sealed class UserBreakpoint
    {
        public string Module;          // canonical compiland name (e.g. clbrws011.clw)
        public int ModuleIdx;          // index within Owner.Dbg (valid once Owner is set)
        public LoadedModule Owner;     // the mapped/known image whose TSWD carries this compiland; null = pending
        public int RequestedLine;      // the line the user asked for
        public int Line;               // the line actually planted (snapped to nearest record line)
        public readonly List<uint> Rvas = new List<uint>();   // code RVAs within Owner
        public bool Pending { get { return Owner == null; } } // owning image not yet loaded/resolved
    }

    /// <summary>
    /// x86 debug engine: launches a target under the Windows debug API, plants INT3 breakpoints,
    /// pumps the debug-event loop, and resolves hits to module + source line via TSWD info.
    ///
    /// Phase 2 adds:
    ///  - persistent breakpoints (re-armed after each hit via a TF single-step over the original byte)
    ///  - multiple module:line breakpoints, with runtime add/remove
    ///  - an interactive stdin command loop while paused: continue / step / stepover / stepout /
    ///    bp add|del|list / mem / regs / quit  (while running: bp add|del|list / quit)
    ///  - source-level stepping driven by the TF single-step flag + the +0x1C line table, with a
    ///    call-skip optimization (temp INT3 at the return address) so callees run at full speed —
    ///    no x86 instruction decoder needed.
    /// </summary>
    internal sealed partial class DebugEngine
    {
        private enum StepMode { None, Into, Over, Out }

        private const uint TRAP_FLAG = 0x100;        // EFLAGS TF bit
        private const int MAX_STEPS = 2000000;       // hard cap of single-steps per step command
        private const uint CALL_WINDOW = 8;          // max CALL instr length for return-addr detection
        private const uint PROLOGUE_WINDOW = 0x100;  // callee with a line record this close to entry is Clarion code
        private const uint ESP_SLACK = 0x10;         // frame-depth slack for step-over stop checks
        private const uint OUT_GAP_MAX = 0x200;      // step-out: max gap for "this looks like the call statement"

        private readonly string _exePath;
        private readonly bool _once;
        private readonly int _waitMs;
        private readonly bool _interactive;
        private readonly List<uint> _rawRvas;
        private readonly List<BpSpec> _initialSpecs;

        /// <summary>When true, emit one machine-readable JSON object per event (for the IDE addin).</summary>
        public bool EmitJson;

        // The module table: the EXE (module 0) plus every loaded DLL. Pre-launch, the EXE and any
        // solution DLLs are present with LoadBase==0 (not yet mapped) so breakpoints resolve against
        // their TSWD before launch; the live base is filled in at CREATE_PROCESS / LOAD_DLL.
        private readonly List<LoadedModule> _modules = new List<LoadedModule>();
        private LoadedModule _exe;           // module 0 — the launched image

        private IntPtr _hProcess = IntPtr.Zero;
        private bool _seenInitialBreak;
        public int Hits { get; private set; }

        // ---- pause (break into a running target) ----
        // DebugBreakProcess injects a breakpoint on a throwaway OS thread; when that break arrives we
        // pick the app thread actually in Clarion code and pause there. Live thread ids are tracked so
        // we can scan them at pause time (the injected thread is not the one the user cares about).
        private bool _pauseRequested;
        private readonly HashSet<uint> _threads = new HashSet<uint>();
        private uint _mainTid;               // first thread (from CREATE_PROCESS) — pause fallback

        // logical user breakpoints + armed-byte map (VA -> original byte)
        private readonly List<UserBreakpoint> _bps = new List<UserBreakpoint>();
        private readonly Dictionary<uint, byte> _armed = new Dictionary<uint, byte>();
        // internal temp breakpoints (call-skip return addresses): VA -> original byte
        private readonly Dictionary<uint, byte> _temp = new Dictionary<uint, byte>();

        // re-arm: a VA whose original byte was restored so the real instruction can execute; re-plant
        // 0xCC after one single-step. Keyed by the thread that restored the byte and consumed by THAT
        // thread's next single-step — a scalar here loses re-plants when a second thread hits a
        // breakpoint (or a recursive temp BP fires) between the restore and its single-step.
        private struct Rearm { public uint Va; public bool IsTemp; }
        private readonly Dictionary<uint, Rearm> _rearm = new Dictionary<uint, Rearm>();

        // ---- threaded-data func-eval (watch NAME on THREADed .cwtls data) ----
        // While paused, hijack the CURRENT thread to call ClaRUN!THR$GetInstance(EAX=templateVA,
        // EBX=.cwtls base) and trap the return at an unmapped magic address. The paused thread IS
        // the thread whose instance the user wants — per-thread data resolves correctly by design.
        private const uint EVAL_TRAP_VA = 0x7FFF1000;   // never valid in 32-bit user space
        private bool _evalActive;
        private uint _evalTid;
        private Native.CONTEXT_X86 _evalSavedCtx;
        private bool _evalHadRearm;
        private Rearm _evalSavedRearm;
        private string _evalName;                       // pending watch: symbol + size to read
        private uint _evalSize;
        private string _evalTypeName;
        private byte _evalTypeCode;
        private uint _evalTemplateVa;

        // source-level stepping state
        private StepMode _mode = StepMode.None;
        private uint _stepTid;
        private uint _startEsp;       // ESP at step start (stack grows down: larger = shallower)
        private int _startLine;
        private int _startModIdx;
        private LoadedModule _startModule;   // owning image at step start (moduleIdx is only comparable within it)
        private uint _prevVa;         // EIP at the previous single-step trap (for call-entry detection)
        private int _stepCount;
        private bool _skipRunning;    // running full-speed to a call-skip temp BP; TF off
        private uint _skipEntryEsp;   // ESP at the callee's entry instruction (return depth = this + 4)

        private readonly ConcurrentQueue<string> _cmds = new ConcurrentQueue<string>();

        public DebugEngine(string exe, PeImage exePe, TswdDebugInfo exeDbg, List<uint> rawRvas,
                           List<BpSpec> specs, bool once, int waitMs, bool interactive,
                           IEnumerable<string> solutionDlls = null)
        {
            _exePath = exe;
            _rawRvas = rawRvas ?? new List<uint>();
            _initialSpecs = specs ?? new List<BpSpec>();
            _once = once; _waitMs = waitMs; _interactive = interactive;

            // Seed the module table with the EXE (module 0) and any solution DLLs the host named, so
            // breakpoints resolve against their TSWD before launch. LoadBase stays 0 until mapped.
            _exe = RegisterImageFromPe(exe, exePe, exeDbg);
            if (solutionDlls != null)
                foreach (var dll in solutionDlls)
                    TryPreloadSolutionDll(dll);
        }

        public int Run()
        {
            if (_interactive) StartStdinReader();

            // resolve module:line specs up front so bp-set/bp-error report before launch
            foreach (var s in _initialSpecs) AddBreakpoint(s.Module, s.Line);
            // raw RVAs (legacy --rva/--entry/--all-entries) become anonymous breakpoints
            foreach (var rva in _rawRvas) AddRawBreakpoint(rva);

            if (_bps.Count == 0 && !_interactive)
            {
                Console.Error.WriteLine("nothing to break on — no breakpoint resolved");
                return -1;
            }

            var si = new Native.STARTUPINFO();
            si.cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(si);
            Native.PROCESS_INFORMATION pi;

            string workDir = Path.GetDirectoryName(Path.GetFullPath(_exePath));
            bool ok = Native.CreateProcess(_exePath, null, IntPtr.Zero, IntPtr.Zero, false,
                Native.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, workDir, ref si, out pi);
            if (!ok)
                throw new InvalidOperationException("CreateProcess failed, win32 error " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());

            Console.WriteLine($"launched {Path.GetFileName(_exePath)} (pid {pi.dwProcessId}); {_bps.Count} breakpoint(s)");
            _hProcess = pi.hProcess;

            var buf = new byte[1024];
            bool running = true;
            uint pollMs = _interactive ? 200u : (uint)_waitMs;
            while (running)
            {
                if (!Native.WaitForDebugEvent(buf, pollMs))
                {
                    if (_interactive)
                    {
                        // no event — service any commands that arrived while the target runs
                        DrainCommandsWhileRunning();
                        continue;
                    }
                    Console.WriteLine("(timeout waiting for debug event — terminating target)");
                    Native.TerminateProcess(_hProcess, 0);
                    // drain until exit
                    while (Native.WaitForDebugEvent(buf, 2000))
                    {
                        if (Code(buf) == Native.EXIT_PROCESS_DEBUG_EVENT) break;
                        Native.ContinueDebugEvent(Pid(buf), Tid(buf), Native.DBG_CONTINUE);
                    }
                    break;
                }

                uint code = Code(buf);
                uint pid = Pid(buf);
                uint tid = Tid(buf);
                uint status = Native.DBG_CONTINUE;

                switch (code)
                {
                    case Native.CREATE_PROCESS_DEBUG_EVENT:
                        // union @+12: hFile(+12) hProcess(+16) hThread(+20) lpBaseOfImage(+24)
                        _exe.LoadBase = U32(buf, 24);
                        _mainTid = tid; _threads.Add(tid);
                        PlantAll();
                        uint preferred = _exe.Pe != null ? _exe.Pe.ImageBase : 0;
                        Console.WriteLine($"process created: loadBase=0x{_exe.LoadBase:X} (preferred 0x{preferred:X}){(_exe.LoadBase != preferred ? "  [relocated]" : "")}");
                        if (EmitJson)
                        {
                            Console.WriteLine("@JSON " + Json.Loaded(pi.dwProcessId, _exe.LoadBase));
                            Console.WriteLine("@JSON " + Json.ModuleLoaded(_exe));
                        }
                        break;

                    case Native.LOAD_DLL_DEBUG_EVENT:
                        // union @+12: hFile(+12) lpBaseOfDll(+16) ...
                        OnDllLoaded(U32(buf, 12), U32(buf, 16));
                        break;

                    case Native.UNLOAD_DLL_DEBUG_EVENT:
                        // union @+12: lpBaseOfDll(+12)
                        OnDllUnloaded(U32(buf, 12));
                        break;

                    case Native.CREATE_THREAD_DEBUG_EVENT:
                        _threads.Add(tid);
                        break;

                    case Native.EXIT_THREAD_DEBUG_EVENT:
                        _threads.Remove(tid);
                        break;

                    case Native.EXCEPTION_DEBUG_EVENT:
                        // union @+12: EXCEPTION_RECORD: code(+12) flags(+16) recPtr(+20) addr(+24)
                        uint exCode = U32(buf, 12);
                        uint exAddr = U32(buf, 24);
                        if (exCode == Native.EXCEPTION_BREAKPOINT)
                        {
                            if (_armed.ContainsKey(exAddr))
                                status = OnUserBp(tid, exAddr);
                            else if (_temp.ContainsKey(exAddr))
                                status = OnTempBp(tid, exAddr);
                            else if (!_seenInitialBreak)
                            {
                                _seenInitialBreak = true; // OS loader breakpoint — swallow it
                                status = Native.DBG_CONTINUE;
                            }
                            else if (_pauseRequested)
                            {
                                // Our injected DebugBreakProcess landed → pause here. MUST be checked
                                // before OnProgrammaticBreak, or a user-requested pause would be
                                // misreported as a hardcoded breakpoint the debuggee executed itself.
                                _pauseRequested = false;
                                status = OnPauseBreak(tid);
                            }
                            else status = OnProgrammaticBreak(tid); // an int3 the debuggee executed itself
                        }
                        else if (exCode == Native.EXCEPTION_SINGLE_STEP)
                        {
                            status = OnSingleStep(tid);
                        }
                        else if (_evalActive && tid == _evalTid && exAddr == EVAL_TRAP_VA)
                        {
                            // the hijacked THR$GetInstance call returned into our unmapped magic
                            // address — EAX now holds the thread's live instance VA
                            status = OnEvalComplete(tid);
                        }
                        else
                        {
                            // pass first-chance non-breakpoint exceptions back to the app
                            status = Native.DBG_EXCEPTION_NOT_HANDLED;
                        }
                        break;

                    case Native.EXIT_PROCESS_DEBUG_EVENT:
                        uint exitCode = U32(buf, 12);
                        Console.WriteLine($"process exited (code {exitCode})");
                        if (EmitJson) Console.WriteLine("@JSON " + Json.Exited(exitCode));
                        running = false;
                        break;

                    // OUTPUT_DEBUG_STRING / RIP: just continue
                    default:
                        status = Native.DBG_CONTINUE;
                        break;
                }

                if (running)
                    Native.ContinueDebugEvent(pid, tid, status);
            }

            Native.CloseHandle(pi.hThread);
            Native.CloseHandle(pi.hProcess);
            return Hits;
        }

        // ------------------------------------------------------------------ programmatic breakpoint

        /// <summary>
        /// An unexpected breakpoint after startup that we did NOT plant — the debuggee executed an
        /// int3 itself: a hardcoded breakpoint via DebugBreak() / __debugbreak() (e.g. a Clarion
        /// program calling kernel32 DebugBreak under IsDebuggerPresent()). This is the program asking
        /// the debugger to stop here, so honour it and enter the pause loop.
        ///
        /// Unlike our planted 0xCC — where we restore the original byte and rewind EIP so the real
        /// instruction re-executes — a hardcoded int3 IS the instruction. EIP already points past it
        /// and must NOT be rewound (rewinding would re-run the int3 forever). We just report and, on
        /// resume, DBG_CONTINUE so the thread proceeds. Non-interactive sessions ignore it (the legacy
        /// behaviour) so batch runs never block.
        /// </summary>
        private uint OnProgrammaticBreak(uint tid)
        {
            if (!_interactive) return Native.DBG_CONTINUE;
            Hits++;
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);
            CancelStep(); // a programmatic break supersedes any in-flight step
            PausedWait(tid, hThread, ref ctx, haveCtx, "debugbreak");
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        // ------------------------------------------------------------------ pause (break into running)

        /// <summary>Inject a breakpoint into the target so a running session can pause. The break is
        /// caught by the debug loop and routed to <see cref="OnPauseBreak"/>.</summary>
        private void RequestPause()
        {
            if (_hProcess == IntPtr.Zero) { EmitError("pause: no target running"); return; }
            _pauseRequested = true;
            if (!Native.DebugBreakProcess(_hProcess))
            {
                _pauseRequested = false;
                EmitError("pause: DebugBreakProcess failed (" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ")");
            }
        }

        /// <summary>The injected break arrived. It runs on a throwaway ntdll thread, so pick the app
        /// thread actually in Clarion code (or the main thread) and pause there. The whole process is
        /// frozen while we hold this event, so every thread's context is stable to read.</summary>
        private uint OnPauseBreak(uint breakTid)
        {
            uint tid = PickPauseThread(breakTid);
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);
            CancelStep();
            if (_interactive)
                PausedWait(tid, hThread, ref ctx, haveCtx, "pause");
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;  // release the injected break thread (it then exits)
        }

        /// <summary>Choose the most useful thread to report at a pause: prefer one whose EIP is in
        /// TSWD-mapped Clarion code (any loaded module); else the first readable non-break thread;
        /// else the main thread.</summary>
        private uint PickPauseThread(uint breakTid)
        {
            uint fallback = 0;
            foreach (uint t in _threads)
            {
                if (t == breakTid) continue;
                IntPtr h = OpenThreadForContext(t);
                if (h == IntPtr.Zero) continue;
                var c = NewContext();
                bool ok = Native.GetThreadContext(h, ref c);
                Native.CloseHandle(h);
                if (!ok) continue;
                if (fallback == 0) fallback = t;
                // EIP in any mapped Clarion image's code → this is the thread worth reporting. Resolve
                // against the owning module (multi-DLL: the active thread may be in a DLL, not the EXE).
                var m = ModuleAt(c.Eip);
                if (m != null && m.Dbg != null)
                {
                    int line, mi; uint rec;
                    if (m.Dbg.ResolveAddr(c.Eip - m.LoadBase, out line, out mi, out rec)) return t;
                }
            }
            if (fallback != 0) return fallback;
            return _mainTid != 0 ? _mainTid : breakTid;
        }

        // ------------------------------------------------------------------ pause + command loop

        /// <summary>
        /// Blocks the debug loop (target fully suspended — the debug event is not continued) and
        /// services stdin commands until a resume-type command arrives.
        /// </summary>
        private void PausedWait(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx, string reason)
        {
            _pauseRequested = false;  // any pause we reach consumes a pending pause request
            uint va = haveCtx ? ctx.Eip : 0;
            var m = haveCtx ? ModuleAt(va) : null;
            uint rva = m != null ? va - m.LoadBase : va;
            int line = 0; int mi = -1; uint recRva = 0;
            bool resolved = haveCtx && m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            if (!resolved) { line = 0; mi = -1; recRva = 0; }
            string mod = resolved ? m.Dbg.ModuleNameForIdx(mi) : null;
            string proc = haveCtx ? ProcNameAt(m, rva, resolved ? mi : -1) : null;
            uint gap = resolved ? rva - recRva : 0;

            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Paused(reason, mod, proc, resolved ? line : 0, rva, va, gap, resolved,
                    haveCtx ? Json.Regs(ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp, ctx.Eip, ctx.EFlags) : null));
            Console.WriteLine($"  [paused: {reason}]{(resolved ? " " + mod + " line " + line : "")}{(proc != null ? " in " + proc : "")} — commands: continue step stepover stepout bp mem regs stack sym watch quit");

            while (true)
            {
                string cmd;
                if (!_cmds.TryDequeue(out cmd)) { Thread.Sleep(20); continue; }
                cmd = cmd.Trim();
                if (cmd.Length == 0) continue;
                var parts = cmd.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string verb = parts[0].ToLowerInvariant();
                switch (verb)
                {
                    case "continue": case "c": case "g":
                        EmitResumed("continue");
                        ArmResume(tid, hThread, ref ctx, haveCtx, false);
                        return;

                    case "step": case "stepinto": case "s": case "i":
                        BeginStep(StepMode.Into, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("step");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepover": case "next": case "n":
                        BeginStep(StepMode.Over, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("stepover");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepout": case "out": case "finish": case "o":
                        BeginStep(StepMode.Out, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("stepout");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "bp":
                        HandleBpCommand(parts);
                        break;

                    case "regs":
                        if (haveCtx && EmitJson)
                            Console.WriteLine("@JSON " + Json.RegsEvent(Json.Regs(ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp, ctx.Eip, ctx.EFlags)));
                        else if (haveCtx)
                            Console.WriteLine($"  EAX={ctx.Eax:X8} EBX={ctx.Ebx:X8} ECX={ctx.Ecx:X8} EDX={ctx.Edx:X8} ESI={ctx.Esi:X8} EDI={ctx.Edi:X8} EBP={ctx.Ebp:X8} ESP={ctx.Esp:X8} EIP={ctx.Eip:X8}");
                        break;

                    case "mem":
                        HandleMemCommand(parts);
                        break;

                    case "stack": case "bt": case "where":
                        HandleStackCommand(parts, ref ctx, haveCtx);
                        break;

                    case "locals": case "vars":
                        HandleLocalsCommand(parts, ref ctx, haveCtx);
                        break;

                    case "sym":
                        HandleSymCommand(parts);
                        break;

                    case "watch":
                        // resolve + read a data symbol's CURRENT-THREAD value. THREADed (.cwtls)
                        // names need a func-eval: the target resumes briefly to run
                        // THR$GetInstance, so we must leave the pause loop; the completion
                        // handler re-enters it with the original context restored.
                        if (HandleWatchCommand(parts, tid, hThread, ref ctx, haveCtx))
                            return;
                        break;

                    case "quit": case "q": case "kill":
                        Native.TerminateProcess(_hProcess, 0);
                        return; // the EXIT_PROCESS event ends the loop

                    default:
                        EmitError("unknown command: " + verb);
                        break;
                }
            }
        }

        /// <summary>Set TF on the paused thread when the resume needs a single-step (BP re-arm or stepping).</summary>
        private void ArmResume(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx, bool stepping)
        {
            if (!haveCtx) return;
            bool needTf = stepping || _rearm.ContainsKey(tid);
            if (!needTf) return;
            Native.GetThreadContext(hThread, ref ctx); // refresh — EIP was rewritten at hit time
            ctx.EFlags |= TRAP_FLAG;
            Native.SetThreadContext(hThread, ref ctx);
        }

        /// <summary>Commands accepted while the target is running (between debug events).</summary>
        private void DrainCommandsWhileRunning()
        {
            string cmd;
            while (_cmds.TryDequeue(out cmd))
            {
                cmd = cmd.Trim();
                if (cmd.Length == 0) continue;
                var parts = cmd.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string verb = parts[0].ToLowerInvariant();
                switch (verb)
                {
                    case "bp":
                        HandleBpCommand(parts);
                        break;
                    case "sym":
                        HandleSymCommand(parts);   // static lookup — safe while running
                        break;
                    case "pause": case "break":
                        RequestPause();            // inject a break → pause at the app's current location
                        break;
                    case "quit": case "q": case "kill":
                        if (_hProcess != IntPtr.Zero) Native.TerminateProcess(_hProcess, 0);
                        break;
                    case "continue": case "c": case "g":
                    case "step": case "stepinto": case "s": case "i":
                    case "stepover": case "next": case "n":
                    case "stepout": case "out": case "finish": case "o":
                    case "mem": case "regs": case "stack": case "bt": case "where": case "watch":
                    case "locals": case "vars":
                        EmitError("target is running — " + verb + " is only valid while paused");
                        break;
                    default:
                        EmitError("unknown command: " + verb);
                        break;
                }
            }
        }

        /// <summary>bp add module:line | bp del module:line | bp list</summary>
        private void HandleBpCommand(string[] parts)
        {
            string sub = parts.Length > 1 ? parts[1].ToLowerInvariant() : "list";
            if (sub == "list")
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpList(_bps));
                else foreach (var b in _bps) Console.WriteLine($"  bp {b.Module}:{b.Line} ({b.Rvas.Count} addr)");
                return;
            }
            if (parts.Length < 3) { EmitError("bp " + sub + " expects module:line"); return; }
            string spec = parts[2];
            int colon = spec.LastIndexOf(':');
            int lineNo;
            if (colon <= 0 || !int.TryParse(spec.Substring(colon + 1), out lineNo))
            {
                EmitError("bp " + sub + " expects module:line, got '" + spec + "'");
                return;
            }
            string module = spec.Substring(0, colon);
            if (sub == "add") AddBreakpoint(module, lineNo);
            else if (sub == "del" || sub == "remove" || sub == "rm") RemoveBreakpoint(module, lineNo);
            else EmitError("unknown bp subcommand: " + sub);
        }

        /// <summary>
        /// sym NAME — resolve a data name (global, record buffer, or record field like JOB:JOBID)
        /// to its live VA + type/size so the host can follow up with a mem read. Resolution is
        /// static (TSWD tables), so it is valid while paused OR running. The VA is the link-time
        /// template instance — for THREADed (.cwtls) data the active thread's copy may differ.
        /// </summary>
        private void HandleSymCommand(string[] parts)
        {
            if (parts.Length < 2) { EmitError("sym expects: sym NAME"); return; }
            string name = parts[1];
            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            if (!ResolveDataAcrossModules(name, out owner, out loc))
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.Sym(name, false, 0, 0, 0, null, 0, null));
                Console.WriteLine($"  sym {name}: not found");
                return;
            }
            uint va = owner.LoadBase + loc.Rva;
            string tn = TswdDebugInfo.TypeCodeName(loc.TypeCode);
            if (EmitJson) Console.WriteLine("@JSON " + Json.Sym(name, true, loc.Rva, va, loc.TypeCode, tn, loc.Size, loc.Container));
            Console.WriteLine($"  sym {name}: VA 0x{va:X} (RVA 0x{loc.Rva:X}) {(tn ?? $"type 0x{loc.TypeCode:X2}")} size {loc.Size}{(loc.Container != null ? " in " + loc.Container : "")}");
        }

        private static Native.CONTEXT_X86 CloneContext(ref Native.CONTEXT_X86 src)
        {
            var c = src;   // struct copy — but the two byte[] fields still REFERENCE src's arrays
            c.FltRegisterArea = (byte[])src.FltRegisterArea.Clone();
            c.ExtendedRegisters = (byte[])src.ExtendedRegisters.Clone();
            return c;
        }

        private void WriteU32(uint va, uint value)
        {
            int wrote;
            Native.WriteProcessMemory(_hProcess, (IntPtr)va, BitConverter.GetBytes(value), 4, out wrote);
        }

        /// <summary>mem 0xADDR LEN — read target memory while paused (for the watch pane).</summary>
        private void HandleMemCommand(string[] parts)
        {
            if (parts.Length < 3) { EmitError("mem expects: mem 0xADDR LEN"); return; }
            uint addr; int len;
            string a = parts[1].Trim();
            try
            {
                addr = a.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    ? Convert.ToUInt32(a.Substring(2), 16)
                    : Convert.ToUInt32(a);
            }
            catch { EmitError("mem: bad address '" + a + "'"); return; }
            if (!int.TryParse(parts[2], out len) || len <= 0 || len > 4096)
            {
                EmitError("mem: length must be 1..4096");
                return;
            }
            var buf = new byte[len];
            int read;
            Native.ReadProcessMemory(_hProcess, (IntPtr)addr, buf, len, out read);
            if (read <= 0)
            {
                EmitError($"mem: read failed at 0x{addr:X}");
                return;
            }
            // echo the REQUESTED len so the host can correlate the reply to its request even when
            // the read came back short; bytes carries only what was actually read
            if (EmitJson) Console.WriteLine("@JSON " + Json.Mem(addr, buf, read, len));
            else
            {
                // hex + ASCII sidebar, 16 bytes per row (a flat hex blob hides readable strings)
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
                    Console.WriteLine($"  mem 0x{addr + (uint)row:X8}: {hex.ToString().PadRight(48)} {asc}");
                }
            }
        }

        private void EmitResumed(string mode)
        {
            if (EmitJson) Console.WriteLine("@JSON " + Json.Resumed(mode));
            Console.WriteLine($"  [resumed: {mode}]");
        }

        private void EmitError(string message)
        {
            if (EmitJson) Console.WriteLine("@JSON " + Json.Error(message));
            Console.WriteLine("  ERROR: " + message);
        }

        // ------------------------------------------------------------------ helpers

        private void StartStdinReader()
        {
            var t = new Thread(() =>
            {
                try
                {
                    string line;
                    while ((line = Console.In.ReadLine()) != null)
                        _cmds.Enqueue(line);
                }
                catch { /* stdin torn down */ }
                // stdin closed → the host (IDE addin) went away; kill the target rather than orphan it
                _cmds.Enqueue("quit");
            });
            t.IsBackground = true;
            t.Name = "stdin-commands";
            t.Start();
        }

        /// <summary>
        /// Demangled symbol (proc/method/routine) containing a code RVA, or null when unknown.
        /// Cross-checks the symbol's module against the +0x1C moduleIdx when the caller has one:
        /// code emitted BELOW a module's named entry (init/cold) would otherwise bind to the
        /// previous module's last symbol — better to say "unknown" than name the wrong proc.
        /// </summary>
        private string ProcNameAt(LoadedModule m, uint rva, int moduleIdx)
        {
            if (m == null || m.Dbg == null) return null;
            ProcSymbol sym;
            if (!m.Dbg.ResolveSymbol(rva, out sym)) return null;
            if (moduleIdx >= 0 && sym.ModuleIdx != moduleIdx) return null;
            return sym.Name;
        }

        /// <summary>Is there a line record in [rva, rva+window] in this image? (Spots Clarion callees.)</summary>
        private bool HasRecordInRange(LoadedModule m, uint rva, uint window)
        {
            if (m == null || m.Dbg == null) return false;
            var t = m.Dbg.AddrTable;
            if (t == null || t.Count == 0) return false;
            int lo = 0, hi = t.Count - 1, ans = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (t[mid].Rva >= rva) { ans = mid; hi = mid - 1; }
                else lo = mid + 1;
            }
            return ans >= 0 && t[ans].Rva <= rva + window;
        }

        private bool ReadByte(uint va, out byte value)
        {
            var b = new byte[1];
            int read;
            bool ok = Native.ReadProcessMemory(_hProcess, (IntPtr)va, b, 1, out read) && read == 1;
            value = ok ? b[0] : (byte)0;
            return ok;
        }

        private void WriteByte(uint va, byte value)
        {
            int wrote;
            Native.WriteProcessMemory(_hProcess, (IntPtr)va, new[] { value }, 1, out wrote);
            Native.FlushInstructionCache(_hProcess, (IntPtr)va, (IntPtr)1);
        }

        private uint ReadU32(uint va)
        {
            var b = new byte[4];
            int read;
            if (!Native.ReadProcessMemory(_hProcess, (IntPtr)va, b, 4, out read) || read != 4) return 0;
            return BitConverter.ToUInt32(b, 0);
        }

        private static Native.CONTEXT_X86 NewContext()
        {
            var c = new Native.CONTEXT_X86();
            c.ContextFlags = Native.CONTEXT_FULL;
            c.FltRegisterArea = new byte[80];
            c.ExtendedRegisters = new byte[512];
            return c;
        }

        // EXCEPTION debug events don't carry a thread handle, so open one for the thread id.
        private static IntPtr OpenThreadForContext(uint tid)
        {
            const uint THREAD_GET_CONTEXT = 0x0008;
            const uint THREAD_SET_CONTEXT = 0x0010;
            const uint THREAD_QUERY_INFORMATION = 0x0040;
            return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, tid);
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern uint GetFinalPathNameByHandle(IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        /// <summary>Resolve a LOAD_DLL file handle to its on-disk path, stripping the \\?\ device
        /// prefix. Returns null when the handle is invalid or the path can't be resolved.</summary>
        private static string GetPathFromHandle(uint hFile)
        {
            if (hFile == 0) return null;
            var sb = new System.Text.StringBuilder(520);
            uint n = GetFinalPathNameByHandle((IntPtr)hFile, sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            string p = sb.ToString();
            if (p.StartsWith(@"\\?\UNC\")) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\")) p = p.Substring(4);
            return p;
        }

        /// <summary>Close a raw debug-event handle (the LOAD_DLL hFile) so we don't leak it.</summary>
        private static void CloseHandleValue(uint handle)
        {
            if (handle != 0) Native.CloseHandle((IntPtr)handle);
        }

        // --- DEBUG_EVENT header accessors (first 12 bytes) ---
        private static uint Code(byte[] b) { return U32(b, 0); }
        private static uint Pid(byte[] b) { return U32(b, 4); }
        private static uint Tid(byte[] b) { return U32(b, 8); }
        private static uint U32(byte[] b, int off) { return BitConverter.ToUInt32(b, off); }

    }
}
