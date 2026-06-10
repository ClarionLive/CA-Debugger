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

    /// <summary>One logical user breakpoint: a module:line bound to its code RVAs.</summary>
    internal sealed class UserBreakpoint
    {
        public string Module;          // canonical module name (e.g. clbrws011.clw)
        public int ModuleIdx;
        public int RequestedLine;      // the line the user asked for
        public int Line;               // the line actually planted (snapped to nearest record line)
        public readonly List<uint> Rvas = new List<uint>();
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
    internal sealed class DebugEngine
    {
        private enum StepMode { None, Into, Over, Out }

        private const uint TRAP_FLAG = 0x100;        // EFLAGS TF bit
        private const int MAX_STEPS = 2000000;       // hard cap of single-steps per step command
        private const uint CALL_WINDOW = 8;          // max CALL instr length for return-addr detection
        private const uint PROLOGUE_WINDOW = 0x100;  // callee with a line record this close to entry is Clarion code
        private const uint ESP_SLACK = 0x10;         // frame-depth slack for step-over stop checks
        private const uint OUT_GAP_MAX = 0x200;      // step-out: max gap for "this looks like the call statement"

        private readonly string _exe;
        private readonly TswdDebugInfo _dbg;
        private readonly bool _once;
        private readonly int _waitMs;
        private readonly bool _interactive;
        private readonly List<uint> _rawRvas;
        private readonly List<BpSpec> _initialSpecs;

        /// <summary>When true, emit one machine-readable JSON object per event (for the IDE addin).</summary>
        public bool EmitJson;

        private IntPtr _hProcess = IntPtr.Zero;
        private uint _imageBase;             // PE preferred base — log/reporting only; never used in live VA math
        private uint _loadBase;              // actual load base from CREATE_PROCESS event — ALL live VA math uses this
        private bool _seenInitialBreak;
        public int Hits { get; private set; }

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
        private uint _cwtlsLo, _cwtlsHi;                // .cwtls RVA range (0,0 = no threaded support)
        private uint _thrGetInstanceIatRva;             // IAT slot of ClaRUN.dll!THR$GetInstance
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

        /// <summary>Enable threaded-data resolution (call before Run). cwtls = the .cwtls section
        /// RVA range; iatSlotRva = the IAT slot of ClaRUN.dll!THR$GetInstance.</summary>
        public void SetThreadEvalInfo(uint cwtlsLo, uint cwtlsHi, uint iatSlotRva)
        {
            _cwtlsLo = cwtlsLo; _cwtlsHi = cwtlsHi; _thrGetInstanceIatRva = iatSlotRva;
        }

        // source-level stepping state
        private StepMode _mode = StepMode.None;
        private uint _stepTid;
        private uint _startEsp;       // ESP at step start (stack grows down: larger = shallower)
        private int _startLine;
        private int _startModIdx;
        private uint _prevVa;         // EIP at the previous single-step trap (for call-entry detection)
        private int _stepCount;
        private bool _skipRunning;    // running full-speed to a call-skip temp BP; TF off
        private uint _skipEntryEsp;   // ESP at the callee's entry instruction (return depth = this + 4)

        private readonly ConcurrentQueue<string> _cmds = new ConcurrentQueue<string>();

        public DebugEngine(string exe, TswdDebugInfo dbg, uint imageBase, List<uint> rawRvas,
                           List<BpSpec> specs, bool once, int waitMs, bool interactive)
        {
            _exe = exe; _dbg = dbg; _imageBase = imageBase;
            _rawRvas = rawRvas ?? new List<uint>();
            _initialSpecs = specs ?? new List<BpSpec>();
            _once = once; _waitMs = waitMs; _interactive = interactive;
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

            string workDir = Path.GetDirectoryName(Path.GetFullPath(_exe));
            bool ok = Native.CreateProcess(_exe, null, IntPtr.Zero, IntPtr.Zero, false,
                Native.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, workDir, ref si, out pi);
            if (!ok)
                throw new InvalidOperationException("CreateProcess failed, win32 error " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());

            Console.WriteLine($"launched {Path.GetFileName(_exe)} (pid {pi.dwProcessId}); {_bps.Count} breakpoint(s)");
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
                        _loadBase = U32(buf, 24);
                        PlantAll();
                        Console.WriteLine($"process created: loadBase=0x{_loadBase:X} (preferred 0x{_imageBase:X}){(_loadBase != _imageBase ? "  [relocated]" : "")}");
                        if (EmitJson) Console.WriteLine("@JSON " + Json.Loaded(pi.dwProcessId, _loadBase));
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
                            else status = Native.DBG_CONTINUE;
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

                    // CREATE_THREAD / EXIT_THREAD / LOAD_DLL / UNLOAD_DLL / OUTPUT_DEBUG_STRING / RIP: just continue
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

        // ------------------------------------------------------------------ breakpoint management

        /// <summary>Resolve module:line to RVAs (snapping to the nearest record line) and register it.</summary>
        private void AddBreakpoint(string module, int line)
        {
            int mi = _dbg.FindModuleIdx(module);
            if (mi < 0)
            {
                Console.WriteLine($"bp: unknown module {module}");
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(module, line, "unknown module"));
                return;
            }
            string canon = _dbg.ModuleNameForIdx(mi) ?? module;
            int planted = line;
            var rvas = _dbg.LineToRvasInModuleIdx(mi, line);
            if (rvas.Count == 0)
            {
                // Clarion's line table is sparse — snap to the nearest line that has a record
                int snapped = NearestIn(_dbg.BreakableLinesInModuleIdx(mi), line);
                if (snapped > 0) { planted = snapped; rvas = _dbg.LineToRvasInModuleIdx(mi, snapped); }
            }
            if (rvas.Count == 0)
            {
                Console.WriteLine($"bp: no code records in {canon} (line {line})");
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(canon, line, "no code records in module"));
                return;
            }
            // adding an existing planted line is a no-op (re-confirm so the UI can sync)
            foreach (var b in _bps)
                if (b.ModuleIdx == mi && b.Line == planted)
                {
                    if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(b.Module, line, b.Line, b.Rvas));
                    return;
                }

            var bp = new UserBreakpoint { Module = canon, ModuleIdx = mi, RequestedLine = line, Line = planted };
            bp.Rvas.AddRange(rvas);
            _bps.Add(bp);
            if (_loadBase != 0) PlantBp(bp);
            if (planted != line)
                Console.WriteLine($"bp: line {line} has no code record in {canon}; breakpoint moved to nearest line {planted}");
            Console.WriteLine($"bp: set {canon}:{planted} ({bp.Rvas.Count} address(es))");
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpSet(canon, line, planted, bp.Rvas));
        }

        /// <summary>Register a raw RVA (legacy --rva/--entry) as an anonymous breakpoint.</summary>
        private void AddRawBreakpoint(uint rva)
        {
            int line; int mi; uint recRva;
            bool resolved = _dbg.ResolveAddr(rva, out line, out mi, out recRva);
            var bp = new UserBreakpoint
            {
                Module = resolved ? _dbg.ModuleNameForIdx(mi) : null,
                ModuleIdx = resolved ? mi : -1,
                RequestedLine = resolved ? line : 0,
                Line = resolved ? line : 0
            };
            bp.Rvas.Add(rva);
            _bps.Add(bp);
            if (_loadBase != 0) PlantBp(bp);
        }

        private void RemoveBreakpoint(string module, int line)
        {
            int mi = _dbg.FindModuleIdx(module);
            string canon = mi >= 0 ? (_dbg.ModuleNameForIdx(mi) ?? module) : module;
            UserBreakpoint found = null;
            foreach (var b in _bps)
                if (b.ModuleIdx == mi && (b.Line == line || b.RequestedLine == line)) { found = b; break; }
            if (found == null)
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(canon, line, "no such breakpoint"));
                return;
            }
            foreach (var rva in found.Rvas)
            {
                uint va = _loadBase + rva;
                byte orig;
                if (_loadBase != 0 && _armed.TryGetValue(va, out orig))
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
            _bps.Remove(found);
            Console.WriteLine($"bp: removed {canon}:{found.Line}");
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpDel(canon, found.Line));
        }

        private void PlantAll()
        {
            foreach (var bp in _bps) PlantBp(bp);
        }

        private void PlantBp(UserBreakpoint bp)
        {
            foreach (var rva in bp.Rvas)
            {
                uint va = _loadBase + rva;
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
            uint rva = va - _loadBase;

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

            ReportHit(rva, va, ref ctx, haveCtx);

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

        private void ReportHit(uint rva, uint va, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            Console.WriteLine();
            Console.WriteLine("*** BREAKPOINT HIT ***");
            Console.WriteLine($"  VA 0x{va:X}  (loadBase 0x{_loadBase:X} + RVA 0x{rva:X})");

            int line; int moduleIdx; uint recRva;
            bool resolved = _dbg.ResolveAddr(rva, out line, out moduleIdx, out recRva);
            string modName = resolved ? _dbg.ModuleNameForIdx(moduleIdx) : null;
            string proc = ProcNameAt(rva, resolved ? moduleIdx : -1);
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
                if (_mode != StepMode.None && haveCtx)
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

        // ------------------------------------------------------------------ single-step machine

        private uint OnSingleStep(uint tid)
        {
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);

            // 1) pending re-plant after THIS thread stepped off a restored breakpoint byte
            Rearm pr;
            if (_rearm.TryGetValue(tid, out pr))
            {
                bool stillWanted = pr.IsTemp ? _temp.ContainsKey(pr.Va) : _armed.ContainsKey(pr.Va);
                if (stillWanted) WriteByte(pr.Va, 0xCC);
                _rearm.Remove(tid);
            }

            // 2) drive the step machine (TF auto-clears on each trap; re-set it to keep stepping)
            if (_mode != StepMode.None && tid == _stepTid && !_skipRunning && haveCtx)
                StepMachine(tid, hThread, ref ctx);

            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        private void StepMachine(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx)
        {
            _stepCount++;
            uint va = ctx.Eip;
            uint rva = va - _loadBase;

            // call-entry detection: the stack top holds an address just past the previous trap →
            // we just stepped INTO a CALL. Follow Clarion callees (step-into); skip everything else
            // at full speed via a temp INT3 at the return address.
            if (_prevVa != 0)
            {
                uint ret = ReadU32(ctx.Esp);
                if (ret > _prevVa && ret - _prevVa <= CALL_WINDOW && ret != va)
                {
                    bool follow = _mode == StepMode.Into && HasRecordInRange(rva, PROLOGUE_WINDOW);
                    if (!follow)
                    {
                        bool covered = _armed.ContainsKey(ret); // a user BP there already pauses us
                        if (!covered)
                        {
                            byte orig;
                            if (!_temp.ContainsKey(ret) && ReadByte(ret, out orig))
                            {
                                WriteByte(ret, 0xCC);
                                _temp[ret] = orig;
                                covered = true;
                            }
                            else if (_temp.ContainsKey(ret))
                                covered = true;
                        }
                        if (covered)
                        {
                            _skipEntryEsp = ctx.Esp;
                            _skipRunning = true;
                            _prevVa = va;
                            return; // TF stays clear → full speed until the temp BP (or a user BP)
                        }
                        // couldn't plant — fall through and keep instruction-stepping
                    }
                }
            }

            // stop check: pause at the next statement boundary appropriate for the mode
            int line; int mi; uint recRva;
            bool resolved = _dbg.ResolveAddr(rva, out line, out mi, out recRva);
            uint gap = resolved ? rva - recRva : 0;
            bool atRecord = resolved && gap == 0;
            bool newStatement = atRecord && (line != _startLine || mi != _startModIdx);
            bool stop = false;
            switch (_mode)
            {
                case StepMode.Into:
                    stop = newStatement;
                    break;
                case StepMode.Over:
                    stop = newStatement && ctx.Esp + ESP_SLACK >= _startEsp;
                    break;
                case StepMode.Out:
                    stop = resolved && ctx.Esp > _startEsp && gap <= OUT_GAP_MAX;
                    break;
            }

            if (!stop && _stepCount >= MAX_STEPS)
            {
                Console.WriteLine($"  (step limit reached after {_stepCount} instructions — pausing here)");
                StopStepAndPause(tid, hThread, ref ctx, "step-limit");
                return;
            }
            if (stop)
            {
                StopStepAndPause(tid, hThread, ref ctx, "step");
                return;
            }

            // keep stepping
            _prevVa = va;
            ctx.EFlags |= TRAP_FLAG;
            Native.SetThreadContext(hThread, ref ctx);
        }

        private void StopStepAndPause(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, string reason)
        {
            CancelStep();
            uint va = ctx.Eip;
            byte orig;
            if (_armed.TryGetValue(va, out orig))
            {
                // landed exactly on a user breakpoint byte — restore it so the instruction can
                // execute on resume, and re-plant after one single-step
                WriteByte(va, orig);
                _rearm[tid] = new Rearm { Va = va, IsTemp = false };
            }
            PausedWait(tid, hThread, ref ctx, true, reason);
        }

        private void CancelStep()
        {
            _mode = StepMode.None;
            _skipRunning = false;
            foreach (var kv in _temp) WriteByte(kv.Key, kv.Value);
            _temp.Clear();
            // drop pending TEMP re-plants (their bytes were just restored); user-BP re-plants survive
            var drop = new List<uint>();
            foreach (var kv in _rearm) if (kv.Value.IsTemp) drop.Add(kv.Key);
            foreach (var t in drop) _rearm.Remove(t);
        }

        // ------------------------------------------------------------------ pause + command loop

        /// <summary>
        /// Blocks the debug loop (target fully suspended — the debug event is not continued) and
        /// services stdin commands until a resume-type command arrives.
        /// </summary>
        private void PausedWait(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx, string reason)
        {
            uint va = haveCtx ? ctx.Eip : 0;
            uint rva = va - _loadBase;
            int line = 0; int mi = -1; uint recRva = 0;
            bool resolved = haveCtx && _dbg.ResolveAddr(rva, out line, out mi, out recRva);
            if (!resolved) { line = 0; mi = -1; recRva = 0; }
            string mod = resolved ? _dbg.ModuleNameForIdx(mi) : null;
            string proc = haveCtx ? ProcNameAt(rva, resolved ? mi : -1) : null;
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
                        BeginStep(StepMode.Into, tid, ref ctx, haveCtx, resolved, line, mi);
                        EmitResumed("step");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepover": case "next": case "n":
                        BeginStep(StepMode.Over, tid, ref ctx, haveCtx, resolved, line, mi);
                        EmitResumed("stepover");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepout": case "out": case "finish": case "o":
                        BeginStep(StepMode.Out, tid, ref ctx, haveCtx, resolved, line, mi);
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

        private void BeginStep(StepMode mode, uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx, bool resolved, int line, int mi)
        {
            _mode = mode;
            _stepTid = tid;
            _startEsp = haveCtx ? ctx.Esp : 0;
            _startLine = resolved ? line : -1;
            _startModIdx = resolved ? mi : -1;
            _prevVa = haveCtx ? ctx.Eip : 0;
            _stepCount = 0;
            _skipRunning = false;
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
                    case "quit": case "q": case "kill":
                        if (_hProcess != IntPtr.Zero) Native.TerminateProcess(_hProcess, 0);
                        break;
                    case "continue": case "c": case "g":
                    case "step": case "stepinto": case "s": case "i":
                    case "stepover": case "next": case "n":
                    case "stepout": case "out": case "finish": case "o":
                    case "mem": case "regs": case "stack": case "bt": case "where": case "watch":
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
            TswdDebugInfo.DataLocation loc;
            if (!_dbg.ResolveDataName(name, out loc))
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.Sym(name, false, 0, 0, 0, null, 0, null));
                Console.WriteLine($"  sym {name}: not found");
                return;
            }
            uint va = _loadBase + loc.Rva;
            string tn = TswdDebugInfo.TypeCodeName(loc.TypeCode);
            if (EmitJson) Console.WriteLine("@JSON " + Json.Sym(name, true, loc.Rva, va, loc.TypeCode, tn, loc.Size, loc.Container));
            Console.WriteLine($"  sym {name}: VA 0x{va:X} (RVA 0x{loc.Rva:X}) {(tn ?? $"type 0x{loc.TypeCode:X2}")} size {loc.Size}{(loc.Container != null ? " in " + loc.Container : "")}");
        }

        // ------------------------------------------------------------------ watch (by name)

        /// <summary>
        /// watch NAME — resolve a data name and read its CURRENT value on the paused thread.
        /// Non-threaded data reads directly at template VA (returns false: stay paused).
        /// THREADed (.cwtls) data launches the THR$GetInstance func-eval (returns true: the
        /// caller must leave the pause loop so the target can run the call).
        /// </summary>
        private bool HandleWatchCommand(string[] parts, uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (parts.Length < 2) { EmitError("watch expects: watch NAME"); return false; }
            string name = parts[1];
            TswdDebugInfo.DataLocation loc;
            if (!_dbg.ResolveDataName(name, out loc))
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.Watch(name, false, 0, 0, false, 0, null, 0, null, 0));
                Console.WriteLine($"  watch {name}: not found");
                return false;
            }
            uint templateVa = _loadBase + loc.Rva;
            bool threaded = loc.Rva >= _cwtlsLo && loc.Rva < _cwtlsHi && _cwtlsHi != 0;

            if (!threaded)
            {
                EmitWatchValue(name, templateVa, templateVa, false, loc.TypeCode, loc.Size);
                return false;
            }

            if (_thrGetInstanceIatRva == 0)
            {
                EmitError($"watch {name}: THREADed data but THR$GetInstance import not found in this EXE");
                return false;
            }
            if (!haveCtx)
            {
                EmitError($"watch {name}: no thread context for func-eval");
                return false;
            }
            uint helper = ReadU32(_loadBase + _thrGetInstanceIatRva);
            if (helper == 0)
            {
                EmitError($"watch {name}: could not read THR$GetInstance address from the IAT");
                return false;
            }

            // stash what the completion handler needs to finish the read
            _evalName = name; _evalSize = loc.Size; _evalTypeCode = loc.TypeCode;
            _evalTypeName = TswdDebugInfo.TypeCodeName(loc.TypeCode);
            _evalTemplateVa = templateVa;

            // save the real context (deep copy — the struct holds array references)
            _evalSavedCtx = CloneContext(ref ctx);

            // suspend any pending breakpoint re-plant for this thread: the BP byte is currently
            // the ORIGINAL instruction, and the eval resume must not consume the re-arm step
            _evalHadRearm = _rearm.TryGetValue(tid, out _evalSavedRearm);
            if (_evalHadRearm) _rearm.Remove(tid);

            // hijack: EAX = template VA, EBX = .cwtls base, return lands on the magic trap
            var e = CloneContext(ref ctx);
            e.Esp = ctx.Esp - 4;
            WriteU32(e.Esp, EVAL_TRAP_VA);
            e.Eax = templateVa;
            e.Ebx = _loadBase + _cwtlsLo;
            e.Eip = helper;
            e.EFlags &= ~TRAP_FLAG;
            Native.SetThreadContext(hThread, ref e);

            _evalActive = true;
            _evalTid = tid;
            return true;   // leave PausedWait; the debug loop continues the event and the call runs
        }

        /// <summary>The func-eval returned (AV at the magic address): collect EAX = instance VA,
        /// restore the saved thread state, emit the watch value, and re-enter the pause loop.</summary>
        private uint OnEvalComplete(uint tid)
        {
            _evalActive = false;
            IntPtr hThread = OpenThreadForContext(tid);
            var c = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref c);
            uint instanceVa = haveCtx ? c.Eax : 0;

            // restore the genuine pause state (EIP/ESP/regs exactly as before the eval)
            if (hThread != IntPtr.Zero) Native.SetThreadContext(hThread, ref _evalSavedCtx);
            if (_evalHadRearm) { _rearm[tid] = _evalSavedRearm; _evalHadRearm = false; }

            if (instanceVa != 0)
                EmitWatchValue(_evalName, _evalTemplateVa, instanceVa, true, _evalTypeCode, _evalSize);
            else
                EmitError($"watch {_evalName}: THR$GetInstance eval failed");

            // we are logically still paused at the original location — resume the command loop
            PausedWait(tid, hThread, ref _evalSavedCtx, true, "watch");
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        /// <summary>Read and report a watch value (instanceVa = templateVa for non-threaded data).</summary>
        private void EmitWatchValue(string name, uint templateVa, uint instanceVa, bool threaded, byte typeCode, uint size)
        {
            int len = (int)Math.Min(Math.Max(size, 1), 4096);
            var buf = new byte[len];
            int read;
            Native.ReadProcessMemory(_hProcess, (IntPtr)instanceVa, buf, len, out read);
            if (read < 0) read = 0;
            string tn = TswdDebugInfo.TypeCodeName(typeCode);
            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Watch(name, true, templateVa, instanceVa, threaded, typeCode, tn, size, buf, read));
            Console.WriteLine($"  watch {name}: {(tn ?? $"type 0x{typeCode:X2}")} size {size} at 0x{instanceVa:X}{(threaded ? $" (threaded; template 0x{templateVa:X})" : "")}");
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

        // ------------------------------------------------------------------ call stack

        private const int STACK_SCAN_BYTES = 0x4000;   // how far up from ESP to scan for return addrs
        private const uint FRAME_GAP_MAX = 0x800;      // max distance past a line record for a code addr
        private const int STACK_FRAMES_DEFAULT = 32;
        private const int STACK_FRAMES_MAX = 256;

        /// <summary>stack [maxFrames] — resolved call stack while paused (frame 0 = current EIP).</summary>
        private void HandleStackCommand(string[] parts, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (!haveCtx) { EmitError("stack: no thread context"); return; }
            int max = STACK_FRAMES_DEFAULT;
            if (parts.Length > 1 && (!int.TryParse(parts[1], out max) || max < 1 || max > STACK_FRAMES_MAX))
            {
                EmitError($"stack: max frames must be 1..{STACK_FRAMES_MAX}");
                return;
            }
            var frames = BuildStack(ctx.Eip, ctx.Esp, max);
            if (EmitJson) Console.WriteLine("@JSON " + Json.Stack(frames));
            Console.WriteLine($"  stack ({frames.Count} frame(s)):");
            for (int i = 0; i < frames.Count; i++)
            {
                var f = frames[i];
                string name = f.Proc ?? "(unknown)";
                string loc = f.Module != null ? $"  {f.Module}:{f.Line}" : "";
                Console.WriteLine($"    #{i,-2} {name}{loc}  RVA 0x{f.Rva:X}{(f.Kind != null ? "  [" + f.Kind + "]" : "")}");
            }
        }

        /// <summary>
        /// Build the call stack WITHOUT an EBP walk (Clarion frames don't reliably chain EBP — even
        /// the native debugger shows Unknown frames). Frame 0 is the current EIP; the rest come from
        /// scanning the stack upward from ESP for plausible return addresses: a dword is a frame iff
        /// (a) it resolves into TSWD-mapped code (a +0x1C record within FRAME_GAP_MAX) and
        /// (b) the bytes immediately before it form a CALL instruction (call-precedes heuristic).
        /// Scan-based stacks can include stale frames from dead stack regions — acceptable noise,
        /// matching the entryRVA-range-binding plan (NOT EBP).
        /// </summary>
        private List<StackFrame> BuildStack(uint eip, uint esp, int maxFrames)
        {
            var frames = new List<StackFrame> { FrameAt(eip - _loadBase, eip, 0) };

            var stack = new byte[STACK_SCAN_BYTES];
            int got = ReadBlock(esp, stack);
            for (int off = 0; off + 4 <= got && frames.Count < maxFrames; off += 4)
            {
                uint cand = BitConverter.ToUInt32(stack, off);
                if (cand <= _loadBase) continue;
                uint rva = cand - _loadBase;

                int line; int mi; uint recRva;
                if (!_dbg.ResolveAddr(rva, out line, out mi, out recRva)) continue;
                if (rva - recRva > FRAME_GAP_MAX) continue;     // not Clarion-mapped code
                if (!CallPrecedes(cand)) continue;              // not a return address

                frames.Add(FrameAt(rva, cand, esp + (uint)off));
            }
            return frames;
        }

        private StackFrame FrameAt(uint rva, uint va, uint stackAddr)
        {
            int line; int mi; uint recRva;
            bool resolved = _dbg.ResolveAddr(rva, out line, out mi, out recRva);
            ProcSymbol sym;
            bool hasSym = _dbg.ResolveSymbol(rva, out sym);
            // same moduleIdx cross-check as ProcNameAt: don't name cold/init code with the
            // previous module's last symbol
            bool symOk = hasSym && (!resolved || sym.ModuleIdx == mi);
            return new StackFrame
            {
                Rva = rva,
                Va = va,
                StackAddr = stackAddr,
                Proc = symOk ? sym.Name : null,
                Kind = symOk ? sym.Kind.ToString().ToLowerInvariant() : null,
                Module = resolved ? _dbg.ModuleNameForIdx(mi) : null,
                Line = resolved ? line : 0
            };
        }

        /// <summary>
        /// Do the bytes immediately before a candidate return address form a CALL instruction?
        /// Checks the x86 encodings by length: E8 rel32 (5), FF /2 reg-or-[reg] (2), FF /2 disp8 or
        /// SIB (3), FF /2 disp32 or [mem] (6), FF /2 SIB+disp32 (7), 9A far (7). No decoder needed —
        /// combined with the TSWD-resolvability gate this filters nearly all stale stack noise.
        /// </summary>
        private bool CallPrecedes(uint va)
        {
            if (va < 8) return false;
            var b = new byte[8];                      // b[i] = byte at va-8+i, so byte at va-k is b[8-k]
            int read;
            if (!Native.ReadProcessMemory(_hProcess, (IntPtr)(va - 8), b, 8, out read) || read != 8)
                return false;
            if (b[3] == 0xE8) return true;                                  // call rel32
            if (b[6] == 0xFF && (b[7] & 0x38) == 0x10) return true;         // call reg / [reg]
            if (b[5] == 0xFF && ((b[6] & 0xF8) == 0x50 || b[6] == 0x14)) return true;  // disp8 / SIB
            if (b[2] == 0xFF && ((b[3] & 0xF8) == 0x90 || b[3] == 0x15)) return true;  // disp32 / [mem]
            if (b[1] == 0xFF && b[2] == 0x94) return true;                  // SIB + disp32
            if (b[1] == 0x9A) return true;                                  // far call ptr16:32
            return false;
        }

        /// <summary>Read up to buf.Length bytes at va, page-by-page so a guard page or the stack top
        /// truncates the read instead of failing it entirely. Returns bytes actually read.</summary>
        private int ReadBlock(uint va, byte[] buf)
        {
            int total = 0;
            while (total < buf.Length)
            {
                int chunk = Math.Min(0x1000 - (int)((va + (uint)total) & 0xFFF), buf.Length - total);
                var page = new byte[chunk];
                int read;
                if (!Native.ReadProcessMemory(_hProcess, (IntPtr)(va + (uint)total), page, chunk, out read) || read <= 0)
                    break;
                Array.Copy(page, 0, buf, total, read);
                total += read;
                if (read < chunk) break;
            }
            return total;
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
        private string ProcNameAt(uint rva, int moduleIdx)
        {
            ProcSymbol sym;
            if (!_dbg.ResolveSymbol(rva, out sym)) return null;
            if (moduleIdx >= 0 && sym.ModuleIdx != moduleIdx) return null;
            return sym.Name;
        }

        /// <summary>Is there a line record in [rva, rva+window]? (Used to spot Clarion callees.)</summary>
        private bool HasRecordInRange(uint rva, uint window)
        {
            var t = _dbg.AddrTable;
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

        // --- DEBUG_EVENT header accessors (first 12 bytes) ---
        private static uint Code(byte[] b) { return U32(b, 0); }
        private static uint Pid(byte[] b) { return U32(b, 4); }
        private static uint Tid(byte[] b) { return U32(b, 8); }
        private static uint U32(byte[] b, int off) { return BitConverter.ToUInt32(b, off); }
    }
}
