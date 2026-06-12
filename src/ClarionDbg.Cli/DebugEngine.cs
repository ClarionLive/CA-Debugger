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
    internal sealed class DebugEngine
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

        // ------------------------------------------------------------------ module table

        /// <summary>Add a module entry from an already-parsed PE/TSWD (the EXE, or a pre-loaded
        /// solution DLL). LoadBase is filled in later when the image maps.</summary>
        private LoadedModule RegisterImageFromPe(string path, PeImage pe, TswdDebugInfo dbg)
        {
            var m = new LoadedModule
            {
                Path = path,
                Name = (System.IO.Path.GetFileName(path) ?? path).ToLowerInvariant(),
                Pe = pe,
                Dbg = dbg,
                Size = pe != null ? pe.SizeOfImage : 0,
            };
            m.ResolveThreadedInfo();
            _modules.Add(m);
            return m;
        }

        /// <summary>Pre-parse a solution DLL off disk so its breakpoints resolve before launch.
        /// Failures are non-fatal (the DLL may be rebuilt/absent); it will re-parse at LOAD_DLL.</summary>
        private void TryPreloadSolutionDll(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path)) return;
                string name = System.IO.Path.GetFileName(path).ToLowerInvariant();
                foreach (var m in _modules) if (m.Name == name) return; // already known
                var pe = PeImage.Load(path);
                var dbg = TswdDebugInfo.TryFromPe(pe);
                RegisterImageFromPe(path, pe, dbg);
            }
            catch { /* best-effort pre-load */ }
        }

        /// <summary>The mapped module whose [LoadBase, LoadBase+Size) contains <paramref name="va"/>,
        /// or null. Only mapped modules (LoadBase != 0) are candidates.</summary>
        private LoadedModule ModuleAt(uint va)
        {
            foreach (var m in _modules)
                if (m.LoadBase != 0 && m.ContainsVa(va)) return m;
            return null;
        }

        /// <summary>The mapped, debuggable module that owns a TSWD compiland by name (e.g. clbrws011.clw),
        /// or null when no loaded image carries it yet (deferred breakpoint).</summary>
        private LoadedModule OwnerOfModule(string clwName)
        {
            foreach (var m in _modules)
                if (m.HasDebug && m.Dbg.FindModuleIdx(clwName) >= 0) return m;
            return null;
        }

        /// <summary>Resolve a live VA to its owning module + source line via that image's TSWD.
        /// Returns false when no mapped module owns it or the owner carries no debug info.</summary>
        private bool ResolveVa(uint va, out LoadedModule m, out int line, out int moduleIdx, out uint recRva)
        {
            line = 0; moduleIdx = -1; recRva = 0;
            m = ModuleAt(va);
            if (m == null || m.Dbg == null) return false;
            return m.Dbg.ResolveAddr(va - m.LoadBase, out line, out moduleIdx, out recRva);
        }

        /// <summary>Resolve a data name (global / record buffer / field) across all debuggable images,
        /// preferring the EXE. Returns the owning image so the caller can form a live VA + threaded
        /// eval against the right .cwtls/THR$GetInstance.</summary>
        private bool ResolveDataAcrossModules(string name, out LoadedModule owner, out TswdDebugInfo.DataLocation loc)
        {
            loc = default(TswdDebugInfo.DataLocation);
            owner = null;
            if (_exe != null && _exe.Dbg != null && _exe.Dbg.ResolveDataName(name, out loc)) { owner = _exe; return true; }
            foreach (var m in _modules)
            {
                if (m == _exe || m.Dbg == null) continue;
                if (m.Dbg.ResolveDataName(name, out loc)) { owner = m; return true; }
            }
            return false;
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

                    // CREATE_THREAD / EXIT_THREAD / OUTPUT_DEBUG_STRING / RIP: just continue
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
            // adding an existing planted line is a no-op (re-confirm so the UI can sync)
            foreach (var b in _bps)
                if (b.Owner == owner && b.ModuleIdx == mi && b.Line == planted)
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
            foreach (var b in _bps)
                if (Eq(b.Module, module) && (b.Line == line || b.RequestedLine == line)) { found = b; break; }
            string canon = found != null ? found.Module : module;
            if (found == null)
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpError(canon, line, "no such breakpoint"));
                return;
            }
            uint baseVa = found.Owner != null ? found.Owner.LoadBase : 0;
            foreach (var rva in found.Rvas)
            {
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
            _bps.Remove(found);
            Console.WriteLine($"bp: removed {canon}:{found.Line}");
            if (EmitJson) Console.WriteLine("@JSON " + Json.BpDel(canon, found.Line));
        }

        /// <summary>Plant every breakpoint whose owning image is mapped (LoadBase set).</summary>
        /// <summary>A DLL mapped into the target. Resolve its path (via the file handle), parse its
        /// TSWD off disk (or reuse a pre-loaded solution entry), set its live base, and arm any
        /// breakpoints it owns. Tier 3 (no TSWD) is still registered for correct VA attribution.</summary>
        private void OnDllLoaded(uint hFile, uint baseVa)
        {
            try
            {
                string path = GetPathFromHandle(hFile);
                string name = !string.IsNullOrEmpty(path)
                    ? System.IO.Path.GetFileName(path).ToLowerInvariant()
                    : $"(0x{baseVa:x})";

                // reuse a pre-loaded solution DLL entry (already has Pe/Dbg parsed) if names match
                LoadedModule m = null;
                foreach (var im in _modules)
                    if (im.LoadBase == 0 && im.Name == name) { m = im; break; }

                if (m != null)
                {
                    m.LoadBase = baseVa;
                    if (m.Path == null && path != null) m.Path = path;
                }
                else
                {
                    PeImage pe = null; TswdDebugInfo dbg = null;
                    if (!string.IsNullOrEmpty(path) && System.IO.File.Exists(path))
                    {
                        try { pe = PeImage.Load(path); dbg = TswdDebugInfo.TryFromPe(pe); } catch { pe = null; dbg = null; }
                    }
                    m = new LoadedModule { Path = path, Name = name, Pe = pe, Dbg = dbg };
                    m.ResolveThreadedInfo();
                    m.Size = pe != null ? pe.SizeOfImage : ReadRemoteSizeOfImage(baseVa);
                    m.LoadBase = baseVa;
                    _modules.Add(m);
                }
                if (m.Size == 0) m.Size = ReadRemoteSizeOfImage(baseVa);

                PlantOwnBps(m);          // bps already bound to this image (pre-loaded solution DLL)
                ResolvePendingFor(m);    // pending bps whose compiland this image carries
                if (EmitJson) Console.WriteLine("@JSON " + Json.ModuleLoaded(m));
            }
            finally
            {
                CloseHandleValue(hFile);
            }
        }

        /// <summary>A DLL unmapped: drop its armed bytes, return its breakpoints to pending, and
        /// remove it from the table so stale addresses no longer attribute to it.</summary>
        private void OnDllUnloaded(uint baseVa)
        {
            LoadedModule m = null;
            foreach (var im in _modules) if (im.LoadBase == baseVa && im != _exe) { m = im; break; }
            if (m == null) return;

            foreach (var bp in _bps)
            {
                if (bp.Owner != m) continue;
                foreach (var rva in bp.Rvas) _armed.Remove(bp.Owner.LoadBase + rva);
                bp.Owner = null;          // back to pending; re-arms if the DLL reloads
                bp.ModuleIdx = -1;
            }
            if (EmitJson) Console.WriteLine("@JSON " + Json.ModuleUnloaded(m));

            // Keep the pre-loaded solution entry (Pe/Dbg) around but mark it unmapped; drop runtime-only.
            bool preloaded = m.Pe != null && IsSolutionPreloaded(m);
            if (preloaded) m.LoadBase = 0;
            else _modules.Remove(m);
        }

        private bool IsSolutionPreloaded(LoadedModule m)
        {
            // A solution DLL was registered at construction; runtime-discovered DLLs were added later.
            // We treat any module with parsed Dbg whose path we still hold as reusable on reload.
            return m.Path != null && System.IO.File.Exists(m.Path);
        }

        /// <summary>Read SizeOfImage straight from the target's mapped PE header (fallback when the
        /// DLL path/file is unavailable), so VA attribution still has a valid module span.</summary>
        private uint ReadRemoteSizeOfImage(uint baseVa)
        {
            uint eLfanew = ReadU32(baseVa + 0x3C);
            if (eLfanew == 0 || eLfanew > 0x1000) return 0x10000; // sane floor if the header looks odd
            uint optOff = baseVa + eLfanew + 24;
            uint size = ReadU32(optOff + 56);
            return size != 0 ? size : 0x10000;
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
            var m = ModuleAt(va);
            uint rva = m != null ? va - m.LoadBase : va;

            // call-entry detection: the stack top holds an address just past the previous trap →
            // we just stepped INTO a CALL. Follow Clarion callees (step-into); skip everything else
            // at full speed via a temp INT3 at the return address.
            if (_prevVa != 0)
            {
                uint ret = ReadU32(ctx.Esp);
                if (ret > _prevVa && ret - _prevVa <= CALL_WINDOW && ret != va)
                {
                    bool follow = _mode == StepMode.Into && HasRecordInRange(m, rva, PROLOGUE_WINDOW);
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
            int line = 0, mi = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            uint gap = resolved ? rva - recRva : 0;
            bool atRecord = resolved && gap == 0;
            bool newStatement = atRecord && (m != _startModule || line != _startLine || mi != _startModIdx);
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

        private void BeginStep(StepMode mode, uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx, bool resolved, int line, int mi, LoadedModule m)
        {
            _mode = mode;
            _stepTid = tid;
            _startEsp = haveCtx ? ctx.Esp : 0;
            _startLine = resolved ? line : -1;
            _startModIdx = resolved ? mi : -1;
            _startModule = m;
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
            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            if (!ResolveDataAcrossModules(name, out owner, out loc))
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.Watch(name, false, 0, 0, false, 0, null, 0, null, 0));
                Console.WriteLine($"  watch {name}: not found");
                return false;
            }
            uint templateVa = owner.LoadBase + loc.Rva;
            bool threaded = loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi && owner.CwtlsHi != 0;

            if (!threaded)
            {
                EmitWatchValue(name, templateVa, templateVa, false, loc.TypeCode, loc.Size);
                return false;
            }

            if (owner.ThrGetInstanceIatRva == 0)
            {
                EmitError($"watch {name}: THREADed data but THR$GetInstance import not found in {owner.Name}");
                return false;
            }
            if (!haveCtx)
            {
                EmitError($"watch {name}: no thread context for func-eval");
                return false;
            }
            uint helper = ReadU32(owner.LoadBase + owner.ThrGetInstanceIatRva);
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
            e.Ebx = owner.LoadBase + owner.CwtlsLo;
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
            var frames = BuildStack(ctx.Eip, ctx.Esp, ctx.Ebp, max);
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
        /// Build the call stack. Frame 0 is the current EIP. Primary walk follows the EBP frame chain:
        /// Clarion's generated procedures and ABC methods set up standard {push ebp; mov ebp,esp}
        /// frames, so [ebp] = caller EBP and [ebp+4] = return address. This yields the TRUE caller
        /// links across all images (EXE/DLL/runtime) and terminates naturally when a return address
        /// leaves debuggable code (into the C runtime / OS) — so it does NOT manufacture the stale
        /// frames an unconstrained stack scan pulls from dead stack memory (which also made the stack
        /// differ run-to-run). Each link is still validated (mapped code within FRAME_GAP_MAX + a CALL
        /// precedes the return) so a corrupt/FPO frame breaks the chain cleanly rather than lying.
        ///
        /// Fallback: if the chain yields no caller (e.g. paused before the current frame's prologue
        /// ran, or an FPO leaf at the top), scan the stack for plausible return addresses — the legacy
        /// behaviour, which over-includes but never returns an empty stack.
        /// </summary>
        private List<StackFrame> BuildStack(uint eip, uint esp, uint ebp, int maxFrames)
        {
            var m0 = ModuleAt(eip);
            var frames = new List<StackFrame> { FrameAt(m0, eip, 0) };

            // Entry-prologue case: if EIP is exactly at the current procedure's entry, its
            // {push ebp; mov ebp,esp} has not run yet — EBP still belongs to the CALLER and the
            // caller's return address sits at [ESP]. Emit that direct caller first; the EBP chain
            // below (which begins at the caller's frame) then covers the rest without duplication.
            if (AtProcEntry(m0, eip))
            {
                StackFrame f0;
                if (TryFrameForReturn(ReadU32(esp), esp, out f0)) frames.Add(f0);
            }

            uint cur = ebp;
            uint floor = esp;        // frame bases sit at/above ESP and strictly increase up the stack
            bool first = true;
            while (frames.Count < maxFrames && cur != 0 && (first ? cur >= floor : cur > floor))
            {
                StackFrame f;
                if (!TryFrameForReturn(ReadU32(cur + 4), cur + 4, out f)) break; // chain end / corrupt
                frames.Add(f);
                floor = cur;
                cur = ReadU32(cur);  // caller's saved EBP
                first = false;
            }

            if (frames.Count < 2) ScanStack(frames, esp, maxFrames);
            return frames;
        }

        /// <summary>True when <paramref name="va"/> is exactly the entry of its containing procedure
        /// (prologue not yet run, so the frame's EBP is still the caller's).</summary>
        private bool AtProcEntry(LoadedModule m, uint va)
        {
            if (m == null || m.Dbg == null) return false;
            ProcSymbol sym;
            uint rva = va - m.LoadBase;
            return m.Dbg.ResolveSymbol(rva, out sym) && rva == sym.EntryRva;
        }

        /// <summary>Validate a candidate return address (mapped Clarion code within FRAME_GAP_MAX,
        /// preceded by a CALL) and build its frame. False when it isn't a real return address.</summary>
        private bool TryFrameForReturn(uint ret, uint stackAddr, out StackFrame frame)
        {
            frame = null;
            var rm = ModuleAt(ret);
            if (rm == null || rm.Dbg == null) return false;     // left debuggable code
            uint rrva = ret - rm.LoadBase;
            int line; int mi; uint recRva;
            if (!rm.Dbg.ResolveAddr(rrva, out line, out mi, out recRva)) return false;
            if (rrva - recRva > FRAME_GAP_MAX) return false;    // not Clarion-mapped code
            if (!CallPrecedes(ret)) return false;              // not a return address
            frame = FrameAt(rm, ret, stackAddr);
            return true;
        }

        /// <summary>Fallback stack reconstruction: scan upward from ESP for dwords that resolve into
        /// TSWD-mapped code (a +0x1C record within FRAME_GAP_MAX) preceded by a CALL. Over-includes
        /// stale frames from dead stack regions — used only when the EBP chain yields nothing.</summary>
        private void ScanStack(List<StackFrame> frames, uint esp, int maxFrames)
        {
            var stack = new byte[STACK_SCAN_BYTES];
            int got = ReadBlock(esp, stack);
            for (int off = 0; off + 4 <= got && frames.Count < maxFrames; off += 4)
            {
                uint cand = BitConverter.ToUInt32(stack, off);
                var cm = ModuleAt(cand);
                if (cm == null || cm.Dbg == null) continue;     // not in any debuggable image
                uint rva = cand - cm.LoadBase;

                int line; int mi; uint recRva;
                if (!cm.Dbg.ResolveAddr(rva, out line, out mi, out recRva)) continue;
                if (rva - recRva > FRAME_GAP_MAX) continue;     // not Clarion-mapped code
                if (!CallPrecedes(cand)) continue;              // not a return address

                frames.Add(FrameAt(cm, cand, esp + (uint)off));
            }
        }

        private StackFrame FrameAt(LoadedModule m, uint va, uint stackAddr)
        {
            uint rva = m != null ? va - m.LoadBase : va;
            int line = 0, mi = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            ProcSymbol sym = null;
            bool hasSym = m != null && m.Dbg != null && m.Dbg.ResolveSymbol(rva, out sym);
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
                Module = resolved ? m.Dbg.ModuleNameForIdx(mi) : null,
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
