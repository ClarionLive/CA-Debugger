using System;
using System.Collections.Generic;
using System.IO;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// Minimal x86 debug engine: launches a target under the Windows debug API, plants INT3
    /// breakpoints at chosen RVAs, pumps the debug-event loop, and on a hit reads the thread
    /// context and resolves the address to a module + source line via TSWD info.
    /// </summary>
    internal sealed class DebugEngine
    {
        private readonly string _exe;
        private readonly TswdDebugInfo _dbg;
        private readonly bool _once;
        private readonly int _waitMs;

        /// <summary>When true, emit one machine-readable JSON object per event (for the IDE addin).</summary>
        public bool EmitJson;

        private IntPtr _hProcess = IntPtr.Zero;
        private uint _imageBase;             // PE preferred base (for RVA reporting)
        private uint _loadBase;              // actual load base from CREATE_PROCESS event
        private readonly List<uint> _bpRvas;
        // absolute address -> original byte, for planted breakpoints
        private readonly Dictionary<uint, byte> _planted = new Dictionary<uint, byte>();
        private bool _seenInitialBreak;
        public int Hits { get; private set; }

        public DebugEngine(string exe, TswdDebugInfo dbg, uint imageBase, List<uint> bpRvas, bool once, int waitMs)
        {
            _exe = exe; _dbg = dbg; _imageBase = imageBase; _bpRvas = bpRvas; _once = once; _waitMs = waitMs;
        }

        public int Run()
        {
            var si = new Native.STARTUPINFO();
            si.cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(si);
            Native.PROCESS_INFORMATION pi;

            string workDir = Path.GetDirectoryName(Path.GetFullPath(_exe));
            bool ok = Native.CreateProcess(_exe, null, IntPtr.Zero, IntPtr.Zero, false,
                Native.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, workDir, ref si, out pi);
            if (!ok)
                throw new InvalidOperationException("CreateProcess failed, win32 error " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());

            Console.WriteLine($"launched {Path.GetFileName(_exe)} (pid {pi.dwProcessId}); breakpoints at {_bpRvas.Count} RVA(s)");
            _hProcess = pi.hProcess;

            var buf = new byte[1024];
            bool running = true;
            while (running)
            {
                if (!Native.WaitForDebugEvent(buf, (uint)_waitMs))
                {
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
                        PlantBreakpoints();
                        Console.WriteLine($"process created: loadBase=0x{_loadBase:X} (preferred 0x{_imageBase:X}){(_loadBase != _imageBase ? "  [relocated]" : "")}");
                        break;

                    case Native.EXCEPTION_DEBUG_EVENT:
                        // union @+12: EXCEPTION_RECORD: code(+12) flags(+16) recPtr(+20) addr(+24); firstChance after record
                        uint exCode = U32(buf, 12);
                        uint exAddr = U32(buf, 24);
                        if (exCode == Native.EXCEPTION_BREAKPOINT)
                        {
                            if (_planted.ContainsKey(exAddr))
                                status = OnBreakpointHit(pid, tid, exAddr, ref running);
                            else if (!_seenInitialBreak)
                            {
                                _seenInitialBreak = true; // OS loader breakpoint — swallow it
                                status = Native.DBG_CONTINUE;
                            }
                            else status = Native.DBG_CONTINUE;
                        }
                        else
                        {
                            // pass first-chance non-breakpoint exceptions back to the app
                            status = Native.DBG_EXCEPTION_NOT_HANDLED;
                        }
                        break;

                    case Native.EXIT_PROCESS_DEBUG_EVENT:
                        Console.WriteLine($"process exited (code {U32(buf, 12)})");
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

        private void PlantBreakpoints()
        {
            foreach (var rva in _bpRvas)
            {
                uint addr = _loadBase + rva;
                var orig = new byte[1];
                int read;
                if (!Native.ReadProcessMemory(_hProcess, (IntPtr)addr, orig, 1, out read) || read != 1)
                {
                    Console.WriteLine($"  WARN: could not read memory at 0x{addr:X} (RVA 0x{rva:X}) — breakpoint skipped");
                    continue;
                }
                int wrote;
                Native.WriteProcessMemory(_hProcess, (IntPtr)addr, new byte[] { 0xCC }, 1, out wrote);
                Native.FlushInstructionCache(_hProcess, (IntPtr)addr, (IntPtr)1);
                _planted[addr] = orig[0];
            }
        }

        private uint OnBreakpointHit(uint pid, uint tid, uint addr, ref bool running)
        {
            Hits++;
            uint rva = addr - _loadBase;

            Console.WriteLine();
            Console.WriteLine("*** BREAKPOINT HIT ***");
            Console.WriteLine($"  VA 0x{addr:X}  (loadBase 0x{_loadBase:X} + RVA 0x{rva:X})");

            // v2: resolve via the clean +0x1C table (rva -> {line, moduleIdx}); .clw name = names[moduleIdx].
            int line; int moduleIdx; uint recRva;
            bool resolved = _dbg.ResolveAddr(rva, out line, out moduleIdx, out recRva);
            string modName = resolved ? _dbg.ModuleNameForIdx(moduleIdx) : null;
            uint gap = resolved ? rva - recRva : 0;
            if (resolved)
            {
                if (gap == 0)
                    Console.WriteLine($"  -> {modName} line {line}   (exact line record)");
                else if (gap <= 64)
                    Console.WriteLine($"  -> {modName} line {line}   (in statement, +0x{gap:X} into its code)");
                else
                    Console.WriteLine($"  -> nearest line: {modName} line {line} (+0x{gap:X} away — likely startup/library code with no Clarion line)");
            }
            else
                Console.WriteLine("  -> (no source line for this address)");

            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Hit(modName, line, rva, addr, gap, resolved));

            // read & report the thread context
            var ctx = NewContext();
            IntPtr hThread = OpenThreadForContext(tid);
            // We don't have a thread handle directly from the buffer for EXCEPTION events, so re-open.
            if (hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx))
            {
                Console.WriteLine($"  EAX={ctx.Eax:X8} EBX={ctx.Ebx:X8} ECX={ctx.Ecx:X8} EDX={ctx.Edx:X8}");
                Console.WriteLine($"  ESI={ctx.Esi:X8} EDI={ctx.Edi:X8} EBP={ctx.Ebp:X8} ESP={ctx.Esp:X8}");
                Console.WriteLine($"  EIP={ctx.Eip:X8} EFLAGS={ctx.EFlags:X8}");

                // un-patch: restore original byte and back EIP up over the INT3 so execution resumes correctly
                byte orig = _planted[addr];
                int wrote;
                Native.WriteProcessMemory(_hProcess, (IntPtr)addr, new byte[] { orig }, 1, out wrote);
                Native.FlushInstructionCache(_hProcess, (IntPtr)addr, (IntPtr)1);
                ctx.Eip = addr; // EIP was addr+1 after the 0xCC
                Native.SetThreadContext(hThread, ref ctx);
                _planted.Remove(addr); // one-shot
                Native.CloseHandle(hThread);
            }
            else
            {
                Console.WriteLine("  (could not read thread context)");
            }

            if (_once)
            {
                Console.WriteLine("  --once: terminating target after first hit.");
                Native.TerminateProcess(_hProcess, 0);
            }
            return Native.DBG_CONTINUE;
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
