using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// Attach to a running process and detach from it again (ticket 3f2d747f part A). The design, with its
    /// sources, is task report 0120762b on that ticket; the short form is here, next to the code.
    ///
    /// ATTACH is DebugActiveProcess plus DebugSetProcessKillOnExit(FALSE). The debug loop is the launch loop:
    /// Windows replays the process as a synthetic CREATE_PROCESS, a CREATE_THREAD per thread and a LOAD_DLL per
    /// module, then an injected thread executes the attach breakpoint, which the loop already swallows as the
    /// initial break.
    ///
    /// DETACH runs in the debug loop, on whatever event it holds, because while ANY event is held the whole
    /// process is frozen. `detach` while paused returns from PausedWait and the loop detaches on the event that
    /// paused; `detach` while running injects a break and the loop detaches on the FIRST event to arrive, which
    /// may be that break or anything else. Order, all but the last three steps while frozen:
    ///   restore every planted byte (temp and user), drop the re-arms, clear TF on every thread, drop the setip
    ///   observations and the hover mode, CONTINUE the held event, DRAIN what is already queued, then stop.
    ///
    /// WHY THE DRAIN. Microsoft documents nothing about events still queued at DebugActiveProcessStop. The
    /// evidence (ReactOS DbgkClearProcessDebugObject; LLVM PR #115712, merged 2024-11-15) is that the kernel
    /// completes each of them as "the debugger did not handle it", so the exception goes to the app. A thread
    /// that hit one of our INT3s before the freeze would then take EXCEPTION_BREAKPOINT with EIP one byte into
    /// an instruction: crash, or resume mid-instruction. Draining answers those as a debugger would - rewind
    /// EIP, continue - before letting go. Once the bytes are back and TF is clear, nothing WE did can raise a
    /// new event, so anything arriving after the drain is an event the app would have had without a debugger.
    /// UNSETTLED (dated 2026-09-23): an exception already inside the kernel's dispatch at the freeze can queue
    /// after the drain window; nothing found bounds that.
    /// </summary>
    internal sealed partial class DebugEngine
    {
        // The pid to attach to, or 0 for a launch. Set once, by the constructor.
        private uint _attachPid;
        private bool IsAttach { get { return _attachPid != 0; } }

        // `detach` (or `quit` / stdin close in attach mode) was asked for; the debug loop acts on it at the next
        // event it holds. See the class note.
        private bool _detachPending;

        /// <summary>True when DebugActiveProcess refused; the attach verb exits 2.</summary>
        public bool AttachFailed { get; private set; }

        /// <summary>The drain's bounds: one wait, and the caps on the whole drain so a noisy app cannot keep
        /// the engine answering events forever.</summary>
        internal const uint DetachDrainWaitMs = 100;
        internal const int DetachDrainCapMs = 2000;
        internal const int DetachDrainCapEvents = 200;

        // protocolcheck's view of the teardown ORDER, and a step to throw at (the aborted-detach case). Both null
        // in a real session.
        private List<string> _detachTrace;
        private string _detachThrowAt;
        private void DetachStep(string name)
        {
            if (_detachTrace != null) _detachTrace.Add(name);
            if (_detachThrowAt == name) throw new InvalidOperationException("planted fault at " + name);
        }

        // The detach's debug-API calls, as delegates so protocolcheck can feed the DRAIN a queue of events and
        // see how each one is answered. In a real session they are exactly the Win32 functions. The live suite
        // cannot reproduce the race the drain exists for (tools\test-attach.ps1 says why), so this is the only
        // place the drain's answers are checked against events it actually has to answer.
        private Func<byte[], uint, bool> _detachWait = Native.WaitForDebugEvent;
        private Func<uint, uint, uint, bool> _detachContinue = Native.ContinueDebugEvent;

        // The two thread-context operations the detach and a stale hit depend on, each answering whether it
        // WORKED (4b run 2, Codex HIGH: they used to fail silently, and a thread left with TF set, or a queued
        // INT3 whose EIP was not rewound, was continued while `detached` reported no error). Null = the real call.
        private Func<uint, uint, bool> _setEipHook;
        private Func<uint, bool> _clearTfHook;
        private bool SetEip(uint tid, uint eip) { return _setEipHook != null ? _setEipHook(tid, eip) : SetThreadEip(tid, eip); }
        private bool ClearTf(uint tid) { return _clearTfHook != null ? _clearTfHook(tid) : ClearThreadTrapFlag(tid); }

        // EVERY address this session ever planted an INT3 at, for as long as the image that holds it is mapped
        // (4b run 2, MEDIUM). _armed and _temp say what is planted NOW; a byte removed while the target was frozen
        // (bp del while paused, run-to-cursor cleanup, a temp CancelStep restored) can still have another thread's
        // hit on it QUEUED, and that hit is ours: rewind EIP and continue, never hand it back at va+1. A VA whose
        // original byte was itself 0xCC is left out - a hit there is the app's own.
        private readonly HashSet<uint> _plantedEver = new HashSet<uint>();
        private void NotePlanted(uint va, byte original) { if (original != 0xCC) _plantedEver.Add(va); }
        private void ForgetPlantedIn(uint lo, uint size) { _plantedEver.RemoveWhere(va => va >= lo && va - lo < size); }

        /// <summary>A breakpoint at <paramref name="va"/> that we planted once and no longer have planted, whose
        /// byte is not an INT3 now: a hit that was queued before we removed the byte. Unreadable counts as ours,
        /// since we did plant there.</summary>
        private bool IsStaleHitOfOurs(uint va)
        {
            if (!_plantedEver.Contains(va) || _armed.ContainsKey(va) || _temp.ContainsKey(va)) return false;
            byte now;
            return !(ReadByte(va, out now) && now == 0xCC);
        }

        /// <summary>The debug loop met a stale hit of ours (<see cref="IsStaleHitOfOurs"/>): put the thread back on
        /// the instruction the INT3 replaced and let it run. Before this, the loop took it for a programmatic
        /// break and paused at va+1, mid-instruction - in LAUNCH mode as much as attach.</summary>
        private uint OnStaleHit(uint tid, uint va)
        {
            if (SetEip(tid, va))
                Console.WriteLine($"  (a hit on 0x{va:X} was queued before its breakpoint was removed; resumed at the instruction)");
            else
                EmitError($"a hit on 0x{va:X} was queued before its breakpoint was removed, and EIP could not be put back on thread {TidText(tid)}; the thread may fault");
            return Native.DBG_CONTINUE;
        }

        // `attach --expect-start <decimal>`: the creation FILETIME `procs` listed for the pid. Null = not checked.
        public ulong? ExpectStart;
        private bool _detachQuiet;       // a refused attach detaches without a `detached` event: `error` says it all
        private int _plantAllCalls;      // protocolcheck: did anything plant (see PlantAll)

        /// <summary>Pure: does the attached process's creation time answer the one the host listed?
        /// No expectation passes; an expectation with an unreadable time FAILS - it cannot be proven the same.</summary>
        internal static bool StartTimeMatches(ulong? expected, bool read, ulong actual)
        {
            return expected == null || (read && actual == expected.Value);
        }

        /// <summary>After DebugActiveProcess, before anything is planted: the pid may have been reused since the
        /// host listed it (a pid is not an identity). On a mismatch, report it and detach on the first event -
        /// the attach burst's CREATE_PROCESS, which then never reaches PlantAll.</summary>
        private void CheckAttachedIsTheListedProcess()
        {
            if (ExpectStart == null) return;
            ulong actual;
            bool read = ProcsCommand.TryGetProcessStart(_attachPid, out actual);
            ApplyListedProcessCheck(read, actual);
        }

        private void ApplyListedProcessCheck(bool read, ulong actual)
        {
            if (StartTimeMatches(ExpectStart, read, actual)) return;
            RefuseListedProcessMismatch();
        }

        private void RefuseListedProcessMismatch()
        {
            Console.WriteLine("@JSON " + Json.AttachError($"attach failed: process {_attachPid} is not the one listed (pid reused)", 0));
            AttachFailed = true;
            _detachQuiet = true;
            _detachPending = true;
        }

        /// <summary>Start the attach. False (with the error event already written) when Windows refuses.</summary>
        private bool StartAttach()
        {
            if (!Native.DebugActiveProcess(_attachPid))
            {
                int err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                Console.WriteLine("@JSON " + Json.AttachError("attach failed: " + new System.ComponentModel.Win32Exception(err).Message, err));
                AttachFailed = true;
                return false;
            }
            // The default is TRUE: when this thread exits, the debuggee dies with it. An engine that exits for
            // any reason must not take the user's running app along. The cost, stated: an engine that CRASHES
            // after planting leaves 0xCC bytes behind, and the app dies at the next one it reaches. quit, stdin
            // close and detach all restore the bytes first, so only a crash loses the app.
            Native.DebugSetProcessKillOnExit(false);
            Console.WriteLine($"attached to pid {_attachPid}; {_bps.Count} breakpoint(s)");
            return true;
        }

        /// <summary>Ask for a detach from the RUNNING state: inject a break so an event arrives to detach on.
        /// A target that has not reported CREATE_PROCESS yet needs no break: its attach burst is on the way.</summary>
        private void RequestDetach()
        {
            _detachPending = true;
            if (_hProcess == IntPtr.Zero) return;
            RequestPause();
            if (!_pauseRequested)
            {
                // RequestPause already said why. Without an event the loop has nothing to detach on, and an idle
                // GUI app may raise none for a long time: refuse now rather than leave the host waiting.
                _detachPending = false;
                EmitError("detach: could not interrupt the target");
            }
        }

        /// <summary>The attach initial break arrived: every thread that existed at attach has been reported.
        /// Their CREATE_THREAD events came in the kernel's thread-list order, which nothing documents as creation
        /// order, and the CREATE_PROCESS thread is merely the first in that list. Re-number by creation time so
        /// "newest thread" (PickPauseThread) means what it means after a launch.</summary>
        private void ReseedThreadOrderAfterAttach(uint breakTid)
        {
            var created = new List<KeyValuePair<uint, long>>();
            foreach (uint t in _threads)
            {
                long when = long.MaxValue;   // unreadable: sorts after every thread whose time is known
                IntPtr h = OpenThreadForContext(t);
                if (h != IntPtr.Zero)
                {
                    long c, e, k, u;
                    if (GetThreadTimes(h, out c, out e, out k, out u)) when = c;
                    Native.CloseHandle(h);
                }
                created.Add(new KeyValuePair<uint, long>(t, when));
            }
            ApplyThreadOrder(OrderThreadsByCreation(created, breakTid));
        }

        /// <summary>THE ORDER, pure: the tids oldest first by creation time, a tie broken by the lower tid so the
        /// answer never depends on enumeration order, and <paramref name="breakTid"/> left out - the thread the
        /// attach break ran on is injected by Windows, exits as soon as it is continued, and is neither the
        /// program's main thread nor a thread a pause should pick.</summary>
        internal static List<uint> OrderThreadsByCreation(IEnumerable<KeyValuePair<uint, long>> created, uint breakTid)
        {
            var list = new List<KeyValuePair<uint, long>>();
            foreach (var kv in created) if (kv.Key != breakTid) list.Add(kv);
            list.Sort((a, b) => a.Value != b.Value ? a.Value.CompareTo(b.Value) : a.Key.CompareTo(b.Key));
            var order = new List<uint>(list.Count);
            foreach (var kv in list) order.Add(kv.Key);
            return order;
        }

        /// <summary>Re-number the threads 0.. in <paramref name="order"/>, and make the oldest the main thread.
        /// A tid not in the order (the injected break thread) keeps no position, so SeqOf sorts it last.</summary>
        private void ApplyThreadOrder(List<uint> order)
        {
            _threadSeq.Clear();
            _nextThreadSeq = 0;
            foreach (uint t in order) _threadSeq[t] = _nextThreadSeq++;
            if (order.Count > 0) _mainTid = order[0];
        }

        /// <summary>Test seam: the apply step on an engine with no target.</summary>
        internal void ApplyThreadOrderForTest(List<uint> order)
        {
            RefuseSeamIfAttached("ApplyThreadOrderForTest");
            ApplyThreadOrder(order);
        }
        internal uint MainTidForTest { get { return _mainTid; } }
        internal int SeqOfForTest(uint tid) { return SeqOf(tid); }

        /// <summary>
        /// Detach on the event in <paramref name="held"/>. <paramref name="heldStatus"/> is the continue status
        /// the loop's handler already decided, or null when the event arrived with the detach already pending and
        /// no handler ran, in which case the drain rules decide it too. Returns the `detached` event (emitted
        /// unless the detach is the quiet one of a refused attach), or null when the target exited during the drain.
        ///
        /// EVERYTHING that can leave the app worse off is counted and reported in "error", because the host warns
        /// only when error is present (4b run 2): a byte not restored, a thread whose TF could not be cleared, a
        /// queued INT3 whose EIP could not be rewound, a failed stop - and a detach that threw part-way, which
        /// still attempts the stop and still sends `detached` (restored = what was done before it threw).
        /// </summary>
        private string DetachAt(byte[] held, uint? heldStatus)
        {
            _detachPending = false;
            uint pid = _pid != 0 ? _pid : Pid(held);
            int restored = 0, failed = 0, drained = 0, oursDrained = 0;
            var tfFailed = new List<uint>();
            var rewindFailed = new List<string>();
            string stopError = null, aborted = null;
            bool heldContinued = false, stopTried = false, exited = false;
            uint exitCode = 0;
            try
            {
                // The addresses that are OURS, snapshotted before anything is cleared: the drain needs them to tell
                // our INT3 (rewind and continue) from the app's own (hand it to the app). Planted NOW, plus every
                // byte planted earlier in the session, whose queued hits are just as much ours.
                var ours = new HashSet<uint>(_armed.Keys);
                ours.UnionWith(_temp.Keys);
                ours.UnionWith(_plantedEver);

                DetachStep("restore");
                foreach (var kv in _temp) { if (TryWriteByte(kv.Key, kv.Value)) restored++; else failed++; }
                foreach (var kv in _armed) { if (TryWriteByte(kv.Key, kv.Value)) restored++; else failed++; }
                DetachStep("cancelstep");
                CancelStep();          // step state; clears _temp (its bytes are already back)
                _armed.Clear();

                DetachStep("clear-rearm");
                _rearm.Clear();

                DetachStep("clear-tf");
                foreach (uint t in _threads) if (!ClearTf(t)) tfFailed.Add(t);

                DetachStep("forget-setip");
                foreach (uint t in _threads) ForgetSetIpThread(t);
                _setIpStepping = false;

                DetachStep("hover-off");
                _hover.Set(false);
                _hoverTrees.Clear();

                DetachStep("continue-held");
                uint status = heldStatus ?? DetachClassify(held, ours, rewindFailed, ref exited, ref exitCode);
                _detachContinue(Pid(held), Tid(held), status);
                heldContinued = true;

                DetachStep("drain");
                var buf = new byte[1024];
                var sw = Stopwatch.StartNew();
                while (!exited && drained < DetachDrainCapEvents && sw.ElapsedMilliseconds < DetachDrainCapMs
                       && _detachWait(buf, DetachDrainWaitMs))
                {
                    drained++;
                    if (IsOursOrTrap(buf, ours)) oursDrained++;
                    uint st = DetachClassify(buf, ours, rewindFailed, ref exited, ref exitCode);
                    _detachContinue(Pid(buf), Tid(buf), st);
                }

                _hProcess = IntPtr.Zero;   // kernel32 owns the event's handles and closes them at the stop

                if (exited)
                {
                    Console.WriteLine($"process exited (code {exitCode}) while detaching");
                    if (EmitJson) Console.WriteLine("@JSON " + Json.Exited(exitCode));
                    return null;
                }

                DetachStep("stop");
                stopTried = true;
                if (!Native.DebugActiveProcessStop(pid))
                    stopError = "DebugActiveProcessStop failed (" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ")";

                DetachStep("emit");
            }
            catch (Exception ex)
            {
                aborted = "detach aborted: " + ex.Message;
                // Best effort, in the order the normal path would have: the held event must not be left to the
                // stop (which would hand it to the app as unhandled), and the debugger must still let go.
                if (!heldContinued) { try { _detachContinue(Pid(held), Tid(held), heldStatus ?? Native.DBG_CONTINUE); } catch { } }
                _hProcess = IntPtr.Zero;
                if (!stopTried && !exited)
                {
                    try
                    {
                        if (!Native.DebugActiveProcessStop(pid))
                            stopError = "DebugActiveProcessStop failed (" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ")";
                    }
                    catch (Exception stopEx) { stopError = "DebugActiveProcessStop threw: " + stopEx.Message; }
                }
            }

            string error = DetachError(aborted, failed, tfFailed, rewindFailed, stopError);
            string json = Json.Detached(pid, drained, restored, error);
            // "ours" is console-only evidence for tools\test-attach.ps1: how many drained events were the ones the
            // drain exists for (our INT3, a trap flag we set). The wire event stays the frozen contract.
            Console.WriteLine($"detached from pid {pid}: {restored} byte(s) restored, {drained} queued event(s) drained (ours={oursDrained}){(error != null ? "; ERROR: " + error : "")}");
            if (EmitJson && !_detachQuiet) Console.WriteLine("@JSON " + json);
            return json;
        }

        /// <summary>The `detached` error text, or null when nothing went wrong. Pure. Each failure names what it
        /// can (the tids, the addresses), so a user reading the host's warning knows what may fault.</summary>
        internal static string DetachError(string aborted, int bytesNotRestored, List<uint> tfNotCleared,
                                           List<string> eipNotRewound, string stopError)
        {
            var parts = new List<string>();
            if (aborted != null) parts.Add(aborted);
            if (bytesNotRestored > 0) parts.Add(bytesNotRestored + " breakpoint byte(s) could not be restored");
            if (tfNotCleared.Count > 0)
                parts.Add("TF not cleared on " + tfNotCleared.Count + " thread(s) (" + string.Join(",", tfNotCleared) + ")");
            foreach (var r in eipNotRewound) parts.Add("EIP not rewound at " + r);
            if (stopError != null) parts.Add(stopError);
            return parts.Count == 0 ? null : string.Join("; ", parts);
        }

        /// <summary>Is this queued event one the drain exists for: an INT3 at one of our addresses, or a trap?</summary>
        private static bool IsOursOrTrap(byte[] ev, HashSet<uint> ours)
        {
            if (Code(ev) != Native.EXCEPTION_DEBUG_EVENT) return false;
            uint exCode = U32(ev, 12);
            return exCode == Native.EXCEPTION_SINGLE_STEP || (exCode == Native.EXCEPTION_BREAKPOINT && ours.Contains(U32(ev, 24)));
        }

        /// <summary>The continue status for one event met while detaching, applying the side effects the drain
        /// needs (EIP rewind, file-handle close) and recognising the target's exit. A rewind that FAILS is
        /// recorded as "0xVA on TID" for the error.</summary>
        private uint DetachClassify(byte[] ev, HashSet<uint> ours, List<string> rewindFailed, ref bool exited, ref uint exitCode)
        {
            uint code = Code(ev);
            uint exCode = code == Native.EXCEPTION_DEBUG_EVENT ? U32(ev, 12) : 0;
            uint exAddr = code == Native.EXCEPTION_DEBUG_EVENT ? U32(ev, 24) : 0;
            bool rewind;
            uint status = DecideDetachEvent(code, exCode, exAddr, ours, ref _seenInitialBreak, ref _pauseRequested, out rewind);

            if (rewind && !SetEip(Tid(ev), exAddr)) rewindFailed.Add("0x" + exAddr.ToString("X") + " on " + Tid(ev));
            if (code == Native.LOAD_DLL_DEBUG_EVENT || code == Native.CREATE_PROCESS_DEBUG_EVENT) CloseHandleValue(U32(ev, 12));
            if (code == Native.EXIT_PROCESS_DEBUG_EVENT) { exited = true; exitCode = U32(ev, 12); }
            return status;
        }

        /// <summary>THE DRAIN RULES, pure, so protocolcheck can walk the table:
        ///   our INT3                  -> rewind EIP to it, DBG_CONTINUE (as the hit handler would have)
        ///   the attach/loader break   -> DBG_CONTINUE, once
        ///   our injected pause break  -> DBG_CONTINUE, once
        ///   any other INT3            -> NOT_HANDLED: the app's own, which is what it gets with no debugger
        ///   a single-step trap        -> DBG_CONTINUE: TF we set (it clears itself on the trap). The design note
        ///                                said "only for tids we set TF on"; that set is not complete (a silent
        ///                                advanced-bp re-arm, a step, stepi, a temp re-arm all set it), and an
        ///                                unanswered trap crashes the app, while a Clarion app that single-steps
        ///                                itself does not exist. Deliberate deviation, recorded here.
        ///   any other exception       -> NOT_HANDLED
        ///   anything else             -> DBG_CONTINUE
        /// "Our INT3" means any address in <paramref name="ours"/>, which the caller builds from what is planted
        /// now AND everything planted earlier in the session.
        /// </summary>
        internal static uint DecideDetachEvent(uint code, uint exCode, uint exAddr, HashSet<uint> ours,
                                               ref bool seenInitialBreak, ref bool pauseRequested, out bool rewind)
        {
            rewind = false;
            if (code != Native.EXCEPTION_DEBUG_EVENT) return Native.DBG_CONTINUE;
            if (exCode == Native.EXCEPTION_BREAKPOINT)
            {
                if (ours != null && ours.Contains(exAddr)) { rewind = true; return Native.DBG_CONTINUE; }
                if (!seenInitialBreak) { seenInitialBreak = true; return Native.DBG_CONTINUE; }
                if (pauseRequested) { pauseRequested = false; return Native.DBG_CONTINUE; }
                return Native.DBG_EXCEPTION_NOT_HANDLED;
            }
            if (exCode == Native.EXCEPTION_SINGLE_STEP) return Native.DBG_CONTINUE;
            return Native.DBG_EXCEPTION_NOT_HANDLED;
        }

        /// <summary>Clear TF on one thread. True when it is clear afterwards (it was not set, or it was cleared);
        /// false when the thread could not be opened, read or written - its TF is then UNKNOWN, and a set one kills
        /// the app on its next instruction once the debugger has gone.</summary>
        private static bool ClearThreadTrapFlag(uint tid)
        {
            IntPtr h = OpenThreadForContext(tid);
            if (h == IntPtr.Zero) return false;
            try
            {
                var c = NewContext();
                if (!Native.GetThreadContext(h, ref c)) return false;
                if ((c.EFlags & TRAP_FLAG) == 0) return true;
                c.EFlags &= ~TRAP_FLAG;
                return Native.SetThreadContext(h, ref c);
            }
            finally { Native.CloseHandle(h); }
        }

        /// <summary>Put a thread's EIP at <paramref name="eip"/>. True only when the context was written.</summary>
        private static bool SetThreadEip(uint tid, uint eip)
        {
            IntPtr h = OpenThreadForContext(tid);
            if (h == IntPtr.Zero) return false;
            try
            {
                var c = NewContext();
                if (!Native.GetThreadContext(h, ref c)) return false;
                c.Eip = eip;
                return Native.SetThreadContext(h, ref c);
            }
            finally { Native.CloseHandle(h); }
        }

        /// <summary>WriteByte with an answer: true only when the byte was written. The detach counts restores
        /// and reports a failure, because a byte left at 0xCC kills the app later.</summary>
        private bool TryWriteByte(uint va, byte value)
        {
            int wrote;
            bool ok = Native.WriteProcessMemory(_hProcess, Ptr(va), new[] { value }, 1, out wrote) && wrote == 1;
            Native.FlushInstructionCache(_hProcess, Ptr(va), (IntPtr)1);
            return ok;
        }

        /// <summary>A module's path when its load event gave no usable file handle. GetModuleFileNameEx reads the
        /// loader's list, which on a LIVE load event may not hold the DLL yet; GetMappedFileName asks the memory
        /// manager and answers \Device\HarddiskVolumeN\..., mapped back to a drive letter here.</summary>
        private string PathFromMappedImage(uint baseVa)
        {
            if (_hProcess == IntPtr.Zero || baseVa == 0) return null;
            var sb = new StringBuilder(1024);
            uint n = Native.GetModuleFileNameEx(_hProcess, Ptr(baseVa), sb, (uint)sb.Capacity);
            if (n > 0) return sb.ToString(0, (int)n);
            sb.Clear();
            n = Native.GetMappedFileName(_hProcess, Ptr(baseVa), sb, (uint)sb.Capacity);
            return n > 0 ? DevicePathToDosPath(sb.ToString(0, (int)n)) : null;
        }

        private static string DevicePathToDosPath(string device)
        {
            var target = new StringBuilder(1024);
            for (char d = 'A'; d <= 'Z'; d++)
            {
                string drive = d + ":";
                target.Clear();
                if (Native.QueryDosDeviceW(drive, target, (uint)target.Capacity) == 0) continue;
                string prefix = target.ToString();
                int nul = prefix.IndexOf('\0');
                if (nul >= 0) prefix = prefix.Substring(0, nul);
                if (prefix.Length > 0 && device.StartsWith(prefix + "\\", StringComparison.OrdinalIgnoreCase))
                    return drive + device.Substring(prefix.Length);
            }
            return device;
        }

        // ------------------------------------------------------------------ test seams (protocolcheck)

        /// <summary>One detach, set up and observed by protocolcheck. Inputs first, results after the run.</summary>
        internal sealed class DetachScenario
        {
            public uint[] Armed = new uint[0], Temp = new uint[0], RearmTids = new uint[0], Threads = new uint[0], PlantedEver = new uint[0];
            public List<byte[]> Queue = new List<byte[]>();
            public HashSet<uint> TfFailTids = new HashSet<uint>(), EipFailTids = new HashSet<uint>();
            public string ThrowAt;
            // results
            public List<string> Order, Continues = new List<string>(), Rewinds = new List<string>();
            public string Json, Escaped;
        }

        /// <summary>Run the REAL DetachAt on an engine with NO target. The drain is fed <see cref="DetachScenario.Queue"/>
        /// in place of WaitForDebugEvent, and the context operations answer through hooks that record what was asked
        /// and fail for the tids named. Every remaining Win32 call lands on a null handle or pid 0 and fails
        /// harmlessly, which is also why a restore comes back failed. An exception that escapes DetachAt is caught
        /// here and put in <see cref="DetachScenario.Escaped"/>.</summary>
        internal void RunDetachScenarioForTest(DetachScenario s)
        {
            RefuseSeamIfAttached("RunDetachScenarioForTest");
            foreach (var va in s.Armed) _armed[va] = 0x55;
            foreach (var va in s.Temp) _temp[va] = 0x8B;
            foreach (var t in s.RearmTids) _rearm[t] = new Rearm { Va = s.Armed.Length > 0 ? s.Armed[0] : 0, IsTemp = false };
            foreach (var t in s.Threads) _threads.Add(t);
            foreach (var va in s.PlantedEver) NotePlanted(va, 0x55);
            _hover.Set(true);
            _seenInitialBreak = true;

            int next = 0;
            _detachWait = (buf, ms) =>
            {
                if (next >= s.Queue.Count) return false;
                Array.Clear(buf, 0, buf.Length);
                Array.Copy(s.Queue[next], buf, Math.Min(s.Queue[next].Length, buf.Length));
                next++;
                return true;
            };
            _detachContinue = (p, t, st) => { s.Continues.Add(t + ":0x" + st.ToString("X8")); return true; };
            _setEipHook = (t, eip) => { s.Rewinds.Add(t + ":0x" + eip.ToString("X")); return !s.EipFailTids.Contains(t); };
            _clearTfHook = t => !s.TfFailTids.Contains(t);
            _detachTrace = new List<string>();
            _detachThrowAt = s.ThrowAt;

            var held = new byte[1024];
            BitConverter.GetBytes(Native.OUTPUT_DEBUG_STRING_EVENT).CopyTo(held, 0);   // pid 0, tid 0
            try { s.Json = DetachAt(held, null); }
            catch (Exception ex) { s.Escaped = ex.GetType().Name + ": " + ex.Message; }
            finally
            {
                s.Order = _detachTrace; _detachTrace = null; _detachThrowAt = null;
                _detachWait = Native.WaitForDebugEvent; _detachContinue = Native.ContinueDebugEvent;
                _setEipHook = null; _clearTfHook = null;
                foreach (var t in s.Threads) _threads.Remove(t);
            }
        }

        /// <summary>The teardown alone (an empty queue): its step order and the `detached` event.</summary>
        internal string DetachTeardownForTest(uint[] armedVas, uint[] tempVas, uint[] rearmTids, out List<string> order)
        {
            var s = new DetachScenario { Armed = armedVas, Temp = tempVas, RearmTids = rearmTids };
            RunDetachScenarioForTest(s);
            order = s.Order;
            return s.Json;
        }

        /// <summary>The teardown with the drain fed <paramref name="queue"/>. <paramref name="continues"/> gets
        /// "tid:status" for every ContinueDebugEvent, the held event (tid 0) first; <paramref name="rewinds"/> gets
        /// "tid:0xEIP" for every EIP the drain moved back.</summary>
        internal string DetachDrainForTest(uint[] armedVas, uint[] tempVas, uint[] rearmTids, List<byte[]> queue,
                                           out List<string> order, out List<string> continues, out List<string> rewinds)
        {
            var s = new DetachScenario { Armed = armedVas, Temp = tempVas, RearmTids = rearmTids, Queue = queue };
            RunDetachScenarioForTest(s);
            order = s.Order; continues = s.Continues; rewinds = s.Rewinds;
            return s.Json;
        }

        private sealed class EventSourceExhausted : Exception { }

        /// <summary>Run the REAL debug loop against an event source that NEVER goes quiet - every wait returns an
        /// OUTPUT_DEBUG_STRING at once, as an app spamming OutputDebugString does - with <paramref name="command"/>
        /// already queued. Returns how many events the loop took before it acted on the command and left, or -1
        /// when it was still running after <paramref name="maxEvents"/> (the command was starved). Needs an
        /// interactive engine with no target.</summary>
        internal int DebugLoopStarvationForTest(string command, int maxEvents)
        {
            RefuseSeamIfAttached("DebugLoopStarvationForTest");
            if (!_interactive) throw new InvalidOperationException("DebugLoopStarvationForTest: needs an interactive engine");
            int served = 0;
            _loopWait = (buf, ms) =>
            {
                if (served >= maxEvents) throw new EventSourceExhausted();
                Array.Clear(buf, 0, buf.Length);
                BitConverter.GetBytes(Native.OUTPUT_DEBUG_STRING_EVENT).CopyTo(buf, 0);
                served++;
                return true;
            };
            _loopContinue = (p, t, s) => true;
            _detachWait = (buf, ms) => false;           // nothing queued behind the held event
            _detachContinue = (p, t, s) => true;
            _cmds.Enqueue(command);
            try { DebugLoop(); return served; }
            catch (EventSourceExhausted) { return -1; }
            finally
            {
                _loopWait = Native.WaitForDebugEvent; _loopContinue = Native.ContinueDebugEvent;
                _detachWait = Native.WaitForDebugEvent; _detachContinue = Native.ContinueDebugEvent;
            }
        }

        /// <summary>Run the REAL debug loop on ONE event - <paramref name="ev"/> - and hand back how it was continued
        /// and every EIP it rewound. Needs a NON-interactive engine, so a wrong turn into a pause cannot block on
        /// stdin (a non-interactive programmatic break just continues, which is what makes a missing rewind show).</summary>
        internal void OneLoopEventForTest(byte[] ev, uint[] plantedEver, out List<string> continues, out List<string> rewinds)
        {
            RefuseSeamIfAttached("OneLoopEventForTest");
            if (_interactive) throw new InvalidOperationException("OneLoopEventForTest: needs a NON-interactive engine");
            foreach (var va in plantedEver) NotePlanted(va, 0x55);
            _seenInitialBreak = true;
            var cont = new List<string>(); var rew = new List<string>();
            bool given = false;
            _loopWait = (buf, ms) =>
            {
                if (given) throw new EventSourceExhausted();
                Array.Clear(buf, 0, buf.Length);
                Array.Copy(ev, buf, Math.Min(ev.Length, buf.Length));
                given = true;
                return true;
            };
            _loopContinue = (p, t, st) => { cont.Add(t + ":0x" + st.ToString("X8")); return true; };
            _setEipHook = (t, eip) => { rew.Add(t + ":0x" + eip.ToString("X")); return true; };
            try { DebugLoop(); }
            catch (EventSourceExhausted) { }
            finally
            {
                _loopWait = Native.WaitForDebugEvent; _loopContinue = Native.ContinueDebugEvent; _setEipHook = null;
            }
            continues = cont; rewinds = rew;
        }

        /// <summary>The `--expect-start` flow on an ATTACH engine with no target: the listed-process check with a
        /// given creation time, then the REAL loop fed the attach burst's CREATE_PROCESS (pid 0). Reports whether
        /// anything was planted and whether the attach was refused.</summary>
        internal void ExpectStartFlowForTest(ulong expected, bool read, ulong actual, out bool planted, out bool refused)
        {
            RefuseSeamIfAttached("ExpectStartFlowForTest");
            if (!IsAttach) throw new InvalidOperationException("ExpectStartFlowForTest: needs an attach engine");
            ExpectStart = expected;
            ApplyListedProcessCheck(read, actual);
            bool given = false;
            _loopWait = (buf, ms) =>
            {
                if (given) throw new EventSourceExhausted();
                Array.Clear(buf, 0, buf.Length);
                BitConverter.GetBytes(Native.CREATE_PROCESS_DEBUG_EVENT).CopyTo(buf, 0);
                given = true;
                return true;
            };
            _loopContinue = (p, t, st) => true;
            _detachWait = (buf, ms) => false;
            _detachContinue = (p, t, st) => true;
            try { DebugLoop(); }
            catch (EventSourceExhausted) { }
            finally
            {
                _loopWait = Native.WaitForDebugEvent; _loopContinue = Native.ContinueDebugEvent;
                _detachWait = Native.WaitForDebugEvent; _detachContinue = Native.ContinueDebugEvent;
            }
            planted = _plantAllCalls > 0;
            refused = AttachFailed;
        }

        /// <summary>A DEBUG_EVENT buffer for the drain seam: an exception (code, address) on <paramref name="tid"/>,
        /// or, with <paramref name="exCode"/> 0, a bare event of <paramref name="eventCode"/>.</summary>
        internal static byte[] DebugEventForTest(uint eventCode, uint tid, uint exCode, uint exAddr)
        {
            var b = new byte[1024];
            BitConverter.GetBytes(eventCode).CopyTo(b, 0);
            BitConverter.GetBytes(tid).CopyTo(b, 8);
            if (eventCode == Native.EXCEPTION_DEBUG_EVENT)
            {
                BitConverter.GetBytes(exCode).CopyTo(b, 12);
                BitConverter.GetBytes(exAddr).CopyTo(b, 24);
            }
            return b;
        }

        internal int ArmedCountForTest { get { return _armed.Count; } }
        internal int TempCountForTest { get { return _temp.Count; } }
        internal int RearmCountForTest { get { return _rearm.Count; } }
        internal bool HoverOnForTest { get { return _hover.On; } }
        internal bool DetachPendingForTest { get { return _detachPending; } }
    }
}
