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

        // protocolcheck's view of the teardown ORDER. Null in a real session.
        private List<string> _detachTrace;
        private void DetachStep(string name) { if (_detachTrace != null) _detachTrace.Add(name); }

        // The detach's three debug-API calls, as delegates so protocolcheck can feed the DRAIN a queue of events
        // and see how each one is answered. In a real session they are exactly the Win32 functions. The live
        // suite cannot reproduce the race the drain exists for (tools\test-attach.ps1 says why), so this is the
        // only place the drain's answers are checked against events it actually has to answer.
        private Func<byte[], uint, bool> _detachWait = Native.WaitForDebugEvent;
        private Func<uint, uint, uint, bool> _detachContinue = Native.ContinueDebugEvent;
        private Action<uint, uint> _detachSetEip;
        private void DetachSetEip(uint tid, uint eip) { if (_detachSetEip != null) _detachSetEip(tid, eip); else SetThreadEip(tid, eip); }

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
        /// no handler ran, in which case the drain rules decide it too. Returns the `detached` event (also
        /// emitted), or null when the target exited during the drain.
        /// </summary>
        private string DetachAt(byte[] held, uint? heldStatus)
        {
            _detachPending = false;
            uint pid = _pid != 0 ? _pid : Pid(held);

            // The addresses that are OURS, snapshotted before anything is cleared: the drain needs them to tell
            // our INT3 (rewind and continue) from the app's own (hand it to the app).
            var ours = new HashSet<uint>(_armed.Keys);
            ours.UnionWith(_temp.Keys);

            int restored = 0, failed = 0;
            DetachStep("restore");
            foreach (var kv in _temp) { if (TryWriteByte(kv.Key, kv.Value)) restored++; else failed++; }
            foreach (var kv in _armed) { if (TryWriteByte(kv.Key, kv.Value)) restored++; else failed++; }
            DetachStep("cancelstep");
            CancelStep();          // step state; clears _temp (its bytes are already back)
            _armed.Clear();

            DetachStep("clear-rearm");
            _rearm.Clear();

            DetachStep("clear-tf");
            ClearTrapFlagOnAllThreads();

            DetachStep("forget-setip");
            foreach (uint t in _threads) ForgetSetIpThread(t);
            _setIpStepping = false;

            DetachStep("hover-off");
            _hover.Set(false);
            _hoverTrees.Clear();

            bool exited = false;
            uint exitCode = 0;
            DetachStep("continue-held");
            uint status = heldStatus ?? DetachClassify(held, ours, ref exited, ref exitCode);
            _detachContinue(Pid(held), Tid(held), status);

            DetachStep("drain");
            int drained = 0, oursDrained = 0;
            var buf = new byte[1024];
            var sw = Stopwatch.StartNew();
            while (!exited && drained < DetachDrainCapEvents && sw.ElapsedMilliseconds < DetachDrainCapMs
                   && _detachWait(buf, DetachDrainWaitMs))
            {
                drained++;
                if (IsOursOrTrap(buf, ours)) oursDrained++;
                uint st = DetachClassify(buf, ours, ref exited, ref exitCode);
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
            string error = failed > 0 ? failed + " breakpoint byte(s) could not be restored" : null;
            if (!Native.DebugActiveProcessStop(pid))
            {
                string why = "DebugActiveProcessStop failed (" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ")";
                error = error == null ? why : error + "; " + why;
            }

            DetachStep("emit");
            string json = Json.Detached(pid, drained, restored, error);
            // "ours" is console-only evidence for tools\test-attach.ps1: how many drained events were the ones the
            // drain exists for (our INT3, a trap flag we set). The wire event stays the frozen contract.
            Console.WriteLine($"detached from pid {pid}: {restored} byte(s) restored, {drained} queued event(s) drained (ours={oursDrained}){(error != null ? "; ERROR: " + error : "")}");
            if (EmitJson) Console.WriteLine("@JSON " + json);
            return json;
        }

        /// <summary>Is this queued event one the drain exists for: an INT3 at one of our addresses, or a trap?</summary>
        private static bool IsOursOrTrap(byte[] ev, HashSet<uint> ours)
        {
            if (Code(ev) != Native.EXCEPTION_DEBUG_EVENT) return false;
            uint exCode = U32(ev, 12);
            return exCode == Native.EXCEPTION_SINGLE_STEP || (exCode == Native.EXCEPTION_BREAKPOINT && ours.Contains(U32(ev, 24)));
        }

        /// <summary>The continue status for one event met while detaching, applying the side effects the drain
        /// needs (EIP rewind, file-handle close) and recognising the target's exit.</summary>
        private uint DetachClassify(byte[] ev, HashSet<uint> ours, ref bool exited, ref uint exitCode)
        {
            uint code = Code(ev);
            uint exCode = code == Native.EXCEPTION_DEBUG_EVENT ? U32(ev, 12) : 0;
            uint exAddr = code == Native.EXCEPTION_DEBUG_EVENT ? U32(ev, 24) : 0;
            bool rewind;
            uint status = DecideDetachEvent(code, exCode, exAddr, ours, ref _seenInitialBreak, ref _pauseRequested, out rewind);

            if (rewind) DetachSetEip(Tid(ev), exAddr);
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

        private void ClearTrapFlagOnAllThreads()
        {
            foreach (uint t in _threads)
            {
                IntPtr h = OpenThreadForContext(t);
                if (h == IntPtr.Zero) continue;
                try
                {
                    var c = NewContext();
                    if (Native.GetThreadContext(h, ref c) && (c.EFlags & TRAP_FLAG) != 0)
                    {
                        c.EFlags &= ~TRAP_FLAG;
                        Native.SetThreadContext(h, ref c);
                    }
                }
                finally { Native.CloseHandle(h); }
            }
        }

        private void SetThreadEip(uint tid, uint eip)
        {
            IntPtr h = OpenThreadForContext(tid);
            if (h == IntPtr.Zero) return;
            try
            {
                var c = NewContext();
                if (Native.GetThreadContext(h, ref c)) { c.Eip = eip; Native.SetThreadContext(h, ref c); }
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

        /// <summary>Run the REAL detach teardown on an engine with NO target and hand back the step order and the
        /// `detached` event. Every Win32 call in it lands on a null handle, a pid of 0 or a thread with no debug
        /// object, and fails harmlessly - which is also what makes the restore count come back 0 with an error.
        /// Refuses an attached engine like every other mutating seam.</summary>
        internal string DetachTeardownForTest(uint[] armedVas, uint[] tempVas, uint[] rearmTids, out List<string> order)
        {
            List<string> continues; List<string> rewinds;
            return DetachDrainForTest(armedVas, tempVas, rearmTids, new List<byte[]>(), out order, out continues, out rewinds);
        }

        /// <summary>The same teardown, with the drain fed <paramref name="queue"/> in place of WaitForDebugEvent.
        /// <paramref name="continues"/> gets "tid:status" for every ContinueDebugEvent, the held event (tid 0)
        /// first; <paramref name="rewinds"/> gets "tid:0xEIP" for every EIP the drain moved back.</summary>
        internal string DetachDrainForTest(uint[] armedVas, uint[] tempVas, uint[] rearmTids, List<byte[]> queue,
                                           out List<string> order, out List<string> continues, out List<string> rewinds)
        {
            RefuseSeamIfAttached("DetachDrainForTest");
            foreach (var va in armedVas) _armed[va] = 0x55;
            foreach (var va in tempVas) _temp[va] = 0x8B;
            foreach (var t in rearmTids) _rearm[t] = new Rearm { Va = armedVas.Length > 0 ? armedVas[0] : 0, IsTemp = false };
            _hover.Set(true);
            _seenInitialBreak = true;

            var cont = new List<string>(); var rew = new List<string>();
            int next = 0;
            _detachWait = (buf, ms) =>
            {
                if (next >= queue.Count) return false;
                Array.Clear(buf, 0, buf.Length);
                Array.Copy(queue[next], buf, Math.Min(queue[next].Length, buf.Length));
                next++;
                return true;
            };
            _detachContinue = (p, t, st) => { cont.Add(t + ":0x" + st.ToString("X8")); return true; };
            _detachSetEip = (t, eip) => rew.Add(t + ":0x" + eip.ToString("X"));
            _detachTrace = new List<string>();

            var held = new byte[1024];
            BitConverter.GetBytes(Native.OUTPUT_DEBUG_STRING_EVENT).CopyTo(held, 0);   // pid 0, tid 0
            string json;
            try { json = DetachAt(held, null); }
            finally
            {
                order = _detachTrace; _detachTrace = null;
                _detachWait = Native.WaitForDebugEvent; _detachContinue = Native.ContinueDebugEvent; _detachSetEip = null;
            }
            continues = cont; rewinds = rew;
            return json;
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
