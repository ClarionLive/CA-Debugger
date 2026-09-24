using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    // Attach and detach (ticket 3f2d747f part A). See DebugEngine.Attach.cs for the design, and ProtocolCheck.cs
    // for the claim registry and NewEngine.
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The detach, with no debuggee: the wire shapes of the three new events, `detach` kept out of the resume
        /// set, the drain's answer to each kind of queued event, and the teardown ORDER - bytes back and TF clear
        /// BEFORE the held event is continued, the drain before the stop.
        ///
        /// The drain is fed a hand-built queue through DetachDrainForTest, because the live suite cannot make
        /// Windows queue the events it exists for (tools\test-attach.ps1 says why). A drain that stops early, or
        /// never runs, leaves queued events unanswered, and that is what the queue case below catches;
        /// tools\test-attach.ps1 -SelfTest builds exactly that engine and requires this check to fail on it.
        /// </summary>
        private static void CheckDetach(List<string> failures, ClaimLog claims)
        {
            // ---- wire shapes, exact: Lea's host parses these (3f2d747f part C) ----
            ExpectEqual(failures, "attach wire: loaded (attached)", Json.Loaded(1234, 0x400000, true),
                "{\"event\":\"loaded\",\"pid\":1234,\"loadBase\":\"0x400000\",\"attached\":true}");
            ExpectEqual(failures, "attach wire: loaded (launched) is unchanged", Json.Loaded(1234, 0x400000, false),
                Json.Loaded(1234, 0x400000));
            ExpectEqual(failures, "attach wire: detached", Json.Detached(1234, 2, 3, null),
                "{\"event\":\"detached\",\"pid\":1234,\"drained\":2,\"restored\":3}");
            ExpectEqual(failures, "attach wire: detached with an error", Json.Detached(1234, 0, 1, "1 breakpoint byte(s) could not be restored"),
                "{\"event\":\"detached\",\"pid\":1234,\"drained\":0,\"restored\":1,\"error\":\"1 breakpoint byte(s) could not be restored\"}");
            ExpectEqual(failures, "attach wire: attach failed", Json.AttachError("attach failed: Access is denied", 5),
                "{\"event\":\"error\",\"message\":\"attach failed: Access is denied\",\"code\":5}");

            if (DebugEngine.IsResumeVerbForTest("detach"))
                failures.Add("detach: IsResumeVerb accepts 'detach' - the running-state switch would never reach its case");

            // ---- the drain rules, pure ----
            var ours = new HashSet<uint> { 0x401000 };
            Action<string, uint, uint, uint, bool, bool, uint, bool> rule = (what, code, ex, addr, seen, pause, want, wantRewind) =>
            {
                bool s = seen, p = pause, rw;
                uint got = DebugEngine.DecideDetachEvent(code, ex, addr, ours, ref s, ref p, out rw);
                if (got != want || rw != wantRewind)
                    failures.Add("detach rule: " + what + " -> 0x" + got.ToString("X8") + (rw ? " with" : " without")
                                 + " an EIP rewind; expected 0x" + want.ToString("X8") + (wantRewind ? " with one" : " without one"));
            };
            const uint Ex = Native.EXCEPTION_DEBUG_EVENT, Bp = Native.EXCEPTION_BREAKPOINT, Ss = Native.EXCEPTION_SINGLE_STEP;
            const uint Go = Native.DBG_CONTINUE, App = Native.DBG_EXCEPTION_NOT_HANDLED;
            rule("our INT3", Ex, Bp, 0x401000, true, false, Go, true);
            rule("the attach break, before the initial break was seen", Ex, Bp, 0x77001000, false, false, Go, false);
            rule("our injected pause break", Ex, Bp, 0x77001000, true, true, Go, false);
            rule("the app's own INT3", Ex, Bp, 0x409999, true, false, App, false);
            rule("a single-step trap", Ex, Ss, 0x401001, true, false, Go, false);
            rule("an access violation", Ex, 0xC0000005, 0x401000, true, false, App, false);
            rule("a LOAD_DLL", Native.LOAD_DLL_DEBUG_EVENT, 0, 0, true, false, Go, false);

            // ---- the teardown ORDER, on the real DetachAt ----
            var eng = NewEngine();
            List<string> order = null;
            string json = null;
            CaptureConsole(() => { json = eng.DetachTeardownForTest(new uint[] { 0x401000, 0x401010 }, new uint[] { 0x402000 },
                                                                    new uint[] { 7 }, out order); });
            order = order ?? new List<string>();
            string[] want = { "restore", "cancelstep", "clear-rearm", "clear-tf", "forget-setip", "hover-off",
                              "continue-held", "drain", "stop", "emit" };
            if (string.Join(",", order) != string.Join(",", want))
                failures.Add("detach order: " + string.Join(",", order) + " - expected " + string.Join(",", want)
                             + " (the bytes back and TF clear while frozen, then continue, drain, stop)");
            if (eng.ArmedCountForTest != 0 || eng.TempCountForTest != 0 || eng.RearmCountForTest != 0)
                failures.Add("detach state: armed " + eng.ArmedCountForTest + ", temp " + eng.TempCountForTest + ", re-arm "
                             + eng.RearmCountForTest + " left behind - a detach must forget every planted byte");
            if (eng.HoverOnForTest) failures.Add("detach state: the hover mode is still on");
            if (eng.DetachPendingForTest) failures.Add("detach state: the detach-pending flag is still set");
            // No process, so all three restores fail - and that failure must reach the wire, not be swallowed.
            if (json == null || json.IndexOf("\"restored\":0", StringComparison.Ordinal) < 0
                || json.IndexOf("3 breakpoint byte(s) could not be restored", StringComparison.Ordinal) < 0)
                failures.Add("detach report: with no process every restore fails, so detached must say restored 0 and "
                             + "carry the error; got " + (json ?? "(null)"));

            // ---- the DRAIN, fed a queue ----
            var queue = new List<byte[]>
            {
                DebugEngine.DebugEventForTest(Ex, 101, Bp, 0x401000),          // a thread that hit our INT3 before the freeze
                DebugEngine.DebugEventForTest(Ex, 102, Ss, 0x401005),          // a thread mid re-arm single-step
                DebugEngine.DebugEventForTest(Ex, 103, 0xC0000005, 0x500000),  // the app's own fault: the app's to handle
                DebugEngine.DebugEventForTest(Ex, 104, Bp, 0x409999),          // the app's own INT3
                DebugEngine.DebugEventForTest(Native.LOAD_DLL_DEBUG_EVENT, 105, 0, 0),
            };
            var eng2 = NewEngine();
            List<string> order2 = null, continues = null, rewinds = null;
            string json2 = null;
            CaptureConsole(() => { json2 = eng2.DetachDrainForTest(new uint[] { 0x401000 }, new uint[0], new uint[0], queue,
                                                                   out order2, out continues, out rewinds); });
            continues = continues ?? new List<string>();
            rewinds = rewinds ?? new List<string>();
            string[] wantCont = { "0:0x00010002", "101:0x00010002", "102:0x00010002", "103:0x80010001", "104:0x80010001", "105:0x00010002" };
            if (string.Join(",", continues) != string.Join(",", wantCont))
                failures.Add("detach drain: continued " + (continues.Count == 0 ? "nothing" : string.Join(",", continues))
                             + " - expected the held event and then every queued one, in order: " + string.Join(",", wantCont)
                             + ". An unanswered queued event is handed to the app as unhandled when the debugger lets go");
            if (string.Join(",", rewinds) != "101:0x401000")
                failures.Add("detach drain: EIP rewinds " + (rewinds.Count == 0 ? "none" : string.Join(",", rewinds))
                             + " - expected exactly 101:0x401000 (the queued hit on our INT3 only)");
            if (json2 == null || json2.IndexOf("\"drained\":" + queue.Count, StringComparison.Ordinal) < 0)
                failures.Add("detach drain: the detached event does not report drained " + queue.Count + ": " + (json2 ?? "(null)"));

            // ---- the thread order after an attach ----
            // 99 is the injected break thread and the OLDEST time here, so leaving it in puts it first. 20 and 30 tie,
            // listed high tid first, so a sort that does not break the tie by tid (or breaks it the wrong way) moves
            // them. 40's time is unreadable and must sort last.
            var created = new List<KeyValuePair<uint, long>>
            {
                new KeyValuePair<uint, long>(30, 100), new KeyValuePair<uint, long>(10, 200),
                new KeyValuePair<uint, long>(20, 100), new KeyValuePair<uint, long>(99, 50),
                new KeyValuePair<uint, long>(40, long.MaxValue),
            };
            var tOrder = DebugEngine.OrderThreadsByCreation(created, 99);
            if (string.Join(",", tOrder) != "20,30,10,40")
                failures.Add("thread order: " + string.Join(",", tOrder) + " - expected 20,30,10,40 (oldest first, a tie "
                             + "to the lower tid, an unreadable time last, and the injected break thread 99 left out)");
            var eng3 = NewEngine();
            eng3.ApplyThreadOrderForTest(tOrder);
            if (eng3.MainTidForTest != 20)
                failures.Add("thread order: _mainTid is " + eng3.MainTidForTest + " after the reseed - expected 20, the oldest");
            if (eng3.SeqOfForTest(20) != 0 || eng3.SeqOfForTest(30) != 1 || eng3.SeqOfForTest(10) != 2 || eng3.SeqOfForTest(40) != 3
                || eng3.SeqOfForTest(99) != int.MaxValue)
                failures.Add("thread order: positions 20,30,10,40,99 = " + eng3.SeqOfForTest(20) + "," + eng3.SeqOfForTest(30) + ","
                             + eng3.SeqOfForTest(10) + "," + eng3.SeqOfForTest(40) + "," + eng3.SeqOfForTest(99)
                             + " - expected 0,1,2,3 and no position for the break thread");

            claims.Claim("detach: the loaded/detached/attach-error shapes are exact, `detach` is not a resume verb, the "
                         + "drain answers our INT3 (with an EIP rewind), a trap, the attach and pause breaks, and hands the "
                         + "app its own INT3 and faults; the teardown restores bytes and clears TF before continuing, and "
                         + "drains a " + queue.Count + "-event queue before the stop. After an attach, threads are re-numbered "
                         + "oldest first (a tie to the lower tid, the injected break thread left out) and the oldest is main.");
        }

        /// <summary>
        /// A command is never starved by a busy target (3f2d747f, 4b run 1). The debug loop used to read commands
        /// only when WaitForDebugEvent timed out after 200 ms, so an app streaming events with no gap left `detach`
        /// unread until the host gave up and killed it, bytes still planted. This runs the REAL loop against a
        /// source that never times out: `detach`, and `quit` on an ATTACHED engine, must each end the loop on the
        /// first event after they are queued. With the command read in the timeout branch only, neither ends at all.
        /// </summary>
        private static void CheckCommandsNeverStarved(List<string> failures, ClaimLog claims)
        {
            const int Cap = 500;
            Func<uint, DebugEngine> interactive = attachPid =>
                new DebugEngine("protocolcheck", null, null, null, null, false, 0, true, null, attachPid);

            foreach (var c in new[] { new { Cmd = "detach", Pid = 0u, Mode = "launched" },
                                      new { Cmd = "detach", Pid = 4242u, Mode = "attached" },
                                      new { Cmd = "quit", Pid = 4242u, Mode = "attached" } })
            {
                var eng = interactive(c.Pid);
                int served = -2;
                CaptureConsole(() => { served = eng.DebugLoopStarvationForTest(c.Cmd, Cap); });
                if (served < 0)
                    failures.Add("starved: `" + c.Cmd + "` on a " + c.Mode + " engine was never acted on in " + Cap
                                 + " back-to-back events - the loop reads commands only when a wait times out, and a "
                                 + "busy app never lets one time out");
                else if (served != 1)
                    failures.Add("starved: `" + c.Cmd + "` on a " + c.Mode + " engine took " + served
                                 + " events - expected the FIRST event after it was queued to carry the detach");
            }

            claims.Claim("commands are never starved: against the real debug loop fed " + Cap + " back-to-back events "
                         + "(no wait ever times out), `detach` (launched or attached) and `quit` (attached) each detach on "
                         + "the first event after they are queued.");
        }

        /// <summary>
        /// Six ways a detach we called clean could leave the app to crash (3f2d747f, 4b pipeline run 2), each driven
        /// through the REAL code with the one input moved:
        ///   (a) a context operation that FAILS - clearing TF, rewinding EIP - reaches `detached` as an error naming
        ///       the tids and addresses;
        ///   (b) a queued hit on a byte REMOVED before the detach is still ours: the drain rewinds it, and so does the
        ///       debug loop itself (launch mode too) instead of pausing at va+1;
        ///   (c) an unreadable image is not reported as "not x86";
        ///   (d) `--expect-start` with the wrong creation time refuses the attach before anything is planted;
        ///   (e) a detach that throws part-way still sends `detached`, with the error;
        ///   (f) a process that exits during the QUIET detach of a refused attach sends no `exited`: the host would
        ///       show an exit for an app it never attached to (70860d6b C11).
        /// </summary>
        private static void CheckDetachHardening(List<string> failures, ClaimLog claims)
        {
            const uint Ex = Native.EXCEPTION_DEBUG_EVENT, Bp = Native.EXCEPTION_BREAKPOINT;

            // ---- (a) context operations that fail ----
            var sA = new DebugEngine.DetachScenario
            {
                Armed = new uint[] { 0x401000 }, Threads = new uint[] { 7, 8, 9 },
                TfFailTids = new HashSet<uint> { 7, 9 }, EipFailTids = new HashSet<uint> { 101 },
                Queue = new List<byte[]> { DebugEngine.DebugEventForTest(Ex, 101, Bp, 0x401000) },
            };
            CaptureConsole(() => NewEngine().RunDetachScenarioForTest(sA));
            string errA = ErrorMember(sA.Json);
            if (errA == null || errA.IndexOf("TF not cleared on 2 thread(s) (7,9)", StringComparison.Ordinal) < 0)
                failures.Add("detach (a): two threads whose TF could not be cleared are not in detached.error: " + (sA.Json ?? sA.Escaped ?? "(null)"));
            if (errA == null || errA.IndexOf("EIP not rewound at 0x401000 on 101", StringComparison.Ordinal) < 0)
                failures.Add("detach (a): a queued hit whose EIP could not be rewound is not in detached.error: " + (sA.Json ?? sA.Escaped ?? "(null)"));
            // CONTROL: the same scenario with every operation succeeding reports neither (only the no-process restore).
            var sA0 = new DebugEngine.DetachScenario
            {
                Armed = new uint[] { 0x401000 }, Threads = new uint[] { 7, 8, 9 },
                Queue = new List<byte[]> { DebugEngine.DebugEventForTest(Ex, 101, Bp, 0x401000) },
            };
            CaptureConsole(() => NewEngine().RunDetachScenarioForTest(sA0));
            string errA0 = ErrorMember(sA0.Json) ?? "";
            if (errA0.IndexOf("TF not cleared", StringComparison.Ordinal) >= 0 || errA0.IndexOf("EIP not rewound", StringComparison.Ordinal) >= 0)
                failures.Add("detach (a) control: with every context operation succeeding the error still names one: " + errA0);

            // ---- (b) a byte removed before the detach, with a hit on it queued ----
            var sB = new DebugEngine.DetachScenario
            {
                PlantedEver = new uint[] { 0x401300 },     // planted earlier, NOT in _armed now
                Queue = new List<byte[]> { DebugEngine.DebugEventForTest(Ex, 111, Bp, 0x401300) },
            };
            CaptureConsole(() => NewEngine().RunDetachScenarioForTest(sB));
            if (!sB.Continues.Contains("111:0x00010002") || !sB.Rewinds.Contains("111:0x401300"))
                failures.Add("detach (b): a queued hit on a byte planted earlier and already removed was continued "
                             + string.Join(",", sB.Continues) + " with rewinds " + (sB.Rewinds.Count == 0 ? "none" : string.Join(",", sB.Rewinds))
                             + " - expected 111:0x00010002 with a rewind to 0x401300; handed back, the app takes an INT3 at va+1");

            // ...and in the debug loop itself: a stale hit is rewound and continued, not paused on.
            var loopEng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            List<string> lc = null, lr = null;
            CaptureConsole(() => loopEng.OneLoopEventForTest(DebugEngine.DebugEventForTest(Ex, 112, Bp, 0x401300),
                                                             new uint[] { 0x401300 }, out lc, out lr));
            if (lc == null || !lc.Contains("112:0x00010002") || lr == null || !lr.Contains("112:0x401300"))
                failures.Add("stale hit: the debug loop answered a queued hit on a removed breakpoint with continues "
                             + (lc == null ? "(null)" : string.Join(",", lc)) + " and rewinds "
                             + (lr == null || lr.Count == 0 ? "none" : string.Join(",", lr))
                             + " - expected a rewind to 0x401300 and DBG_CONTINUE (a programmatic-break pause would sit at va+1)");
            // CONTROL: an address we never planted is NOT rewound (it is the app's own INT3).
            var loopEng2 = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            List<string> lc2 = null, lr2 = null;
            CaptureConsole(() => loopEng2.OneLoopEventForTest(DebugEngine.DebugEventForTest(Ex, 113, Bp, 0x409999),
                                                              new uint[] { 0x401300 }, out lc2, out lr2));
            if (lr2 == null || lr2.Count != 0)
                failures.Add("stale hit control: an INT3 at an address never planted was rewound: " + (lr2 == null ? "(null)" : string.Join(",", lr2)));

            // ---- (c) the image classification ----
            Action<string, bool, bool, ushort, ProcsCommand.ImageArch, int> arch = (what, wow, ok, mach, want, wantCode) =>
            {
                var got = ProcsCommand.ClassifyProcessImage(wow, ok, mach);
                if (got != want || ProcsCommand.AttachRefusalCode(got) != wantCode)
                    failures.Add("attach image (c): " + what + " -> " + got + " (code " + ProcsCommand.AttachRefusalCode(got)
                                 + "), expected " + want + " (code " + wantCode + ")");
            };
            arch("a process WOW64 does not run", false, false, 0, ProcsCommand.ImageArch.NotX86, 50);
            arch("an x86 process whose image could not be read", true, false, 0, ProcsCommand.ImageArch.Unreadable, 0);
            arch("a WOW64 process whose image is not i386", true, true, ClarionDbg.Core.PeProbe.MachineAmd64, ProcsCommand.ImageArch.NotX86, 50);
            arch("an x86 process with an i386 image", true, true, ClarionDbg.Core.PeProbe.MachineI386, ProcsCommand.ImageArch.X86, 0);

            // ---- (d) --expect-start ----
            Func<DebugEngine> attachEng = () => new DebugEngine("protocolcheck", null, null, null, null, false, 0, true, null, 4242);
            bool planted = true, refused = false;
            string outD = CaptureConsole(() => attachEng().ExpectStartFlowForTest(1000, true, 2000, out planted, out refused));
            if (!refused || planted || outD.IndexOf("\"message\":\"attach failed: process 4242 is not the one listed (pid reused)\",\"code\":0", StringComparison.Ordinal) < 0)
                failures.Add("expect-start (d): a creation-time MISMATCH gave refused=" + refused + " planted=" + planted
                             + " - expected the pid-reused error, exit 2 and nothing planted; output: " + outD.Replace("\r\n", " | "));
            if (outD.IndexOf("\"event\":\"detached\"", StringComparison.Ordinal) >= 0)
                failures.Add("expect-start (d): the refused attach also sent `detached` - the error is the whole answer");
            bool plantedOk = false, refusedOk = true;
            CaptureConsole(() => attachEng().ExpectStartFlowForTest(1000, true, 1000, out plantedOk, out refusedOk));
            if (refusedOk || !plantedOk)
                failures.Add("expect-start (d) control: a MATCHING creation time gave refused=" + refusedOk + " planted=" + plantedOk
                             + " - expected the attach to proceed to planting");
            bool plantedUnread = true, refusedUnread = false;
            CaptureConsole(() => attachEng().ExpectStartFlowForTest(1000, false, 0, out plantedUnread, out refusedUnread));
            if (!refusedUnread || plantedUnread)
                failures.Add("expect-start (d): an UNREADABLE creation time was accepted - it cannot be proven the listed process");

            // ---- (e) a detach that throws part-way ----
            var sE = new DebugEngine.DetachScenario { Armed = new uint[] { 0x401000 }, ThrowAt = "drain" };
            CaptureConsole(() => NewEngine().RunDetachScenarioForTest(sE));
            string errE = ErrorMember(sE.Json);
            if (sE.Escaped != null || errE == null || !errE.StartsWith("detach aborted: planted fault at drain", StringComparison.Ordinal))
                failures.Add("detach (e): a detach that threw at the drain " + (sE.Escaped != null ? "let the exception escape (" + sE.Escaped + ")" : "sent " + (sE.Json ?? "(null)"))
                             + " - expected `detached` with error 'detach aborted: ...'");
            if (!sE.Continues.Contains("0:0x00010002"))
                failures.Add("detach (e): the held event was not continued before the aborted detach let go: " + string.Join(",", sE.Continues));

            // ---- (f) the target exits during the drain of a quiet detach ----
            Func<bool, string> exitDuringDrain = quiet =>
            {
                var sF = new DebugEngine.DetachScenario
                {
                    Quiet = quiet,
                    Queue = new List<byte[]> { DebugEngine.DebugEventForTest(Native.EXIT_PROCESS_DEBUG_EVENT, 121, 0, 0) },
                };
                var engF = NewEngine();
                engF.EmitJson = true;
                return CaptureConsole(() => engF.RunDetachScenarioForTest(sF));
            };
            string outF = exitDuringDrain(true);
            if (outF.IndexOf("\"event\":\"exited\"", StringComparison.Ordinal) >= 0)
                failures.Add("detach (f): a process that exited during the QUIET detach of a refused attach sent `exited` - "
                             + "the host would report an exit for an app it never attached to; output: " + outF.Replace("\r\n", " | "));
            // CONTROL: the same exit during an ordinary detach IS reported.
            string outF0 = exitDuringDrain(false);
            if (outF0.IndexOf("\"event\":\"exited\"", StringComparison.Ordinal) < 0)
                failures.Add("detach (f) control: a process that exited during an ordinary detach sent no `exited`; output: "
                             + outF0.Replace("\r\n", " | "));

            claims.Claim("detach hardening (4b run 2): a failed TF clear or EIP rewind is named in detached.error; a queued hit "
                         + "on a byte planted earlier and removed is rewound by the drain AND by the debug loop (never paused at "
                         + "va+1), while an address never planted is not; an unreadable image is code 0, only a confirmed "
                         + "non-i386 is 50; --expect-start refuses a mismatched or unreadable creation time before anything is "
                         + "planted and a matching one proceeds; a detach that throws still sends `detached` with the error; "
                         + "an exit during the quiet detach of a refused attach sends no `exited`, and during an ordinary one does.");
        }

        /// <summary>The "error" member of a `detached` event, or null when absent (or no event).</summary>
        private static string ErrorMember(string json)
        {
            if (json == null) return null;
            int at = json.IndexOf("\"error\":\"", StringComparison.Ordinal);
            if (at < 0) return null;
            int s = at + 9, e = json.IndexOf('"', s);
            return e > s ? json.Substring(s, e - s) : null;
        }

        private static void ExpectEqual(List<string> failures, string what, string got, string want)
        {
            if (got != want) failures.Add(what + ": " + got + " - expected " + want);
        }
    }
}
