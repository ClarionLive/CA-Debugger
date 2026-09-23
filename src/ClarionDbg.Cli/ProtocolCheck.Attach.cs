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

        private static void ExpectEqual(List<string> failures, string what, string got, string want)
        {
            if (got != want) failures.Add(what + ": " + got + " - expected " + want);
        }
    }
}
