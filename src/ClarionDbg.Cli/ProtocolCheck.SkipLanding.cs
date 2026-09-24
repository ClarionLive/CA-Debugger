using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// A NON-PAUSING user breakpoint at a skip's landing still ends the skip (49538b78 wave 5, F2).
        ///
        /// StepMachine plants no temp INT3 where a user breakpoint already sits, at a skipped call's return or
        /// at an ACCEPT loop head, because "it will pause there anyway". A conditional, hit-count or tracepoint
        /// breakpoint often does not: OnUserBp's silent path only re-anchored and set TF, _skipRunning stayed
        /// set, StepMachine never ran again, and the Step Over ran free. Drives the REAL OnUserBp through
        /// OnUserBpForTest with an invented ESP/EBP, and the loop-head choice through the pure
        /// DebugEngine.LoopHeadWatchFor.
        ///
        /// FIVE CASES. The two landings (a covered return; an End skip's loop head, which also restores the
        /// return's temp and re-bases the ESP gate) are the bug. The deeper hit, the other thread's hit and a
        /// hit at neither landing keep the landing test from passing by ending every skip.
        ///
        /// NOT COVERED: the STOP route (IsStepStop needs a line table, so these reach the resume route), and
        /// what EventLoopBackEdgeTargetAt reads from the image.
        /// </summary>
        private static void CheckSilentBpAtSkipLanding(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a non-pausing user breakpoint (here a tracepoint) at the stepping thread's skip landing ends "
                         + "the skip as a temp INT3 would: at a covered call return (the step resumes, anchored there) "
                         + "and at an End skip's loop head (the return's temp is restored, the ESP baseline re-based); "
                         + "a deeper hit through the same return, a hit on another thread and a hit at neither "
                         + "landing leave the skip running; a loop head holding a user breakpoint is watched through "
                         + "it, not planted. Not covered: the stop route, the back-edge read.");

            // Not multiples of 4, so Windows never assigns them (see CheckStepAnchorBelongsToSteppingThread).
            const uint stepTid = 0xFFFFFFF1;
            const uint otherTid = 0xFFFFFFF5;
            const uint loadBase = 0x00400000;
            const uint prevVa = 0x00401000;
            const uint retVa = 0x00401100;       // the skipped call's return, carrying a tracepoint
            const uint elsewhere = 0x00401300;   // a tracepoint at neither landing
            const uint entryEsp = 0x0012F000;
            const uint frameEbp = 0x0012F100;

            // ---- case 1: THE BUG at the call-skip site. The return is covered by a tracepoint, so no temp.
            var a = NewEngine();
            a.ArmUserBpForTest(loadBase, retVa, null, null, 0, "landing probe");
            a.ArmUserBpForTest(loadBase, elsewhere, null, null, 0, "elsewhere probe");
            ArmCoveredSkip(a, stepTid, prevVa, retVa, 0, entryEsp, frameEbp, 0);
            string log = CaptureConsole(() => SeamOutcome(() => a.OnUserBpForTest(stepTid, retVa, entryEsp + 4, frameEbp)));
            if (log.IndexOf("[TRACE] pc001.clw:100: landing probe", StringComparison.Ordinal) < 0)
                failures.Add("skip landing control: the tracepoint never logged, so the hit did not take the silent "
                             + "path: " + log.Replace("\r\n", " | "));
            if (!a.StepInFlightForTest)
                failures.Add("skip landing control: a silent hit cancelled the step");
            if (a.SkipRunningForTest)
                failures.Add("skip landing: a tracepoint at a covered call return left the skip running - StepMachine "
                             + "never runs again and the Step Over runs free");
            if (a.PrevVaForTest != retVa)
                failures.Add("skip landing: the resumed step is not anchored at the return 0x" + retVa.ToString("X")
                             + " (anchor 0x" + a.PrevVaForTest.ToString("X") + ")");

            // ---- case 2: THE BUG at the loop head. End's return has its temp; the head carries a tracepoint.
            const uint endRet = 0x00401200;
            const uint head = 0x00401180;
            var lh = NewEngine();
            lh.ArmUserBpForTest(loadBase, head, null, null, 0, "loop head probe");
            lh.ArmStepOverSessionForTest(stepTid, prevVa, endRet);
            lh.ArmCallSkipForTest(endRet, head, entryEsp + 0x100, entryEsp, frameEbp, 2);
            const uint passEsp = entryEsp - 0xFC;   // the ACCEPT body's depth on the next pass
            SeamOutcome(() => lh.OnUserBpForTest(stepTid, head, passEsp, frameEbp));
            if (lh.SkipRunningForTest || lh.TempBpCountForTest != 0 || lh.StartEspForTest != passEsp)
                failures.Add("skip landing: a tracepoint at the End skip's loop head did not end the skip (skipRunning "
                             + lh.SkipRunningForTest + ", temps " + lh.TempBpCountForTest + ", ESP baseline 0x"
                             + lh.StartEspForTest.ToString("X") + ", want 0x" + passEsp.ToString("X") + ")");

            // ---- case 3: a deeper frame returning through the same address is not the landing.
            var d = NewEngine();
            d.ArmUserBpForTest(loadBase, retVa, null, null, 0, "landing probe");
            ArmCoveredSkip(d, stepTid, prevVa, retVa, 0, entryEsp, frameEbp, 0);
            SeamOutcome(() => d.OnUserBpForTest(stepTid, retVa, entryEsp - 0x40, frameEbp));
            if (!d.SkipRunningForTest)
                failures.Add("skip landing: a deeper (recursive) hit through the covered return ended the skip");

            // ---- case 4: another thread passing the landing has no skip of its own.
            var o = NewEngine();
            o.ArmUserBpForTest(loadBase, retVa, null, null, 0, "landing probe");
            ArmCoveredSkip(o, stepTid, prevVa, retVa, 0, entryEsp, frameEbp, 0);
            SeamOutcome(() => o.OnUserBpForTest(otherTid, retVa, entryEsp + 4, frameEbp));
            if (!o.SkipRunningForTest || o.PrevVaForTest != prevVa)
                failures.Add("skip landing: a tracepoint hit on ANOTHER thread ended the stepping thread's skip");

            // ---- case 5: the stepping thread's silent hit at neither landing.
            var n = NewEngine();
            n.ArmUserBpForTest(loadBase, retVa, null, null, 0, "landing probe");
            n.ArmUserBpForTest(loadBase, elsewhere, null, null, 0, "elsewhere probe");
            ArmCoveredSkip(n, stepTid, prevVa, retVa, 0, entryEsp, frameEbp, 0);
            SeamOutcome(() => n.OnUserBpForTest(stepTid, elsewhere, entryEsp + 4, frameEbp));
            if (!n.SkipRunningForTest)
                failures.Add("skip landing: a tracepoint that is neither the return nor the loop head ended the skip");

            // ---- the loop-head choice.
            var W = DebugEngine.LoopHeadWatch.None;
            Action<string, DebugEngine.LoopHeadWatch, DebugEngine.LoopHeadWatch> expect = (what, got, want) =>
            {
                if (got != want) failures.Add("loop head: " + what + ": got " + got + ", want " + want);
            };
            expect("a head holding a user breakpoint", DebugEngine.LoopHeadWatchFor(head, endRet, true, false),
                   DebugEngine.LoopHeadWatch.UserBreakpoint);
            expect("a free head", DebugEngine.LoopHeadWatchFor(head, endRet, false, false), DebugEngine.LoopHeadWatch.PlantTemp);
            expect("a head holding another temp", DebugEngine.LoopHeadWatchFor(head, endRet, false, true), W);
            expect("no back-edge", DebugEngine.LoopHeadWatchFor(0, endRet, false, false), W);
            expect("a head that is the return", DebugEngine.LoopHeadWatchFor(endRet, endRet, true, false), W);

            // ---- the new overload refuses an attached engine.
            var hProcField = typeof(DebugEngine).GetField("_hProcess",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (hProcField == null) { failures.Add("skip landing control: DebugEngine._hProcess not found"); return; }
            var att = NewEngine();
            hProcField.SetValue(att, new IntPtr(0x1234));
            string o1 = SeamOutcome(() => att.OnUserBpForTest(stepTid, retVa, entryEsp + 4, frameEbp));
            if (o1 != null) failures.Add("skip landing seam-guard: OnUserBpForTest(esp, ebp) " + o1 + " against an ATTACHED engine");
        }

        /// <summary>A Step Over skipping a call whose return <paramref name="retVa"/> a user breakpoint covers:
        /// the session with no temp of its own, then the run-to-return state.</summary>
        private static void ArmCoveredSkip(DebugEngine e, uint tid, uint prevVa, uint retVa, uint loopHeadVa,
                                           uint entryEsp, uint entryEbp, int kind)
        {
            e.ArmStepOverSessionForTest(tid, prevVa, 0);
            e.ArmCallSkipForTest(retVa, loopHeadVa, entryEsp + 4, entryEsp, entryEbp, kind);
        }
    }
}
