using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    // Engine-correctness checks added by wave 3 stream A (ticket f367a04f). See ProtocolCheck.cs for the
    // claim registry and the shared helpers (NewEngine, CaptureConsole) these use.
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The call-entry anchor belongs to the STEPPING thread (f367a04f item 1).
        ///
        /// A silently-resumed breakpoint hit re-anchors <c>_prevVa</c> on the hit address, so the re-arm trap
        /// that follows is not read as a call entry. That is right for the thread that is stepping, and wrong
        /// for every other: StepMachine runs for <c>tid == _stepTid</c> alone, so a tracepoint firing on
        /// thread B has no step to re-anchor, and writing the anchor anyway moved thread A's to an address A
        /// never executed.
        ///
        /// TWO CASES, and the second is not optional. The first (a thread-B hit leaves A's anchor alone) is
        /// the bug. On its own it would also pass against a guard that never lets the write through at all -
        /// `if (false &amp;&amp; ...)` - so the second asserts that a hit on the stepping thread itself STILL
        /// re-anchors.
        /// </summary>
        private static void CheckStepAnchorBelongsToSteppingThread(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a silently-resumed breakpoint hit re-anchors the step's call-entry detector only "
                         + "on the STEPPING thread: a tracepoint on another thread leaves the anchor and the "
                         + "step session untouched, and one on the stepping thread still moves the anchor to "
                         + "the hit address. Not covered: what StepMachine's next trap does with the anchor.");

            // Neither is a multiple of 4, so Windows never assigns them: OpenThread fails, haveCtx stays
            // false, and no thread on this machine is touched (same reasoning as CheckBpHitVsStep).
            const uint stepTid = 0xFFFFFFF1;   // thread A, the one stepping
            const uint otherTid = 0xFFFFFFF5;  // thread B, which hits the tracepoint
            const uint loadBase = 0x00400000;
            const uint va = 0x00401100;        // the tracepoint's address, where both hits arrive
            const uint prevVa = 0x00401000;    // thread A's anchor: its previous trap's EIP
            const uint tempVa = 0x00402000;    // thread A's call-skip temp INT3

            // ---- case 1: THE BUG. Thread B hits a tracepoint while thread A is mid-Step-Over.
            var eng = NewEngine();
            eng.ArmUserBpForTest(loadBase, va, null, null, 0, "other-thread probe");
            eng.ArmStepOverSessionForTest(stepTid, prevVa, tempVa);
            string log = CaptureConsole(() => { eng.OnUserBpForTest(otherTid, va); });

            // CONTROLS: the hit reached the non-pausing path, on thread B.
            if (log.IndexOf("[TRACE] pc001.clw:100: other-thread probe", StringComparison.Ordinal) < 0)
                failures.Add("step-anchor control: the thread-B tracepoint never logged - this case did not "
                             + "reach the silent-resume path: " + log.Replace("\r\n", " | "));
            if (!eng.HasUserBpRearmForTest(otherTid, va))
                failures.Add("step-anchor control: no user-breakpoint re-plant was scheduled for thread B, "
                             + "so the hit did not run as thread B");
            if (!eng.StepInFlightForTest)
                failures.Add("step-anchor control: a thread-B tracepoint cancelled thread A's step, so the "
                             + "anchor assertion below would be about a session that no longer exists");

            if (eng.PrevVaForTest != prevVa)
                failures.Add("step-anchor: a silently-resumed hit on thread B moved thread A's call-entry "
                             + "anchor from 0x" + prevVa.ToString("X") + " to 0x" + eng.PrevVaForTest.ToString("X")
                             + " - A's next trap tests `ret > _prevVa` against an address A never ran, and "
                             + "can read an ordinary instruction as a call entry");

            // ---- case 2: the stepping thread's own hit still re-anchors. Without it a guard that blocks
            // the write for EVERY thread passes case 1.
            var own = NewEngine();
            own.ArmUserBpForTest(loadBase, va, null, null, 0, "own-thread probe");
            own.ArmStepOverSessionForTest(stepTid, prevVa, tempVa);
            string ownLog = CaptureConsole(() => { own.OnUserBpForTest(stepTid, va); });
            if (ownLog.IndexOf("[TRACE] pc001.clw:100: own-thread probe", StringComparison.Ordinal) < 0)
                failures.Add("step-anchor control: the thread-A tracepoint never logged - this case did not "
                             + "reach the silent-resume path: " + ownLog.Replace("\r\n", " | "));
            if (own.PrevVaForTest != va)
                failures.Add("step-anchor: a silently-resumed hit on the STEPPING thread left its anchor at 0x"
                             + own.PrevVaForTest.ToString("X") + " instead of the hit address 0x"
                             + va.ToString("X") + " - the thread guard is blocking the re-anchor it exists "
                             + "to scope, not scoping it");
        }
    }
}
