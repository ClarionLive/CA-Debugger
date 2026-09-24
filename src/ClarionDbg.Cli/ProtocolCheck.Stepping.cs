using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    // Stepping across ACCEPT's event-loop calls (wave 5, ticket 0f16e12c). See ProtocolCheck.cs for the claim
    // registry and the shared helpers (NewEngine, SeamOutcome) these use.
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// Step Over on an ACCEPT line, and on its END (0f16e12c).
        ///
        /// ClaRUN keeps the event loop's state on the procedure's own stack, so Cla$StartEventLoop returns with
        /// ESP well below its call site, and Cla$EndEventLoop, when the loop goes round, resumes at the loop
        /// head rather than returning. The step machine now names the skipped call at plant time, and for the
        /// two event-loop calls decides "returned" on the frame (EBP), re-bases the step's ESP gate on the ESP
        /// the call left, and for End also catches the loop head.
        ///
        /// FOUR LAYERS: the two pure readers over hand-assembled bytes (the call's kind, the back-edge's loop
        /// head); the skip-return decision through the REAL OnTempBp; the gate the re-base feeds; and the
        /// unchanged cases next to each new one (an ordinary call still decides on ESP and never re-bases, a
        /// deeper activation still re-arms, and another thread still leaves the step alone). The step machine's
        /// plant-time wiring is covered live, by tools/test-interactive.ps1's ACCEPT cases.
        /// </summary>
        private static void CheckEventLoopStepOver(List<string> failures, ClaimLog claims)
        {
            claims.Claim("stepping across ACCEPT: `call [slot]` is named Start/End/other by its IAT slot and must "
                         + "end at the return address seen; `cmp al,0; je T` after End yields T and nothing else "
                         + "does; a Start or End skip ends when EBP is back at the stepping frame whatever ESP says, "
                         + "and re-bases the step's ESP baseline so the loop body passes the Over gate; an End skip "
                         + "ending at either of its temps removes the other; an ordinary call still decides on ESP "
                         + "and never re-bases; a deeper activation re-arms; another thread changes nothing. "
                         + "Not covered here: the plant-time wiring (live suite).");

            // ---- layer 1: which call is this?
            const uint startSlot = 0x004E1960;   // clbrws's real Start slot (call dword [4E1960h] at 0x4754F8)
            const uint endSlot = 0x004E1964;
            const uint otherSlot = 0x004E1968;
            Func<uint, string> slotName = a => a == startSlot ? "ClaRUN.dll!Cla$StartEventLoop"
                                             : a == endSlot ? "ClaRUN.dll!Cla$EndEventLoop"
                                             : a == otherSlot ? "ClaRUN.dll!Cla$PushLong" : null;
            Func<uint, byte[]> callSlot = slot =>
            {
                var b = new byte[6];
                b[0] = 0xFF; b[1] = 0x15;
                BitConverter.GetBytes(slot).CopyTo(b, 2);
                return b;
            };
            const uint callVa = 0x004754F8, retVa = 0x004754FE;
            Action<string, byte[], uint, int> kind = (what, code, ret, want) =>
            {
                int got = DebugEngine.EventLoopCallKind(code, code.Length, callVa, ret, slotName);
                if (got != want)
                    failures.Add("event-loop call kind: " + what + " read as " + got + ", expected " + want);
            };
            kind("call [Start slot]", callSlot(startSlot), retVa, 1);
            kind("call [End slot]", callSlot(endSlot), retVa, 2);
            kind("call [another ClaRUN import]", callSlot(otherSlot), retVa, 0);
            kind("call rel32", new byte[] { 0xE8, 0, 0, 0, 0, 0x90 }, callVa + 5, 0);
            // The Start slot as a displacement off a register is not a call THROUGH the slot (IsAbsoluteSlotCall,
            // which ProveCallsBalanced shares).
            var viaBase = callSlot(startSlot); viaBase[1] = 0x90;                 // call dword [eax+disp32]
            kind("call [eax + Start slot]", viaBase, retVa, 0);
            var viaIndex = new byte[] { 0xFF, 0x14, 0x85, 0, 0, 0, 0 };          // call dword [eax*4+disp32]
            BitConverter.GetBytes(startSlot).CopyTo(viaIndex, 3);
            kind("call [eax*4 + Start slot]", viaIndex, callVa + 7, 0);
            // The right slot, but the return address the step machine saw is not where this call ends: it is
            // not the call that was entered, and must not be named as one.
            kind("call [Start slot] whose decode does not end at the return address", callSlot(startSlot), retVa + 1, 0);

            // ---- layer 1b: the loop head of End's back-edge
            const uint at = 0x004756A3;   // End's return address in clbrws SplashScreen
            Action<string, byte[], uint> head = (what, code, want) =>
            {
                uint got = DebugEngine.EventLoopBackEdgeTarget(code, code.Length, at);
                if (got != want)
                    failures.Add("event-loop back-edge: " + what + " gave 0x" + got.ToString("X") + ", expected 0x" + want.ToString("X"));
            };
            // cmp al,0 (3C 00) + je rel32 back to 0x4754FE: the shape clbrws has at 0x4756A3.
            uint rel = unchecked(retVa - (at + 2 + 6));   // backwards, so it wraps: rel32 is two's complement
            var real = new byte[] { 0x3C, 0x00, 0x0F, 0x84, 0, 0, 0, 0 };
            BitConverter.GetBytes(rel).CopyTo(real, 4);
            head("3C 00 / je rel32 (clbrws)", real, retVa);
            head("80 F8 00 / je rel8", new byte[] { 0x80, 0xF8, 0x00, 0x74, 0x10 }, at + 5 + 0x10);
            head("cmp al,1 / je", new byte[] { 0x3C, 0x01, 0x74, 0x10 }, 0);
            head("cmp al,0 / jne", new byte[] { 0x3C, 0x00, 0x75, 0x10 }, 0);
            head("cmp al,0 / je cut short", new byte[] { 0x3C, 0x00, 0x0F, 0x84, 0x00 }, 0);

            // ---- layer 2: the skip-return decision, through the REAL OnTempBp
            const uint stepTid = 0xFFFFFFF1, otherTid = 0xFFFFFFF5;   // never assigned by Windows
            const uint prevVa = 0x004754F8;
            const uint loopHead = retVa;           // End's second way back is Start's return address
            const uint endRet = at;
            const uint startEsp = 0x0012FE6C;      // ESP on the ACCEPT line (clbrws, 2026-09-24)
            const uint entryEsp = startEsp - 4;    // at the callee's entry, the return address pushed
            const uint frameEbp = 0x0012FEB8;
            const uint bodyEsp = startEsp - 0x12C; // the body's ESP on the first pass, measured the same run

            Func<uint, uint, int, DebugEngine> armed = (ret, loopHeadVa, k) =>
            {
                var e = NewEngine();
                e.ArmStepOverSessionForTest(stepTid, prevVa, ret);
                e.ArmCallSkipForTest(ret, loopHeadVa, startEsp, entryEsp, frameEbp, k);
                return e;
            };
            Func<DebugEngine, string> state = e => "temps " + e.TempBpCountForTest + ", skipRunning "
                + e.SkipRunningForTest + ", start ESP 0x" + e.StartEspForTest.ToString("X");

            // 2a. THE BUG: Start returns LOW, on our frame. It has returned, and the gate moves to the body.
            var st = armed(retVa, 0, 1);
            string outcome = SeamOutcome(() => st.OnTempBpForTest(stepTid, retVa, bodyEsp, frameEbp));
            if (outcome != "returned without refusing")
                failures.Add("event-loop control: OnTempBpForTest " + (outcome ?? "refused") + " on an engine with no target");
            if (st.TempBpCountForTest != 0 || st.SkipRunningForTest)
                failures.Add("event-loop: Start's return on the stepping frame, at ESP 0x" + bodyEsp.ToString("X")
                             + " below its call site, was not taken as the return (" + state(st) + ") - the step "
                             + "re-arms at the loop head on every pass and never stops");
            if (st.StartEspForTest != bodyEsp)
                failures.Add("event-loop: Start's return did not move the step's ESP baseline to the body's ESP ("
                             + state(st) + ") - the Over gate then refuses every statement of the loop body");

            // 2b. ...and what the re-base is FOR: the body's first statement passes the Over gate. The control
            // is the same stop against the ACCEPT line's ESP, which it must fail, or the re-base proves nothing.
            if (!DebugEngine.PassesEspGateForTest(false, bodyEsp, st.StartEspForTest))
                failures.Add("event-loop: a body statement at ESP 0x" + bodyEsp.ToString("X")
                             + " fails the Over gate after the re-base");
            if (DebugEngine.PassesEspGateForTest(false, bodyEsp, startEsp))
                failures.Add("event-loop control: the body's ESP passes the Over gate even against the ACCEPT "
                             + "line's ESP, so the re-base assertion above tests nothing");

            // 2c. A deeper activation of the same procedure through the same return address: its own EBP.
            var deep = armed(retVa, 0, 1);
            SeamOutcome(() => deep.OnTempBpForTest(stepTid, retVa, bodyEsp - 0x400, frameEbp - 0x400));
            if (deep.TempBpCountForTest != 1 || !deep.SkipRunningForTest || deep.StartEspForTest != startEsp
                || !deep.HasTempRearmForTest(stepTid, retVa))
                failures.Add("event-loop: a DEEPER activation (its own EBP) reaching Start's return address ended "
                             + "the skip (" + state(deep) + ") - EBP is not what decided");

            // 2d. An ordinary call is unchanged: ESP decides, whatever EBP says, and nothing re-bases.
            var low = armed(retVa, 0, 0);
            SeamOutcome(() => low.OnTempBpForTest(stepTid, retVa, bodyEsp, frameEbp));
            if (low.TempBpCountForTest != 1 || !low.SkipRunningForTest || !low.HasTempRearmForTest(stepTid, retVa))
                failures.Add("event-loop: an ORDINARY call reaching its return address below its call site, with "
                             + "the frame's EBP, ended the skip (" + state(low) + ") - the EBP rule leaked past the "
                             + "event-loop calls");
            var high = armed(retVa, 0, 0);
            SeamOutcome(() => high.OnTempBpForTest(stepTid, retVa, entryEsp + 4, frameEbp));
            if (high.TempBpCountForTest != 0 || high.SkipRunningForTest || high.StartEspForTest != startEsp)
                failures.Add("event-loop: an ORDINARY call's return (" + state(high) + ") either did not end the "
                             + "skip or re-based the ESP gate");

            // 2e. End: whichever temp the frame reaches first ends the skip and takes the other one out.
            foreach (var hit in new[] { loopHead, endRet })
            {
                var end = armed(endRet, loopHead, 2);
                if (end.TempBpCountForTest != 2)
                    failures.Add("event-loop control: an End skip armed with its loop head holds "
                                 + end.TempBpCountForTest + " temp(s), expected 2");
                uint esp = bodyEsp + 0x30;   // the next pass: the first ran 0x30 deeper (measured 2026-09-24)
                SeamOutcome(() => end.OnTempBpForTest(stepTid, hit, esp, frameEbp));
                string where = hit == loopHead ? "the loop head" : "its own return address";
                if (end.TempBpCountForTest != 0 || end.SkipRunningForTest)
                    failures.Add("event-loop: an End skip ending at " + where + " left " + state(end)
                                 + " - a temp left planted fires later as a skip return with no skip behind it");
                if (end.StartEspForTest != esp)
                    failures.Add("event-loop: an End skip ending at " + where + " did not re-base the ESP gate ("
                                 + state(end) + ")");
            }

            // 2f. Another thread through Start's return address, with our EBP by coincidence: still not ours.
            var other = armed(retVa, 0, 1);
            SeamOutcome(() => other.OnTempBpForTest(otherTid, retVa, bodyEsp, frameEbp));
            if (other.TempBpCountForTest != 1 || !other.SkipRunningForTest || other.StartEspForTest != startEsp)
                failures.Add("event-loop: another thread reaching Start's return address changed the stepping "
                             + "thread's skip (" + state(other) + ")");
        }
    }
}
