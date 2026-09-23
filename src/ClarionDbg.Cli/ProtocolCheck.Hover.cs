using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    // Identify-thread-by-window (ticket f6e547ce item 0). See ProtocolCheck.cs for the claim registry and the
    // shared helpers (NewEngine, CaptureConsole, HasTopLevelMember) these use.
    internal static partial class ProtocolCheck
    {
        // A hand-built desktop. The debuggee (pid 100) has an MDI frame owned by its frame thread; two MDI
        // children on two browse threads overlap in the middle, child A on top. The IDE is pid 200.
        private const uint HvPid = 100, HvIdePid = 200;
        private const uint HvFrameTid = 11, HvTidA = 22, HvTidB = 33;

        private static HoverWin HvWin(int hwnd, int parent, uint pid, uint tid, int sib, int l, int t, int r, int b)
        {
            return new HoverWin
            {
                Hwnd = new IntPtr(hwnd), Parent = new IntPtr(parent), Pid = pid, Tid = tid, Visible = true,
                Rect = new HoverRect(l, t, r, b), Sib = sib,
            };
        }

        private static readonly HoverWin HvFrame = HvWin(0x10, 0, HvPid, HvFrameTid, 0, 0, 0, 800, 600);

        /// <summary>The frame's tree as HoverWalk records it: the root, the MDI client, child A (z 0), child B
        /// (z 1), and a button inside A.</summary>
        private static List<HoverWin> HvFrameTree()
        {
            return new List<HoverWin>
            {
                HvFrame,
                HvWin(0x11, 0x10, HvPid, HvFrameTid, 0, 0, 50, 800, 600),      // MDI client
                HvWin(0x12, 0x11, HvPid, HvTidA, 0, 0, 50, 400, 400),          // child A, topmost
                HvWin(0x13, 0x11, HvPid, HvTidB, 1, 200, 100, 700, 500),       // child B, under A
                HvWin(0x14, 0x12, HvPid, HvTidA, 0, 10, 60, 90, 90),           // a button in A
            };
        }

        private static uint Hv(List<HoverWin> tops, List<HoverWin> tree, int x, int y)
        {
            return DebugEngine.HoverHitTestForTest(tops, root => root == HvFrame.Hwnd ? tree : new List<HoverWin>(), x, y, HvPid);
        }

        private static void HvExpect(List<string> failures, string what, uint got, uint want)
        {
            if (got != want)
                failures.Add("hover hit-test: " + what + " answered " + (got == 0 ? "none" : "thread " + got)
                             + ", expected " + (want == 0 ? "none" : "thread " + want));
        }

        /// <summary>
        /// The hover hit-test, its event and its bookkeeping, all without a window on screen.
        ///
        /// Every rule is paired with a CONTROL that shows the case was built to matter: the IDE is placed
        /// over the point before asserting it answers none (and the same point without the IDE answers the
        /// thread), and each skipped window (cloaked, click-through, invisible) is shown to swallow the hover
        /// when the flag is cleared. Without the control, a skip test passes against an overlay that was never
        /// over the point.
        /// </summary>
        private static void CheckHoverHitTest(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the hover hit-test answers the topmost debuggee window's thread by z-order and "
                         + "rectangle, answers none when another process's window (the IDE) is on top or a "
                         + "foreign child holds the point, and does not let a cloaked, click-through or "
                         + "invisible window swallow the hover; `hover` is accepted by both loops and its "
                         + "event carries no tid for none; a poll is throttled and emits only on change. "
                         + "Not covered: the Win32 reads themselves, which need the Owner's desktop.");

            var tops = new List<HoverWin> { HvFrame };
            var tree = HvFrameTree();

            // ---- descent by z-order and rectangle
            HvExpect(failures, "the overlap of A (z 0) and B (z 1)", Hv(tops, tree, 300, 200), HvTidA);
            HvExpect(failures, "B where A does not reach", Hv(tops, tree, 600, 450), HvTidB);
            HvExpect(failures, "the frame's toolbar strip, above the MDI client", Hv(tops, tree, 100, 20), HvFrameTid);
            HvExpect(failures, "the button inside A", Hv(tops, tree, 50, 70), HvTidA);
            HvExpect(failures, "a point off every window", Hv(tops, tree, 900, 900), 0);
            // Right and Bottom are exclusive: x=400 is the first column OUTSIDE A, so the overlap point there is B.
            HvExpect(failures, "A's right edge (exclusive)", Hv(tops, tree, 400, 200), HvTidB);

            // Swap the siblings' z-order and the overlap must follow it: the answer comes from Sib, not from
            // list order.
            var swapped = HvFrameTree();
            var a = swapped[2]; a.Sib = 1; swapped[2] = a;
            var b = swapped[3]; b.Sib = 0; swapped[3] = b;
            HvExpect(failures, "the overlap with B raised to z 0", Hv(tops, swapped, 300, 200), HvTidB);

            // ---- the IDE on top
            var ide = HvWin(0x90, 0, HvIdePid, 999, 0, 250, 150, 900, 700);
            var ideOnTop = new List<HoverWin> { ide, HvFrame };
            HvExpect(failures, "a point where the IDE covers child A", Hv(ideOnTop, tree, 300, 200), 0);
            HvExpect(failures, "CONTROL: a point on the frame the IDE does not cover", Hv(ideOnTop, tree, 100, 20), HvFrameTid);
            HvExpect(failures, "the IDE BELOW the frame", Hv(new List<HoverWin> { HvFrame, ide }, tree, 300, 200), HvTidA);

            // ---- windows that must not swallow the hover, each with its control
            var cloaked = ide; cloaked.Cloaked = true;
            HvExpect(failures, "a CLOAKED window above the target", Hv(new List<HoverWin> { cloaked, HvFrame }, tree, 300, 200), HvTidA);
            var overlay = ide; overlay.ClickThrough = true;
            HvExpect(failures, "a click-through overlay above the target", Hv(new List<HoverWin> { overlay, HvFrame }, tree, 300, 200), HvTidA);
            var hidden = ide; hidden.Visible = false;
            HvExpect(failures, "an invisible window above the target", Hv(new List<HoverWin> { hidden, HvFrame }, tree, 300, 200), HvTidA);
            // (The uncloaked, opaque, visible version of the same window is the IDE case above: it answers none.)

            // The same skips one level down: an invisible or click-through child A must let B answer.
            foreach (var flag in new[] { "invisible", "click-through", "cloaked" })
            {
                var t2 = HvFrameTree();
                var ca = t2[2];
                if (flag == "invisible") ca.Visible = false;
                else if (flag == "click-through") ca.ClickThrough = true;
                else ca.Cloaked = true;
                t2[2] = ca;
                HvExpect(failures, "the overlap with child A " + flag, Hv(tops, t2, 300, 200), HvTidB);
            }

            // ---- the style test behind ClickThrough: BOTH bits, neither alone
            if (!DebugEngine.IsClickThroughStyleForTest(0x20 | 0x80000))
                failures.Add("hover: WS_EX_TRANSPARENT|WS_EX_LAYERED was not read as click-through");
            if (DebugEngine.IsClickThroughStyleForTest(0x80000))
                failures.Add("hover: WS_EX_LAYERED alone was read as click-through; an ordinary alpha window "
                             + "takes the mouse and must stay a hit");
            if (DebugEngine.IsClickThroughStyleForTest(0x20))
                failures.Add("hover: WS_EX_TRANSPARENT alone was read as click-through; alone it only changes "
                             + "paint order");

            // ---- a foreign child holding the point is not ours
            var t3 = HvFrameTree();
            t3.Add(HvWin(0x15, 0x12, HvIdePid, 999, 0, 280, 180, 320, 220));   // embedded, another process, in A
            HvExpect(failures, "a foreign-process child inside A", Hv(tops, t3, 300, 200), 0);
            HvExpect(failures, "CONTROL: A beside the foreign child", Hv(tops, t3, 250, 300), HvTidA);

            // ---- a parent cycle in the list terminates
            var cyc = new List<HoverWin>
            {
                HvFrame,
                HvWin(0x20, 0x10, HvPid, HvTidA, 0, 0, 0, 800, 600),
                HvWin(0x21, 0x20, HvPid, HvTidB, 0, 0, 0, 800, 600),
                HvWin(0x20, 0x21, HvPid, HvTidA, 0, 0, 0, 800, 600),
            };
            uint cycAnswer = Hv(tops, cyc, 5, 5);
            if (cycAnswer != HvTidA && cycAnswer != HvTidB)
                failures.Add("hover hit-test: a cyclic list answered " + cycAnswer + " rather than a thread on the cycle");

            // ---- the event
            string known = DebugEngine.HoverJsonForTest(true, true, HvTidA);
            // The expected text is composed through the engine's own tid writer, not typed: a typed thread-id
            // member is what tools/test-engine-tid-members.ps1 fails, in a test file as much as an emitter.
            string knownWant = DebugEngine.AppendTidMemberForTest("{\"event\":\"hover\",\"on\":true,\"paused\":true}", HvTidA);
            if (known != knownWant || !HasTopLevelMember(known, "tid") || !known.EndsWith(":" + HvTidA + "}", StringComparison.Ordinal))
                failures.Add("hover event: a known thread was written as " + known + ", expected " + knownWant);
            foreach (var bad in new[] { 0u, uint.MaxValue })
            {
                string none = DebugEngine.HoverJsonForTest(true, false, bad);
                if (HasTopLevelMember(none, "tid"))
                    failures.Add("hover event: \"none\" (" + bad + ") was written as a tid — " + none);
                if (none != "{\"event\":\"hover\",\"on\":true,\"paused\":false}")
                    failures.Add("hover event: \"none\" was malformed — " + none);
            }

            // ---- the verb, on an engine with no process (the poll answers none without a window read)
            var eng = NewEngine();
            eng.EmitJson = true;
            string on = CaptureConsole(() => eng.HandleHoverCommandForTest("hover on", false));
            if (on.IndexOf("@JSON {\"event\":\"hover\",\"on\":true,\"paused\":false}", StringComparison.Ordinal) < 0)
                failures.Add("hover verb: `hover on` did not answer with its starting state — " + on);
            string again = CaptureConsole(() => eng.HandleHoverCommandForTest("hover on", true));
            if (again.IndexOf("\"paused\":true", StringComparison.Ordinal) < 0)
                failures.Add("hover verb: a second `hover on` (now paused) did not re-announce — " + again);
            string off = CaptureConsole(() => eng.HandleHoverCommandForTest("hover off", true));
            if (off.IndexOf("@JSON {\"event\":\"hover\",\"on\":false,\"paused\":true}", StringComparison.Ordinal) < 0)
                failures.Add("hover verb: `hover off` did not answer on:false — " + off);
            string junk = CaptureConsole(() => eng.HandleHoverCommandForTest("hover sideways", false));
            if (junk.IndexOf("hover expects", StringComparison.Ordinal) < 0 || junk.IndexOf("\"event\":\"hover\"", StringComparison.Ordinal) >= 0)
                failures.Add("hover verb: a bad argument was not refused with an error alone — " + junk);
            if (DebugEngine.IsResumeVerbForTest("hover"))
                failures.Add("hover verb: IsResumeVerb accepts it — it would reset the thread selection while "
                             + "paused and be diverted from its case while running");

            // ---- the tracker: throttle, change-only, reset
            var tr = new HoverTracker();
            if (tr.Due(0, 150)) failures.Add("hover tracker: a poll was due with the mode off");
            tr.Set(true);
            if (!tr.Due(1000, 150)) failures.Add("hover tracker: the first poll after `hover on` was not due");
            if (tr.Due(1149, 150)) failures.Add("hover tracker: a second poll was due inside the interval");
            if (!tr.Due(1150, 150)) failures.Add("hover tracker: a poll was not due once the interval passed");
            if (tr.Due(1200, 150)) failures.Add("hover tracker: the slot was not claimed by the poll that took it");
            if (!tr.Due(99999, 150) || tr.Due(100000, 150))
                failures.Add("hover tracker: after a long gap the next slot is not measured from now (catch-up burst)");
            if (!tr.Changed(HvTidA, true)) failures.Add("hover tracker: the first answer was not emitted");
            if (tr.Changed(HvTidA, true)) failures.Add("hover tracker: an unchanged answer was emitted again");
            if (!tr.Changed(HvTidA, false)) failures.Add("hover tracker: a change of paused state alone was not emitted");
            if (!tr.Changed(0, false)) failures.Add("hover tracker: a change to none was not emitted");
            tr.Set(true);
            if (!tr.Changed(0, false)) failures.Add("hover tracker: `hover on` did not forget the last answer");
            tr.Set(false);
            if (tr.Due(999999, 150)) failures.Add("hover tracker: a poll was due after `hover off`");
        }
    }
}
