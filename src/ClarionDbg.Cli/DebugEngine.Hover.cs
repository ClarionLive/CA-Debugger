using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ClarionDbg.Cli
{
    /// <summary>A screen point, as GetCursorPos writes it.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct HoverPoint { public int X; public int Y; }

    /// <summary>A window rectangle in screen coordinates, as GetWindowRect writes it. Right and Bottom are
    /// EXCLUSIVE, which is the Win32 convention (PtInRect agrees).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct HoverRect
    {
        public int Left; public int Top; public int Right; public int Bottom;
        public HoverRect(int l, int t, int r, int b) { Left = l; Top = t; Right = r; Bottom = b; }
        public bool Contains(int x, int y) { return x >= Left && x < Right && y >= Top && y < Bottom; }
    }

    /// <summary>One window as the hover hit-test sees it. Only what the hit-test reads: no class name and
    /// no caption, because this runs every 150 ms and those are the expensive reads in WinInfo.</summary>
    internal struct HoverWin
    {
        public IntPtr Hwnd; public IntPtr Parent; public uint Pid; public uint Tid; public bool Visible;
        public HoverRect Rect;
        public int Sib;     // z-rank among its siblings, 0 = topmost (GW_CHILD, then GW_HWNDNEXT)
        public bool Cloaked;       // DWM hides it: visible by IsWindowVisible, but nothing is on screen
        public bool ClickThrough;  // WS_EX_TRANSPARENT and WS_EX_LAYERED: drawn, but the mouse passes through
    }

    /// <summary>The hover mode's bookkeeping, kept apart from Win32 so protocolcheck can drive it: WHEN a poll
    /// is due, and WHETHER an answer is new enough to emit.</summary>
    internal sealed class HoverTracker
    {
        internal bool On;
        private long _next;                    // Stopwatch timestamp before which a poll is not due
        private bool _haveLast; private uint _lastTid; private bool _lastPaused;

        /// <summary>Turn the mode on or off. Either way the last answer is forgotten, so the first poll after
        /// `hover on` always emits (the page needs a starting state) and a stale answer from a previous
        /// session of the mode can never suppress it.</summary>
        internal void Set(bool on) { On = on; _next = 0; _haveLast = false; }

        /// <summary>A new stop: forget the last answer and make the next poll due at once, so every stop gets
        /// exactly ONE fresh answer. Without this, whether a stop announced itself depended on how long the
        /// step took: a step under the poll interval ran no running-state poll, so the stop's (tid, paused)
        /// matched the previous stop's and was suppressed, while a longer step emitted (X, running) and then
        /// (X, paused). The page treats that first answer as a baseline and never selects from it.</summary>
        internal void Forget() { _next = 0; _haveLast = false; }

        /// <summary>True when a poll is due at <paramref name="now"/>; claims the slot, so the next one is due
        /// <paramref name="interval"/> later. Measured from NOW, not from the previous slot: after a long
        /// debug event the mode must not fire a burst of catch-up polls.</summary>
        internal bool Due(long now, long interval)
        {
            if (!On || now < _next) return false;
            _next = now + interval;
            return true;
        }

        /// <summary>Record an answer; true when it differs from the last one emitted. The answer is the
        /// thread (0 = none) AND whether we are paused, because the page does different things with the same
        /// thread in the two states (select versus report).</summary>
        internal bool Changed(uint tid, bool paused)
        {
            if (_haveLast && tid == _lastTid && paused == _lastPaused) return false;
            _haveLast = true; _lastTid = tid; _lastPaused = paused;
            return true;
        }
    }

    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------ identify-thread-by-window (f6e547ce)
        //
        // `hover on` makes the engine report which of the debuggee's threads owns the window under the mouse.
        // While paused, the page uses it to select that thread; while running it can only report.
        //
        // THE ENGINE POLLS; NOTHING IS HOOKED (Owner decision, 2026-09-22). There is no mouse hook, no IDE
        // timer and no host-side window lookup. The engine already wakes at least every 200 ms while the
        // target runs and every 20 ms while it is paused, so both loops call PollHover on every pass and the
        // tracker throttles it to HOVER_POLL_MS by timestamp. An event goes out only when the answer changes.
        //
        // THE HIT-TEST SENDS NOTHING. Its inputs are GetCursorPos, EnumWindows (true z-order, topmost first),
        // IsWindowVisible, GetWindowRect, GetWindow, GetWindowThreadProcessId and GetWindowLongW, plus
        // DwmGetWindowAttribute (which asks DWM, not the window): all state reads, blessed with the
        // prohibition above the user32 imports in DebugEngine.Threads.cs. It makes its OWN EnumWindows pass
        // over EVERY process's top-level windows, not EnumerateTargetWindows, because "is the debuggee's
        // window the one on top here" cannot be answered from the debuggee's windows alone:
        // when the IDE covers the point, the answer is "none", not the debuggee window underneath.

        private const int HOVER_POLL_MS = 150;
        private readonly HoverTracker _hover = new HoverTracker();

        // The target's window trees, per top-level root, reused for the rest of a stop: the target is frozen,
        // so its windows cannot move, open or close. OTHER processes' windows are not cached, since the IDE
        // moves while we are paused. Cleared on every running-loop pass, and every stop is preceded by one.
        private readonly Dictionary<IntPtr, List<HoverWin>> _hoverTrees = new Dictionary<IntPtr, List<HoverWin>>();

        /// <summary>hover on|off. Accepted in both loops. `on` answers at once with the current state; `off`
        /// answers with on:false so the page can clear what it shows.</summary>
        private void HandleHoverCommand(string[] parts, bool paused)
        {
            string arg = parts.Length > 1 ? parts[1].ToLowerInvariant() : "";
            if (arg == "on")
            {
                _hover.Set(true);
                PollHover(paused);
            }
            else if (arg == "off")
            {
                _hover.Set(false);
                _hoverTrees.Clear();
                if (EmitJson) Console.WriteLine("@JSON " + HoverJson(false, paused, 0));
                else Console.WriteLine("  hover: off");
            }
            else EmitError("hover expects: hover on|off");
        }

        /// <summary>Every stop, from the top of PausedWait. See HoverTracker.Forget.</summary>
        private void HoverNewStop() { _hover.Forget(); }

        /// <summary>Called on EVERY pass of both loops; cheap unless the mode is on and a poll is due. Never
        /// throws: a failed read answers "none" rather than taking a debug loop down with it.</summary>
        private void PollHover(bool paused)
        {
            if (!paused) _hoverTrees.Clear();
            if (!_hover.Due(Stopwatch.GetTimestamp(), Stopwatch.Frequency * HOVER_POLL_MS / 1000)) return;
            uint tid;
            try { tid = HoverTidUnderCursor(paused); }
            catch (Exception) { tid = 0; }
            if (!_hover.Changed(tid, paused)) return;
            if (EmitJson) Console.WriteLine("@JSON " + HoverJson(true, paused, tid));
            else Console.WriteLine("  hover: " + (TidIsKnown(tid) ? "thread " + TidText(tid) : "no debuggee window under the cursor"));
        }

        private uint HoverTidUnderCursor(bool paused)
        {
            uint pid = ProcessId();
            if (pid == 0) return 0;
            HoverPoint pt;
            if (!GetCursorPos(out pt)) return 0;     // fails on a secure desktop (UAC, lock screen)
            return HoverHitTest(EnumerateTopLevelForHover(), root => HoverTreeFor(root, pid, paused), pt.X, pt.Y, pid);
        }

        /// <summary>Every VISIBLE top-level window on the desktop, every process, in EnumWindows order, which is
        /// z-order with the topmost first.</summary>
        private static List<HoverWin> EnumerateTopLevelForHover()
        {
            var list = new List<HoverWin>();
            EnumWindows((h, l) =>
            {
                if (!IsWindowVisible(h)) return true;
                HoverRect rc;
                if (!GetWindowRect(h, out rc)) return true;
                uint p; uint t = GetWindowThreadProcessId(h, out p);
                list.Add(new HoverWin { Hwnd = h, Pid = p, Tid = t, Visible = true, Rect = rc, Sib = list.Count,
                                        Cloaked = IsCloaked(h), ClickThrough = IsClickThrough(h) });
                return true;
            }, IntPtr.Zero);
            return list;
        }

        private IList<HoverWin> HoverTreeFor(IntPtr root, uint pid, bool paused)
        {
            List<HoverWin> tree;
            if (paused && _hoverTrees.TryGetValue(root, out tree)) return tree;
            tree = new List<HoverWin>();
            HoverWalk(tree, root, IntPtr.Zero, pid, 0, 0);
            if (paused) _hoverTrees[root] = tree;
            return tree;
        }

        /// <summary>The same GetWindow walk as WalkWindow, and under the same depth and per-root caps, minus
        /// the class and caption reads. A window of ANOTHER process is recorded (so the hit-test can see that
        /// the point is over something that is not ours) but not descended into.</summary>
        private static void HoverWalk(List<HoverWin> list, IntPtr h, IntPtr parent, uint pid, int sib, int depth)
        {
            if (h == IntPtr.Zero || depth > WIN_MAX_DEPTH || list.Count >= WIN_MAX_PER_ROOT) return;
            uint p; uint t = GetWindowThreadProcessId(h, out p);
            bool vis = IsWindowVisible(h);
            HoverRect rc;
            if (!GetWindowRect(h, out rc)) { rc = new HoverRect(); vis = false; }
            list.Add(new HoverWin { Hwnd = h, Parent = parent, Pid = p, Tid = t, Visible = vis, Rect = rc, Sib = sib,
                                    ClickThrough = vis && IsClickThrough(h) });
            if (p != pid || !vis) return;           // an invisible window's children cannot be under the cursor
            int i = 0;
            for (IntPtr c = GetWindow(h, GW_CHILD); c != IntPtr.Zero && list.Count < WIN_MAX_PER_ROOT; c = GetWindow(c, GW_HWNDNEXT))
                HoverWalk(list, c, h, pid, i++, depth + 1);
        }

        private const int DWMWA_CLOAKED = 14;
        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_TRANSPARENT = 0x20;
        private const int WS_EX_LAYERED = 0x80000;

        /// <summary>True when DWM reports the window cloaked. FAILS OPEN, to "not cloaked": a missing
        /// dwmapi.dll or a failed call leaves the window a candidate, which at worst reproduces the behaviour
        /// without this check (a hidden window swallowing the hover) rather than skipping a window the user
        /// can actually see.</summary>
        private static bool IsCloaked(IntPtr h)
        {
            try
            {
                int v;
                return DwmGetWindowAttribute(h, DWMWA_CLOAKED, out v, sizeof(int)) == 0 && v != 0;
            }
            catch (DllNotFoundException) { return false; }
            catch (EntryPointNotFoundException) { return false; }
        }

        private static bool IsClickThrough(IntPtr h) { return IsClickThroughStyle(GetWindowLong(h, GWL_EXSTYLE)); }

        /// <summary>BOTH bits. WS_EX_TRANSPARENT alone only changes paint order and WS_EX_LAYERED alone is an
        /// ordinary alpha-blended window that still takes the mouse; together they are an overlay the mouse
        /// passes through.</summary>
        private static bool IsClickThroughStyle(int exStyle)
        {
            return (exStyle & WS_EX_TRANSPARENT) != 0 && (exStyle & WS_EX_LAYERED) != 0;
        }

        /// <summary>Can this window be the one under the cursor? Visible, holding the point, and neither
        /// cloaked nor click-through. ONE predicate for both levels of the hit-test, so the top-level pass and
        /// the descent cannot disagree about what a hit is.</summary>
        private static bool HoverCandidate(HoverWin w, int x, int y)
        {
            return w.Visible && !w.Cloaked && !w.ClickThrough && w.Rect.Contains(x, y);
        }

        /// <summary>
        /// THE HIT-TEST, pure, so protocolcheck runs this exact code over hand-built windows.
        ///
        /// 1. The FIRST candidate top-level window (z-order, topmost first; see HoverCandidate) is
        ///    the one the user sees there. If it is not the debuggee's, the answer is none: the IDE lying over
        ///    the debuggee must not report the window underneath.
        /// 2. Descend that root's tree: at each level the topmost (lowest Sib) visible child holding the point.
        ///    A child that belongs to another process ends the answer as none.
        /// 3. The answer is the owning thread of the deepest window reached. 0 means none.
        /// </summary>
        private static uint HoverHitTest(IList<HoverWin> tops, Func<IntPtr, IList<HoverWin>> treeOf, int x, int y, uint pid)
        {
            foreach (var top in tops)
            {
                if (!HoverCandidate(top, x, y)) continue;
                if (top.Pid != pid) return 0;
                var tree = treeOf(top.Hwnd) ?? new List<HoverWin>();
                var cur = top;
                // Bounded by the tree size: a hand-built or corrupted list with a parent cycle cannot hang the
                // debug loop.
                for (int guard = 0; guard <= tree.Count; guard++)
                {
                    bool found = false; HoverWin best = default(HoverWin);
                    foreach (var w in tree)
                    {
                        if (w.Parent != cur.Hwnd || w.Hwnd == IntPtr.Zero || !HoverCandidate(w, x, y)) continue;
                        if (!found || w.Sib < best.Sib) { best = w; found = true; }
                    }
                    if (!found) break;
                    if (best.Pid != pid) return 0;
                    cur = best;
                }
                return cur.Tid;
            }
            return 0;
        }

        /// <summary>The `hover` event. UNSCOPED: it goes out through Console, not EmitThreadEvent, because
        /// it is not a read answered for the selected thread. Its "tid" names the thread under the cursor
        /// and goes through AppendTidMember like every thread id, so "none" is an ABSENT tid.</summary>
        private static string HoverJson(bool on, bool paused, uint tid)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"hover\",\"on\":").Append(on ? "true" : "false")
              .Append(",\"paused\":").Append(paused ? "true" : "false");
            AppendTidMember(sb, tid);
            return sb.Append('}').ToString();
        }

        /// <summary>Test seams for protocolcheck (ProtocolCheck.Hover.cs). Pure; none touches a process.</summary>
        internal static uint HoverHitTestForTest(IList<HoverWin> tops, Func<IntPtr, IList<HoverWin>> treeOf, int x, int y, uint pid)
        {
            return HoverHitTest(tops, treeOf, x, y, pid);
        }
        internal static string HoverJsonForTest(bool on, bool paused, uint tid) { return HoverJson(on, paused, tid); }
        internal static bool IsClickThroughStyleForTest(int exStyle) { return IsClickThroughStyle(exStyle); }
        internal void HoverNewStopForTest() { HoverNewStop(); }
        internal void PollHoverForTest(bool paused) { PollHover(paused); }

        /// <summary>Drive the verb on an engine with NO process: the poll answers "none" at ProcessId() without
        /// a single window read, so this exercises the handler and the event, and touches nothing.</summary>
        internal void HandleHoverCommandForTest(string cmd, bool paused)
        {
            HandleHoverCommand(cmd.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries), paused);
        }
    }
}
