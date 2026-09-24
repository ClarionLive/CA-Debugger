using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------- thread evidence, the picker, and the pause
        //
        // The shared MEASUREMENT layer: ProbeAllThreads and the stack / window / Cla$THREAD probes behind
        // it, plus its two decision-making consumers — the `threads` picker and PickPauseThread's choice of
        // which thread a Pause reports. `threadscan`, which PRINTS this evidence and decides nothing, is in
        // DebugEngine.ThreadScan.cs.
        //
        // STRICTLY READ-ONLY, and this is the prohibition for everything below AND for every caller of it,
        // threadscan included. The process is frozen while we hold the debug event, so every thread's
        // context is stable to read; nothing here runs target code. The per-thread register read is
        // GetThreadContext, the stack is reconstructed from ReadProcessMemory, and Cla$THREAD is EMULATED
        // against that thread's TEB the same way Library State and THR$GetInstance already are
        // (DebugEngine.LibState.cs / DebugEngine.Watch.cs). Re-introducing a thread hijack here would undo
        // exactly what 50414e39 removed. See also the message-sending prohibition above the user32 imports.

        private const int SCAN_FRAMES = 48;     // frames to walk per thread when scanning (deeper than the
                                                // default stack view: we want the Clarion frames under a
                                                // syscall-parked top frame, not just the first few)

        // ------------------------------------------------------------- once-per-session diagnostics (ec45805f)
        //
        // Two console diagnostics here and in DebugEngine.Watch.cs fire on a REPEATING event rather than a
        // changing one: the window-walk cap is reported on every pause, and the THREADed-emulation notes on
        // every hit of a conditional breakpoint over an image with no .cwtls span. Neither says anything on
        // the hundredth time it did not say on the first, and a diagnostic that floods the console it informs
        // is read as noise — which is the failure mode, because these exist to be NOTICED.
        //
        // So each one is reported once per KEY per session, and the key is a stable category, never the
        // formatted line: the notes interpolate addresses, so keying on the text would dedup nothing.
        //
        // AND THE SUPPRESSION IS ANNOUNCED, not silent. The comment on NoteThreadedEmulation says these may
        // never be silent, and dropping the repeats without saying so would quietly re-introduce exactly
        // that — a reader could no longer tell "it happened once" from "it happens constantly". The first
        // report says further ones for that key are suppressed; the count is not tracked, because the only
        // decision it would change is one nobody makes from a console line.
        //
        // It lives in this file rather than DebugEngine.cs because both callers are diagnostic reporters in
        // the thread/threaded-data partials, and one holder beats a copy in each.
        private readonly HashSet<string> _reportedOnce = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>True the FIRST time this key is seen in this session, false every time after. The caller
        /// does the reporting, so the key and the message stay visibly separate — a key derived from the
        /// message is a key that stops matching the moment the message interpolates anything.</summary>
        private bool FirstReportOf(string key) { return _reportedOnce.Add(key); }

        /// <summary>Test seam for the rule holder. It mutates the reported-keys set and NOTHING ELSE — no
        /// debuggee memory, no breakpoint map, no handle — so it deliberately does not join the
        /// attached-engine refusals in CheckSeamsRefuseLiveTarget. That set exists for seams whose real work
        /// writes to the target, and putting a console-bookkeeping seam in it would weaken what its count
        /// claims rather than strengthen this.</summary>
        internal bool FirstReportOfForTest(string key) { return FirstReportOf(key); }

        /// <summary>The tail every once-only diagnostic carries, so "reported once" is a fact on the line
        /// rather than something the reader has to infer from never seeing it again.</summary>
        private const string ONCE_SUFFIX = "  [reported once per session]";

        /// <summary>The window-walk cap's dedup key: the root window's own IDENTITY, never its position in
        /// the enumeration.
        ///
        /// THIS SIGNATURE IS THE GUARANTEE. The loop index is not a parameter, so the key cannot be built
        /// from one however the call site is later rewritten — which is the defect being fixed, not a
        /// hypothetical: the key was `"wincap|root " + i`, and closing one top-level window renumbered every
        /// later root, silencing a brand-new pathological window under a key already reported.
        ///
        /// AN HWND CAN BE RECYCLED. Windows reuses handles of destroyed windows, so a future window could
        /// in principle inherit a handle already reported and be suppressed — the same class as the
        /// pid-reuse bugs this session found four of. It is ACCEPTABLE HERE, and only here, because this
        /// key gates a console NICETY: the worst outcome is one diagnostic line not printed, not a wrong
        /// thread read, a wrong process signalled or a write to the wrong memory. Do not lift this key into
        /// anything that decides authority; build one that fails closed instead.
        ///
        /// The class name is in the key for that reason, and it is what makes this better than the HWND
        /// alone: a recycled handle belonging to a DIFFERENT kind of window gets a different key and is
        /// reported. What remains is a recycled handle reused by the same window class, which is a residue
        /// rather than the original bug. The window TEXT is deliberately NOT in the key — a document title
        /// changes while the window lives, which would un-dedup the very message this is suppressing.</summary>
        private static string WinCapKey(IntPtr root, string cls)
        {
            return "wincap|hwnd " + root.ToInt64() + "|" + (cls ?? "");
        }

        /// <summary>Test seam for the key. The "not positional" half is settled by the signature above and
        /// needs no test; what this exercises is the half a signature cannot promise — that the key actually
        /// SEPARATES two different roots and stays STABLE for the same one, so the dedup both dedups and
        /// does not over-suppress.</summary>
        internal static string WinCapKeyForTest(long hwnd, string cls)
        {
            return WinCapKey(new IntPtr(hwnd), cls);
        }

        /// <summary>One thread's measured state at a stop. Nothing here is cached across stops.</summary>
        private sealed class ThreadProbe
        {
            public uint Tid;
            public int Seq;                 // creation order (0 = the CREATE_PROCESS main thread)
            public bool IsStopped;          // this is the thread PausedWait is reporting
            public bool HaveCtx;
            public uint Eip, Esp, Ebp;
            public string EipImage;         // owning image of EIP, or null when in no known module
            public string EipSym;           // nearest import symbol when EIP is outside TSWD code
            public string State;            // clarion | rtl | syscall | unknown
            public int ClarionFrames;       // frames on the stack that resolved to TSWD-mapped code
            public bool FramesUncertain;    // the frames came from the ESP scan, not a verified EBP chain
            public string TopProc;          // topmost Clarion frame's procedure
            public string TopModule;        // ... its compiland (file.clw)
            public int TopLine;             // ... its source line
            public List<string> TopFrames = new List<string>();  // first few Clarion frames, for the report
            // The RTL's own thread number and, separately, why there isn't one. These used to be a single
            // string holding either a number or a failure reason ("no TEB", "(InvalidOperationException)"),
            // re-parsed downstream by int.TryParse and compared against the literal "null" by the printer —
            // a value whose meaning depended on parsing it back, which is the same defect class as a 0 tid.
            // Clarion numbers its threads from 1, so there is no in-band way to say "none" with an int.
            public int? ClarionThread;      // the Clarion thread number, or null when there is not one
            public string ClarionThreadWhyNot;  // ... and why not: a failure reason, or "not a Clarion thread"
            public uint StartAddr;          // Win32 thread start address
            public string StartImage;       // ... and its owning image
            public DateTime Created;        // GetThreadTimes creation time (UTC)
            public string Probed;           // `threadscan NAME`: NAME's value AS THIS THREAD READS IT
            public int VisibleWindows;      // top-level/MDI-child windows this thread owns that are VISIBLE
            public int HiddenWindows;       // ... and ones that are not
            public int CrossRank = int.MaxValue; // sibling z-rank of this thread's topmost visible window whose
                                                 // parent belongs to ANOTHER thread (0 = active MDI child)
            public List<string> Windows = new List<string>();
        }

        /// <summary>One window of the debuggee, attributed to its owning thread.</summary>
        private struct WinInfo
        {
            public IntPtr Hwnd; public IntPtr Parent; public uint Tid; public uint ParentTid;
            public bool Visible; public int Sib; public int Depth;
            public string Cls; public string Text;
        }

        /// <summary>Measure every live thread. Creation order first (main thread first), which is the order
        /// the evidence is easiest to read in; the heuristic work happens on the caller's side.</summary>
        private List<ThreadProbe> ProbeAllThreads(uint stoppedTid, bool withClarionThread, bool withDiagnostics)
        {
            var probes = new List<ThreadProbe>();
            var tids = new List<uint>(_threads);
            tids.Sort((a, b) => SeqOf(a).CompareTo(SeqOf(b)));

            // Cla$THREAD costs one emulator run per thread. The `threads` list wants it (the developer reads
            // the Clarion thread number); PickPauseThread does not, and a pause should not pay for it.
            var rt = withClarionThread ? RuntimeModule() : null;
            uint claThreadRva = rt != null && rt.Pe != null ? rt.Pe.FindExportRva("Cla$THREAD") : 0;

            foreach (uint t in tids)
            {
                var p = new ThreadProbe { Tid = t, Seq = SeqOf(t), IsStopped = t == stoppedTid };
                IntPtr h = OpenThreadForContext(t);
                if (h == IntPtr.Zero) { p.State = "unknown"; p.ClarionThreadWhyNot = "no thread handle"; probes.Add(p); continue; }
                try
                {
                    var c = NewContext();
                    p.HaveCtx = Native.GetThreadContext(h, ref c);
                    if (!p.HaveCtx) { p.State = "unknown"; p.ClarionThreadWhyNot = "no context"; probes.Add(p); continue; }
                    p.Eip = c.Eip; p.Esp = c.Esp; p.Ebp = c.Ebp;

                    var m = ModuleAt(c.Eip);
                    p.EipImage = m != null ? m.Name : null;
                    p.State = ClassifyEip(m, c.Eip);
                    if (p.State != "clarion") p.EipSym = NearestImportSymbol(c.Eip);

                    FillStackEvidence(p, c, withDiagnostics);
                    // Diagnostic-only, and paid for per thread: FillStartAddress is an
                    // NtQueryInformationThread, ThreadCreationTime is a GetThreadTimes, and the TopFrames
                    // strings above are up to 8 formatted lines each. `threadscan` prints all three;
                    // PickPauseThread and the `threads` picker read none of them.
                    if (withDiagnostics)
                    {
                        FillStartAddress(p, h);
                        p.Created = ThreadCreationTime(h);
                    }
                    if (withClarionThread) ReadClarionThreadNumber(p, rt, claThreadRva, t, h);
                }
                finally { Native.CloseHandle(h); }
                probes.Add(p);
            }
            return probes;
        }

        // ---- window ownership -------------------------------------------------------------------------
        //
        // The measurement that refuted "newest Clarion thread": with no browse open, clbrws still has a live
        // SPLASHSCREEN thread parked in ACCEPT, newer than the frame. What actually separates "the thread
        // showing the user's window" from a parked-but-invisible one is whether it OWNS A VISIBLE WINDOW.
        //
        // These are Win32 queries issued by the DEBUGGER against the window manager. They read the frozen
        // target's window state; they do not run a single instruction of target code, and they cannot (the
        // target is stopped). Nothing here sends a message — SendMessage to a frozen thread would deadlock
        // the engine, and GetWindowText does that for a foreign window, so the caption is read with
        // WM_GETTEXT's non-blocking sibling, InternalGetWindowText.

        // DO NOT ADD A MESSAGE-SENDING API HERE. The target is FROZEN while we hold the debug event, so:
        //   * SendMessage / SendMessageTimeout / SendNotifyMessage block on a thread that cannot pump — they
        //     deadlock the ENGINE, and with it the debuggee, until the timeout (or forever).
        //   * GetWindowText and GetWindowTextLength look harmless but send WM_GETTEXT cross-process. That is
        //     why the caption below is read with InternalGetWindowText, which reads the window's stored text
        //     directly and sends nothing. Do not "simplify" it back to GetWindowText.
        //   * PostMessage does not block, but the message sits in the queue and is delivered when we resume —
        //     a side effect on the program under test, which a debugger must never introduce.
        // Everything used here is a pure window-manager state read: EnumWindows, GetWindow,
        // GetWindowThreadProcessId, IsWindowVisible, GetClassName, InternalGetWindowText, GetCursorPos,
        // GetWindowRect, GetWindowLongW, and DwmGetWindowAttribute (a query of DWM, not of the window).
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern IntPtr GetWindow(IntPtr hwnd, uint cmd);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hwnd);
        // GetClassName sits outside the originally blessed user32 set above, and that was queried in review
        // rather than assumed. BLESSED by the PM on 2026-09-17 (ticket ab4b3fcf item 10): it is
        // message-free, answered kernel-side from the window's own class, and its result is used only for
        // threadscan's display string. Recorded here so the next reader finds the decision instead of
        // re-litigating it — and so that a future addition to this block is still an explicit decision.
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hwnd, System.Text.StringBuilder buf, int max);
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int InternalGetWindowText(IntPtr hwnd, System.Text.StringBuilder buf, int max);
        // GetCursorPos and GetWindowRect are also outside the original set. BLESSED by the PM on 2026-09-23
        // (ticket f6e547ce item 0, the Owner's engine-side hover design): GetCursorPos reads the input
        // desktop's cursor position and GetWindowRect reads the window's stored rectangle. Neither sends a
        // message to the window or its thread. They exist for the hover hit-test in DebugEngine.Hover.cs.
        //
        // WindowFromPoint / ChildWindowFromPoint(Ex) / RealChildWindowFromPoint are deliberately NOT here,
        // though they would do the hit-test in one call: their hit-test can send WM_NCHITTEST to the window
        // under the cursor, and that window belongs to a thread that is frozen while we are paused.
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool GetCursorPos(out HoverPoint pt);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hwnd, out HoverRect rc);
        // Two more for the same hit-test, BLESSED by Diana (PM) on 2026-09-23 (ticket f6e547ce item 0), so a
        // window the user cannot see or click does not swallow the hover:
        //   * DwmGetWindowAttribute(DWMWA_CLOAKED) asks DWM whether a window is cloaked (a suspended UWP
        //     frame, a window on another virtual desktop). It reads state, and the party queried is DWM, not
        //     the window's thread, so it sends no message to the frozen target.
        //   * GetWindowLongW(GWL_EXSTYLE) reads the window's stored extended style, to recognise a click-through
        //     overlay (WS_EX_TRANSPARENT and WS_EX_LAYERED). It reads state and sends no message. The plain
        //     GetWindowLongW, not GetWindowLongPtr: the engine is x86, where user32 exports only the former.
        [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
        private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out int value, int size);
        [System.Runtime.InteropServices.DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
        private static extern int GetWindowLong(IntPtr hwnd, int index);
        private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

        private const uint GW_HWNDNEXT = 2;
        private const uint GW_CHILD = 5;
        private const int WIN_MAX_DEPTH = 4;      // frame -> MDI client -> child window -> its controls
        // Hard cap: never walk a pathological window tree forever. PER ROOT, not per enumeration — and the
        // name says so now. As a whole-enumeration budget it changed the ANSWER, not just the cost: a first
        // root with a large control tree could exhaust it before the browse's thread was reached, so that
        // thread got no window evidence, no CrossRank, and the pause silently fell through from the
        // `window-z` rule to `newest`. A cap that decides which thread you stop on is not a safety valve.
        // Per root, one pathological root can only cost itself.
        private const int WIN_MAX_PER_ROOT = 400;

        /// <summary>Walk the debuggee's window tree with GetWindow, so every window carries its TRUE
        /// z-order rank among its siblings (GW_CHILD gives the topmost child, GW_HWNDNEXT descends the
        /// z-order). EnumChildWindows cannot do this: it flattens all descendants into one list, which is
        /// why the first cut of this probe reported a meaningless rank for MDI children.</summary>
        private List<WinInfo> EnumerateTargetWindows(uint pid)
        {
            var list = new List<WinInfo>();
            var roots = new List<IntPtr>();
            EnumWindows((h, l) =>
            {
                uint p; GetWindowThreadProcessId(h, out p);
                if (p == pid) roots.Add(h);
                return true;
            }, IntPtr.Zero);
            for (int i = 0; i < roots.Count; i++)
            {
                int before = list.Count;
                WalkWindow(list, roots[i], IntPtr.Zero, pid, i, 0, before + WIN_MAX_PER_ROOT);
                // Once per ROOT per session. This fires on EVERY pause otherwise, and a root whose tree was
                // too big to walk at the first stop is still too big at the two hundredth — the line is the
                // same line, so repeating it only buries the stop's real output.
                //
                // The key names the WINDOW, not its position in this enumeration. It used to be
                // "wincap|root " + i, and i is the EnumWindows loop index: close the app's first top-level
                // window and the former root 1 becomes root 0, so a genuinely new pathological root is
                // silenced under a key already reported — and the message named a root number that by then
                // identified nothing. Position is not identity, the same lesson as a recycled pid.
                if (list.Count - before >= WIN_MAX_PER_ROOT)
                {
                    // Safe: the cap was reached, so WalkWindow added at least one window, and it adds the
                    // root itself first.
                    var root = list[before];
                    if (FirstReportOf(WinCapKey(roots[i], root.Cls)))
                        Console.WriteLine($"  (window walk: root 0x{roots[i].ToInt64():X} [{root.Cls}] "
                                          + $"\"{Trunc(root.Text, 40)}\" hit the {WIN_MAX_PER_ROOT}-window "
                                          + "cap — its tree is truncated; later roots are unaffected)"
                                          + ONCE_SUFFIX);
                }
            }
            return list;
        }

        /// <summary><paramref name="stopAtCount"/> is an ABSOLUTE ceiling on <paramref name="list"/>.Count,
        /// not a remaining allowance: the caller passes `before + WIN_MAX_PER_ROOT`, so each root gets its
        /// own cap measured from wherever the list already stood. It was called `budget`, which reads as
        /// "how many more you may add" and would be off by every window a previous root contributed.</summary>
        private void WalkWindow(List<WinInfo> list, IntPtr h, IntPtr parent, uint pid, int sib, int depth, int stopAtCount)
        {
            if (h == IntPtr.Zero || depth > WIN_MAX_DEPTH || list.Count >= stopAtCount) return;
            uint p; uint t = GetWindowThreadProcessId(h, out p);
            if (p != pid) return;
            uint pp = 0, ptid = 0;
            if (parent != IntPtr.Zero) ptid = GetWindowThreadProcessId(parent, out pp);
            var cls = new System.Text.StringBuilder(128);
            GetClassName(h, cls, cls.Capacity);
            var txt = new System.Text.StringBuilder(128);
            InternalGetWindowText(h, txt, txt.Capacity);
            list.Add(new WinInfo
            {
                Hwnd = h, Parent = parent, Tid = t, ParentTid = ptid, Visible = IsWindowVisible(h),
                Sib = sib, Depth = depth, Cls = cls.ToString(), Text = txt.ToString(),
            });
            int i = 0;
            for (IntPtr c = GetWindow(h, GW_CHILD); c != IntPtr.Zero && list.Count < stopAtCount; c = GetWindow(c, GW_HWNDNEXT))
                WalkWindow(list, c, h, pid, i++, depth + 1, stopAtCount);
        }

        /// <summary>Attribute the debuggee's windows to the probed threads. The signal that matters is
        /// CrossRank: the sibling z-rank of the topmost VISIBLE window this thread owns whose PARENT belongs
        /// to a DIFFERENT thread — i.e. how the MDI client (owned by the frame thread) stacks this thread's
        /// window. Rank 0 = the active MDI child, which is the window the developer is looking at.</summary>
        private void FillWindowEvidence(List<ThreadProbe> probes, uint pid)
        {
            var wins = EnumerateTargetWindows(pid);
            foreach (var p in probes)
            {
                foreach (var w in wins)
                {
                    if (w.Tid != p.Tid) continue;
                    if (w.Visible) p.VisibleWindows++; else p.HiddenWindows++;
                    bool cross = w.Parent != IntPtr.Zero && w.ParentTid != 0 && w.ParentTid != p.Tid;
                    if (w.Visible && cross && w.Sib < p.CrossRank) p.CrossRank = w.Sib;
                    if (w.Depth <= 2 && p.Windows.Count < 6)
                        p.Windows.Add($"d{w.Depth} sib{w.Sib} {(w.Visible ? "VIS" : "hid")} {(cross ? "X" : " ")} "
                                      + w.Cls + (w.Text.Length > 0 ? " '" + Trunc(w.Text, 40) + "'" : ""));
                }
            }
        }

        /// <summary>Where is this thread's EIP? clarion = TSWD-mapped app code; rtl = a known image that is
        /// not the OS and carries no TSWD (ClaRUN etc.); syscall = ntdll/win32u/kernel; else unknown.</summary>
        private string ClassifyEip(LoadedModule m, uint eip)
        {
            if (m != null && m.Dbg != null)
            {
                int line, mi; uint rec;
                if (m.Dbg.ResolveAddr(eip - m.LoadBase, out line, out mi, out rec)) return "clarion";
            }
            if (m == null) return "unknown";
            string n = m.Name ?? "";
            if (n.StartsWith("ntdll") || n.StartsWith("win32u") || n.StartsWith("kernel32")
                || n.StartsWith("kernelbase") || n.StartsWith("user32") || n.StartsWith("gdi32"))
                return "syscall";
            return "rtl";
        }

        /// <summary>Walk this thread's stack and record the Clarion frames it carries. This is the whole
        /// point of the probe: two threads both parked in win32u!NtUserGetMessage are indistinguishable by
        /// EIP, but their STACKS are not.</summary>
        /// <param name="withFrameText">Also format the first few frames as display strings. The COUNT and the
        /// topmost frame are what the pause decision and the picker read; the strings are threadscan's alone,
        /// so they are not built on a path that will throw them away.</param>
        private void FillStackEvidence(ThreadProbe p, Native.CONTEXT_X86 c, bool withFrameText)
        {
            List<StackFrame> frames;
            // The failure is recorded even when the frame text is off: a stack walk that threw is evidence,
            // and dropping it on the quiet path would make a broken walk look like a thread with no frames.
            try { frames = BuildStack(c.Eip, c.Esp, c.Ebp, SCAN_FRAMES); }
            catch (Exception ex) { p.TopFrames.Add("(stack walk failed: " + ex.Message + ")"); return; }

            foreach (var f in frames)
            {
                // One test, not two: `Module == null && Proc == null` was sitting immediately above
                // `Module == null`, which subsumes it — the first could never decide anything the second
                // did not already decide. Frame 0 in un-mapped code is caught by this line too.
                if (f.Module == null) continue;                     // not TSWD-resolved: not a Clarion frame
                p.ClarionFrames++;
                if (f.Uncertain) p.FramesUncertain = true;
                if (p.TopProc == null) { p.TopProc = f.Proc; p.TopModule = f.Module; p.TopLine = f.Line; }
                if (withFrameText && p.TopFrames.Count < 8)
                    p.TopFrames.Add((f.Proc ?? "(unknown)") + "  " + f.Module + ":" + f.Line
                                    + "  RVA 0x" + f.Rva.ToString("X") + (f.Uncertain ? "  [scan]" : "  [chain]"));
            }
        }

        /// <summary>The thread's Win32 start address (NtQueryInformationThread class 9) and its owning image —
        /// evidence for which image spawned the thread (the RTL's thread stub vs the process entry).</summary>
        private void FillStartAddress(ThreadProbe p, IntPtr hThread)
        {
            var buf = new byte[4];
            int retLen;
            if (Native.NtQueryInformationThread(hThread, 9, buf, buf.Length, out retLen) != 0) return;
            p.StartAddr = BitConverter.ToUInt32(buf, 0);
            var sm = ModuleAt(p.StartAddr);
            p.StartImage = sm != null ? sm.Name : null;
        }

        /// <summary>Cla$THREAD for one thread, read by EMULATING the export against THAT thread's TEB — the
        /// same read-only path Library State uses. Never runs target code; records the reason on failure so
        /// the evidence never silently claims a number it could not read.
        ///
        /// Writes BOTH fields on the probe, because "which thread number" and "why there isn't one" are two
        /// different questions and a caller should not have to parse one answer to find out which it got.
        /// A Cla$THREAD of 0 or below is not a thread number: Clarion numbers its threads from 1, so that
        /// answer means the thread is not a Clarion thread at all, and it is recorded as such rather than
        /// passed on as a number no consumer could use.</summary>
        private void ReadClarionThreadNumber(ThreadProbe p, LoadedModule rt, uint claThreadRva, uint tid, IntPtr hThread)
        {
            if (rt == null) { p.ClarionThreadWhyNot = "no ClaRUN"; return; }
            if (claThreadRva == 0) { p.ClarionThreadWhyNot = "no Cla$THREAD export"; return; }
            uint teb = GetTebBase(hThread);
            if (teb == 0) { p.ClarionThreadWhyNot = "no TEB"; return; }
            try
            {
                var emu = BuildEmulator(rt, tid, teb);
                int n = (int)emu.Call(rt.LoadBase + claThreadRva);
                if (n > 0) p.ClarionThread = n;
                else p.ClarionThreadWhyNot = "not a Clarion thread";
            }
            catch (Exception ex) { p.ClarionThreadWhyNot = "(" + ex.GetType().Name + ")"; }
        }

        /// <summary>What to show a human for this thread's Clarion thread number: the number, else why there
        /// isn't one, else a dash. One place, so the console table and the detail lines cannot disagree.</summary>
        private static string ClarionThreadText(ThreadProbe p)
        {
            return p.ClarionThread.HasValue ? p.ClarionThread.Value.ToString()
                 : (p.ClarionThreadWhyNot ?? "-");
        }

        private static DateTime ThreadCreationTime(IntPtr hThread)
        {
            long c, e, k, u;
            return GetThreadTimes(hThread, out c, out e, out k, out u)
                ? DateTime.FromFileTimeUtc(c).ToLocalTime() : default(DateTime);
        }

        /// <summary>The debuggee's pid, for the window enumeration.
        ///
        /// Read from the CREATE_PROCESS PROCESS_INFORMATION the debugger already has, not asked back from
        /// the OS: a `GetProcessId` P/Invoke here was re-deriving a value the engine was handed at launch
        /// and had been throwing away (it was only ever printed). Returns 0 when there is no target, so a
        /// pid can never be reported for a process we no longer hold — the invariant on _pid, enforced here
        /// rather than assumed at the two call sites.</summary>
        private uint ProcessId() { return _hProcess == IntPtr.Zero ? 0u : _pid; }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadTimes(IntPtr hThread, out long creation, out long exit,
                                                  out long kernel, out long user);

        private static string Trunc(string s, int n)
            => s == null ? "" : (s.Length <= n ? s : s.Substring(0, n - 1) + "…");

        // ============================================================ thread inventory + selection (item 1/2)
        //
        // `threads`        list every live thread, described by its topmost CLARION frame (what makes the list
        //                  readable when every thread is parked in GetMessage) — see the frozen protocol.
        // `thread <tid>`   choose which thread the read commands answer about for the REST OF THIS STOP.
        //
        // The selection is per-stop and never carried across one: PausedWait resets it to the stopped thread
        // every time. Resume-type commands always act on the stopped thread and reset the selection first, so
        // a step can never be reported against a thread the user was merely looking at.

        /// <summary>threads — the thread list for the picker. Ordered stopped-thread-first, then newest
        /// created first (an MDI child's thread is newer than the frame's).</summary>
        private void HandleThreadsCommand(uint stoppedTid)
        {
            // The picker shows the Clarion thread number and the topmost frame. It shows none of the
            // diagnostic evidence, so it does not pay for it.
            var probes = ProbeAllThreads(stoppedTid, withClarionThread: true, withDiagnostics: false);
            // Never offer the thread DebugBreakProcess injected to cause this stop. It is a real live
            // thread, so it would list and select like any other, but it belongs to the debugger, carries
            // no Clarion work, and exits the instant the target resumes. `threadscan` still shows it — that
            // is a diagnostic and the break thread is part of what it is diagnosing.
            if (_breakTid != 0) probes.RemoveAll(p => p.Tid == _breakTid);
            probes.Sort((x, y) =>
            {
                if (x.IsStopped != y.IsStopped) return x.IsStopped ? -1 : 1;   // stopped thread first
                return y.Seq.CompareTo(x.Seq);                                  // then newest first
            });

            if (EmitJson) Console.WriteLine("@JSON " + ThreadsJson(stoppedTid, _selectedTid, probes));

            // The console line says "(unknown)" for the same reason the wire omits the member: 0 is not a
            // thread, and printing it invites the reader to go looking for thread 0.
            Console.WriteLine($"  threads ({probes.Count}), stopped {TidText(stoppedTid)}, "
                              + $"selected {TidText(_selectedTid)}:");
            foreach (var p in probes)
                Console.WriteLine($"    {(p.IsStopped ? "*" : " ")}"
                    + $"{(TidIsKnown(_selectedTid) && p.Tid == _selectedTid ? ">" : " ")} tid {p.Tid,-6} "
                    + $"{p.State,-8} {(p.TopProc ?? "(no Clarion frame)")}"
                    + (p.TopModule != null ? "  " + p.TopModule + ":" + p.TopLine : "")
                    + (p.ClarionThread.HasValue ? "  [Clarion thread " + p.ClarionThread.Value + "]" : ""));
        }

        /// <summary>The `threads` event for the picker. A pure builder over already-measured probes, so
        /// `ClarionDbg protocolcheck` can assert the absent-tid rule against THIS code rather than against a
        /// hand-written copy of its shape — a fixture that is written twice is a fixture that agrees with
        /// itself and with nothing else.
        ///
        /// The TOP-LEVEL "stopped" and "selected" are thread ids under another name, so they go through the
        /// same writer as "tid" (ticket 3b043dfc): unknown means the member is ABSENT, and the object opens
        /// with "event" so there is always a member for the writer's leading comma to follow. The PER-ROW
        /// "stopped"/"selected" below share the names but are booleans about the row, and are written here.
        ///
        /// The row's "selected" is ANDed with the rule's own predicate rather than compared alone: with no
        /// selection, selectedTid is 0, and a row that somehow carried a 0 tid would otherwise mark itself
        /// as the selected thread — the sentinel-reads-as-real defect again, one level down and in a
        /// boolean. TidIsKnown is the same predicate that decides whether the top-level member is written,
        /// so the row cannot claim a selection the event does not state.</summary>
        private static string ThreadsJson(uint stoppedTid, uint selectedTid, List<ThreadProbe> probes)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"threads\"");
            AppendTidValuedMember(sb, TidMemberStopped, stoppedTid);
            AppendTidValuedMember(sb, TidMemberSelected, selectedTid);
            sb.Append(",\"threads\":[");
            for (int i = 0; i < probes.Count; i++)
            {
                var p = probes[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"clarionThread\":").Append(ClarionThreadJson(p.ClarionThread))
                  .Append(",\"proc\":").Append(Json.Str(p.TopProc))
                  .Append(",\"module\":").Append(Json.Str(p.TopModule))
                  .Append(",\"line\":").Append(p.TopLine)
                  .Append(",\"state\":").Append(Json.Str(p.State))
                  .Append(",\"clarionFrames\":").Append(p.ClarionFrames)
                  .Append(",\"stopped\":").Append(p.IsStopped ? "true" : "false")
                  .Append(",\"selected\":").Append(TidIsKnown(selectedTid) && p.Tid == selectedTid ? "true" : "false");
                AppendTidMember(sb, p.Tid);
                sb.Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        /// <summary>The RTL's thread number as a JSON value: the number, or null. The decision about what
        /// counts as a number is made where the value is READ (ReadClarionThreadNumber), not re-derived here
        /// by parsing a string back — the old version of this method was the second holder of that rule, and
        /// the printer beside it was a third, comparing against the literal "null". Same shape of defect as
        /// two places deciding whether to write a tid.</summary>
        private static string ClarionThreadJson(int? n)
        {
            return n.HasValue ? n.Value.ToString() : "null";
        }

        /// <summary>thread &lt;tid&gt; — point the read commands at another thread for the rest of this stop.
        /// An unknown or exited tid is refused and the selection is left exactly as it was.</summary>
        private void HandleThreadSelectCommand(string[] parts, uint stoppedTid)
        {
            if (parts.Length < 2) { EmitThreadSelected(0, false, "thread expects: thread <tid>"); return; }
            uint tid;
            if (!uint.TryParse(parts[1], out tid))
            {
                EmitThreadSelected(0, false, "not a thread id: '" + parts[1] + "'");
                return;
            }
            if (!_threads.Contains(tid))
            {
                EmitThreadSelected(tid, false, "unknown or exited thread " + tid);
                return;
            }
            if (tid == _breakTid)
            {
                // Live, but it is the debugger's own injected break thread — it is not in the list we
                // offered, and it dies on resume. Refuse by name rather than let a reply come back from it.
                EmitThreadSelected(tid, false, "thread " + tid + " is the debugger's injected break thread");
                return;
            }
            _selectedTid = tid;
            EmitThreadSelected(tid, true, null);
            Console.WriteLine($"  thread {TidText(tid)} selected{(tid == stoppedTid ? " (the stopped thread)" : " — reads now answer for this thread")}");
        }

        /// <summary>The reply to `thread &lt;tid&gt;`. On success the tid is the thread now selected; on a
        /// REFUSAL it is the thread that was ASKED FOR, not the one that survived — the host needs to match
        /// the reply to the request it sent, and the selection it still has is the one it already knew about.
        ///
        /// An unknown tid emits NO "tid" member. That is the case for a malformed request (no tid given, or
        /// one that would not parse) and for a `thread` that arrived while the target is running, where there
        /// is no stop and so no selection to name. This method used to carry its OWN copy of the rule — an
        /// inline `tid != 0 ?` — which is how the rule came to be held in two places that could drift apart.
        /// The decision now belongs to <see cref="AppendTidMember"/> and is made nowhere else.</summary>
        private void EmitThreadSelected(uint tid, bool ok, string error)
        {
            if (EmitJson) Console.WriteLine("@JSON " + ThreadSelectedJson(tid, ok, error));
            if (!ok) Console.WriteLine("  thread: " + error);
        }

        /// <summary>The `threadselected` reply as JSON. Pure, so protocolcheck can run the real builder.</summary>
        private static string ThreadSelectedJson(uint tid, bool ok, string error)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"threadselected\",\"ok\":").Append(ok ? "true" : "false");
            if (error != null) sb.Append(",\"error\":").Append(Json.Str(error));
            AppendTidMember(sb, tid);
            return sb.Append('}').ToString();
        }

        // ============================================================ which thread a Pause reports (item 3)

        /// <summary>
        /// Choose the thread to report at a pause, by its STACK rather than its EIP.
        ///
        /// Measured on clbrws.exe (task 0128a37e item 0): with the app idle, the frame thread AND every browse
        /// thread sit at win32u!NtUserGetMessage+0xC, so the old EIP test disqualified all of them and the
        /// fallback took the frame — the thread whose copy of the record buffer was never filled. What DOES
        /// separate them is the stack (only Clarion threads carry Clarion frames: 2 of 8 threads in the
        /// measured run) and, between several Clarion threads, which one's window is on top.
        ///
        /// The rules, in order:
        ///   1. CANDIDATE = a thread other than the injected break thread whose stack carries at least one
        ///      Clarion frame. This is binary and reliable. The frame COUNT is not usable for ranking — the
        ///      ESP-scan fallback over-includes stale return addresses, and the measured frame thread showed
        ///      10 frames against the browse thread's 3.
        ///   2. window-z  Among candidates, the one owning the topmost visible window whose parent belongs to
        ///      ANOTHER thread — i.e. sibling z-rank 0 under the MDI client, the active MDI child. Measured:
        ///      opening Publishers then Authors and re-activating Publishers flips the ranking to Publishers,
        ///      which is what the developer is looking at. Creation order cannot see that, which is why it is
        ///      only the tiebreak.
        ///   3. newest    No window evidence (no windows up yet, mid-teardown, or the enumeration named no
        ///      candidate): the newest candidate by OS creation order.
        ///   4. first-readable / main  No candidate at all: the first readable non-break thread in creation
        ///      order, else the main thread. This is the pre-existing fallback, unchanged.
        ///
        /// Step 2 is BEST-EFFORT throughout — any failure falls through to 3 and then 4, so a pause always
        /// lands somewhere sane. It is also strictly read-only: it reads window-manager state and sends no
        /// messages (see the prohibition above the user32 P/Invokes).
        /// </summary>
        private uint PickPauseThread(uint breakTid)
        {
            List<ThreadProbe> probes;
            try { probes = ProbeAllThreads(0, withClarionThread: false, withDiagnostics: false); }
            catch (Exception ex)
            {
                uint lr0 = LastResortThread(breakTid);
                LogPauseChoice(lr0, "probe-failed(" + ex.GetType().Name + ")", 0);
                return lr0;
            }

            // 1. candidates: a Clarion frame on the stack, and never the injected break thread
            var candidates = new List<ThreadProbe>();
            foreach (var p in probes)
                if (p.Tid != breakTid && p.HaveCtx && p.ClarionFrames > 0) candidates.Add(p);

            if (candidates.Count == 0)
            {
                uint fb = 0;
                foreach (var p in probes)          // probes are already in creation order
                    if (p.Tid != breakTid && p.HaveCtx) { fb = p.Tid; break; }
                if (fb != 0) { LogPauseChoice(fb, "first-readable", 0); return fb; }
                uint lr = LastResortThread(breakTid);
                LogPauseChoice(lr, "main", 0);
                return lr;
            }

            // 2. window-z: the candidate owning the topmost cross-thread visible window (active MDI child).
            //    Best-effort: a throw, an empty enumeration, or a window set naming no candidate all fall
            //    through to step 3 rather than failing the pause.
            // Best-effort, but NOT silent: a bare catch here would make a genuine defect in the window walk
            // indistinguishable from "the app has no windows up", and every pause would quietly fall through
            // to `newest` with nothing in the log to say why. The reason rides along in the rule name.
            string windowFailure = null;
            try { FillWindowEvidence(candidates, ProcessId()); }
            catch (Exception ex) { windowFailure = ex.GetType().Name; }

            ThreadProbe best = null;
            foreach (var p in candidates)
                if (p.CrossRank != int.MaxValue && (best == null || p.CrossRank < best.CrossRank)) best = p;
            if (best != null)
            {
                LogPauseChoice(best.Tid, "window-z", candidates.Count);
                return best.Tid;
            }

            // 3. newest candidate by creation order
            foreach (var p in candidates)
                if (best == null || p.Seq > best.Seq) best = p;
            LogPauseChoice(best.Tid, windowFailure == null ? "newest" : "newest(window-probe-failed:" + windowFailure + ")",
                           candidates.Count);
            return best.Tid;
        }

        /// <summary>The pre-existing last resort: the main thread, else the thread the break landed on.</summary>
        private uint LastResortThread(uint breakTid)
        {
            return _mainTid != 0 ? _mainTid : breakTid;
        }

        /// <summary>Say which thread a pause chose and WHY. The Owner asked about a thread they did not pick;
        /// the next person to wonder the same should find the answer in the log rather than in this file.
        ///
        /// This was the LIVE hole in the absent-tid rule: it wrote a top-level `,"tid":` UNCONDITIONALLY, and
        /// its tid comes from <see cref="LastResortThread"/>, which returns `breakTid` when `_mainTid` is 0 —
        /// and 0 itself when both are. A pause that fell all the way to the last resort therefore stamped a
        /// console event with `"tid":0`, which the pad reads as a real thread. The text still names the
        /// chosen thread either way, so the log stays readable when the member is absent.</summary>
        private void LogPauseChoice(uint tid, string rule, int candidates)
        {
            string text = $"pause: thread {TidText(tid)} chosen by {rule} ({candidates} Clarion candidate(s) of {_threads.Count} live thread(s))";
            Console.WriteLine("  [" + text + "]");
            if (EmitJson) Console.WriteLine("@JSON " + PauseChoiceJson(text, tid));
        }

        /// <summary>The pause-choice console event as JSON. Pure, so protocolcheck can run the real
        /// builder — this is the emitter that was breaking the rule, so a fixture would have been no
        /// evidence at all.</summary>
        private static string PauseChoiceJson(string text, uint tid)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"console\",\"level\":\"info\",\"text\":").Append(Json.Str(text));
            AppendTidMember(sb, tid);
            return sb.Append('}').ToString();
        }

        // ------------------------------------------------------------ test seams for the hand-built emitters
        //
        // These exist so `ClarionDbg protocolcheck` can assert the absent-tid rule against THE REAL BUILDERS.
        // The three fixed breakages were all on hand-built paths, so a check written against a hand-copied
        // shape would have agreed with the copy and missed every one of them. `ThreadProbe` is private, so
        // the seam takes plain tids and builds the probes here rather than exposing the type.

        internal static string ThreadsJsonForTest(uint stoppedTid, uint selectedTid, uint[] tids)
        {
            return ThreadsJson(stoppedTid, selectedTid, ProbesForTest(tids, stoppedTid));
        }

        internal static string ThreadSelectedJsonForTest(uint tid, bool ok, string error)
        {
            return ThreadSelectedJson(tid, ok, error);
        }

        internal static string PauseChoiceJsonForTest(string text, uint tid)
        {
            return PauseChoiceJson(text, tid);
        }

        private static List<ThreadProbe> ProbesForTest(uint[] tids, uint stoppedTid)
        {
            var probes = new List<ThreadProbe>();
            for (int i = 0; i < tids.Length; i++)
                probes.Add(new ThreadProbe
                {
                    Tid = tids[i], Seq = i, IsStopped = tids[i] == stoppedTid && stoppedTid != 0,
                    HaveCtx = true, State = "clarion", ClarionThread = 1,
                });
            return probes;
        }
    }
}
