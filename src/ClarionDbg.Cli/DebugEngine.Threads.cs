using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ thread scan (measurement probe)
        //
        // `threadscan` — task 0128a37e item 0. Dumps, for EVERY live thread at the current stop, the evidence
        // needed to decide WHICH thread a Pause should report: tid, creation order, EIP + owning image, the
        // EIP's state (clarion / rtl / syscall / unknown), the Clarion frames its STACK carries, its topmost
        // Clarion procedure, the RTL's own thread number (Cla$THREAD) and its Win32 start address.
        //
        // STRICTLY READ-ONLY. The process is frozen while we hold the debug event, so every thread's context
        // is stable to read; nothing here runs target code. The per-thread register read is GetThreadContext,
        // the stack is reconstructed from ReadProcessMemory, and Cla$THREAD is EMULATED against that thread's
        // TEB the same way Library State and THR$GetInstance already are (DebugEngine.LibState.cs /
        // DebugEngine.Eval.cs). Re-introducing a thread hijack here would undo exactly what 50414e39 removed.

        private const int SCAN_FRAMES = 48;     // frames to walk per thread when scanning (deeper than the
                                                // default stack view: we want the Clarion frames under a
                                                // syscall-parked top frame, not just the first few)

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
            public string ClarionThread;    // Cla$THREAD for this thread, or a reason it is unavailable
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

        /// <summary>threadscan [NAME] — emit the per-thread evidence table for the current stop (read-only).
        /// With NAME, additionally resolve that data name on EVERY thread and show the value that thread
        /// would read, which is the direct evidence for "the browse's copy is filled, the frame's is not".</summary>
        private void HandleThreadScanCommand(uint stoppedTid, string[] parts)
        {
            var probes = ProbeAllThreads(stoppedTid);
            string probeName = parts != null && parts.Length > 1 ? parts[1] : null;
            if (probeName != null) ProbeNameOnEachThread(probeName, probes);
            FillWindowEvidence(probes, GetProcessId(_hProcess));

            Console.WriteLine($"  threadscan: {probes.Count} live thread(s), stopped tid={stoppedTid}");
            Console.WriteLine("    seq  tid    stopped  state     eip        image            clfr  wins      top Clarion frame                     Cla$THREAD  created");
            foreach (var p in probes)
            {
                string top = p.TopProc != null
                    ? p.TopProc + (p.TopModule != null ? " (" + p.TopModule + ":" + p.TopLine + ")" : "")
                    : "(none)";
                Console.WriteLine(string.Format(
                    "    {0,-4} {1,-6} {2,-8} {3,-9} 0x{4:X8} {5,-16} {6,-5} {7,-9} {8,-37} {9,-11} {10}",
                    p.Seq, p.Tid, p.IsStopped ? "YES" : "", p.State, p.Eip,
                    p.EipImage ?? "(none)", p.ClarionFrames + (p.FramesUncertain ? "?" : ""),
                    p.VisibleWindows + "/" + (p.VisibleWindows + p.HiddenWindows)
                        + (p.CrossRank != int.MaxValue ? " r" + p.CrossRank : ""),
                    Trunc(top, 37), p.ClarionThread ?? "-", p.Created == default(DateTime) ? "-" : p.Created.ToString("HH:mm:ss.fff")));
            }
            foreach (var p in probes)
            {
                Console.WriteLine($"    --- tid {p.Tid} (seq {p.Seq}){(p.IsStopped ? " [STOPPED]" : "")} ---");
                Console.WriteLine($"        eip=0x{p.Eip:X8} esp=0x{p.Esp:X8} ebp=0x{p.Ebp:X8} image={p.EipImage ?? "(none)"}{(p.EipSym != null ? " sym=" + p.EipSym : "")}");
                Console.WriteLine($"        start=0x{p.StartAddr:X8} in {p.StartImage ?? "(unknown)"}   clarionThread={p.ClarionThread ?? "-"}");
                if (p.Probed != null) Console.WriteLine($"        {probeName} = {p.Probed}");
                Console.WriteLine($"        windows: {p.VisibleWindows} visible, {p.HiddenWindows} hidden"
                                  + (p.CrossRank != int.MaxValue ? $", crossRank={p.CrossRank}" : ""));
                foreach (var w in p.Windows) Console.WriteLine("          " + w);
                if (p.TopFrames.Count == 0) Console.WriteLine("        clarion frames: (none)");
                else for (int i = 0; i < p.TopFrames.Count; i++) Console.WriteLine($"        #{i} {p.TopFrames[i]}");
            }

            if (EmitJson) Console.WriteLine("@JSON " + ThreadScanJson(stoppedTid, probes));
        }

        /// <summary>Measure every live thread. Creation order first (main thread first), which is the order
        /// the evidence is easiest to read in; the heuristic work happens on the caller's side.</summary>
        private List<ThreadProbe> ProbeAllThreads(uint stoppedTid)
        {
            var probes = new List<ThreadProbe>();
            var tids = new List<uint>(_threads);
            tids.Sort((a, b) => SeqOf(a).CompareTo(SeqOf(b)));

            var rt = RuntimeModule();
            uint claThreadRva = rt != null && rt.Pe != null ? rt.Pe.FindExportRva("Cla$THREAD") : 0;

            foreach (uint t in tids)
            {
                var p = new ThreadProbe { Tid = t, Seq = SeqOf(t), IsStopped = t == stoppedTid };
                IntPtr h = OpenThreadForContext(t);
                if (h == IntPtr.Zero) { p.State = "unknown"; p.ClarionThread = "no thread handle"; probes.Add(p); continue; }
                try
                {
                    var c = NewContext();
                    p.HaveCtx = Native.GetThreadContext(h, ref c);
                    if (!p.HaveCtx) { p.State = "unknown"; p.ClarionThread = "no context"; probes.Add(p); continue; }
                    p.Eip = c.Eip; p.Esp = c.Esp; p.Ebp = c.Ebp;

                    var m = ModuleAt(c.Eip);
                    p.EipImage = m != null ? m.Name : null;
                    p.State = ClassifyEip(m, c.Eip);
                    if (p.State != "clarion") p.EipSym = NearestImportSymbol(c.Eip);

                    FillStackEvidence(p, c);
                    FillStartAddress(p, h);
                    p.Created = ThreadCreationTime(h);
                    p.ClarionThread = ReadClarionThreadNumber(rt, claThreadRva, t, h);
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

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern IntPtr GetWindow(IntPtr hwnd, uint cmd);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hwnd);
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hwnd, System.Text.StringBuilder buf, int max);
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern int InternalGetWindowText(IntPtr hwnd, System.Text.StringBuilder buf, int max);
        private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

        private const uint GW_HWNDNEXT = 2;
        private const uint GW_CHILD = 5;
        private const int WIN_MAX_DEPTH = 4;      // frame -> MDI client -> child window -> its controls
        private const int WIN_MAX = 400;          // hard cap: never walk a pathological window tree forever

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
            for (int i = 0; i < roots.Count; i++) WalkWindow(list, roots[i], IntPtr.Zero, pid, i, 0);
            return list;
        }

        private void WalkWindow(List<WinInfo> list, IntPtr h, IntPtr parent, uint pid, int sib, int depth)
        {
            if (h == IntPtr.Zero || depth > WIN_MAX_DEPTH || list.Count >= WIN_MAX) return;
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
            for (IntPtr c = GetWindow(h, GW_CHILD); c != IntPtr.Zero && list.Count < WIN_MAX; c = GetWindow(c, GW_HWNDNEXT))
                WalkWindow(list, c, h, pid, i++, depth + 1);
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

        /// <summary>Resolve one data NAME on every probed thread and record the value THAT thread reads.
        /// Uses the same read-only THR$GetInstance emulation the watch path uses (TryResolveThreadedInstance
        /// already takes a tid + hThread), so this measures exactly what a per-thread watch would report —
        /// it does not run target code and does not allocate an instance for a thread that has none.</summary>
        private void ProbeNameOnEachThread(string name, List<ThreadProbe> probes)
        {
            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            if (!ResolveDataAcrossModules(name, out owner, out loc))
            {
                foreach (var p in probes) p.Probed = "(not found)";
                return;
            }
            uint templateVa = owner.LoadBase + loc.Rva;
            bool threaded = owner.CwtlsHi != 0 && loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi;

            foreach (var p in probes)
            {
                if (!threaded) { p.Probed = FormatValueAt(loc.TypeCode, 0, loc.Size, 0, templateVa) + "  [not threaded]"; continue; }
                IntPtr h = OpenThreadForContext(p.Tid);
                if (h == IntPtr.Zero) { p.Probed = "(no thread handle)"; continue; }
                try
                {
                    uint instanceVa; string reason;
                    var r = TryResolveThreadedInstance(owner, templateVa, p.Tid, h, out instanceVa, out reason);
                    switch (r)
                    {
                        case ThreadedResolve.Ok:
                            p.Probed = FormatValueAt(loc.TypeCode, 0, loc.Size, 0, instanceVa)
                                     + $"  [own instance 0x{instanceVa:X}]";
                            break;
                        case ThreadedResolve.Template:
                            p.Probed = FormatValueAt(loc.TypeCode, 0, loc.Size, 0, templateVa)
                                     + "  [no thread instance — shared template value]";
                            break;
                        case ThreadedResolve.Unallocated:
                            p.Probed = FormatValueAt(loc.TypeCode, 0, loc.Size, 0, templateVa)
                                     + "  [not yet used on this thread — initial value]";
                            break;
                        default:
                            p.Probed = "(error: " + reason + ")";
                            break;
                    }
                }
                finally { Native.CloseHandle(h); }
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
        private void FillStackEvidence(ThreadProbe p, Native.CONTEXT_X86 c)
        {
            List<StackFrame> frames;
            try { frames = BuildStack(c.Eip, c.Esp, c.Ebp, SCAN_FRAMES); }
            catch (Exception ex) { p.TopFrames.Add("(stack walk failed: " + ex.Message + ")"); return; }

            foreach (var f in frames)
            {
                if (f.Module == null && f.Proc == null) continue;   // frame 0 in un-mapped code
                if (f.Module == null) continue;                     // not TSWD-resolved: not a Clarion frame
                p.ClarionFrames++;
                if (f.Uncertain) p.FramesUncertain = true;
                if (p.TopProc == null) { p.TopProc = f.Proc; p.TopModule = f.Module; p.TopLine = f.Line; }
                if (p.TopFrames.Count < 8)
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
        /// same read-only path Library State uses. Never runs target code; returns the reason on failure so
        /// the evidence never silently claims a number it could not read.</summary>
        private string ReadClarionThreadNumber(LoadedModule rt, uint claThreadRva, uint tid, IntPtr hThread)
        {
            if (rt == null) return "no ClaRUN";
            if (claThreadRva == 0) return "no Cla$THREAD export";
            uint teb = GetTebBase(hThread);
            if (teb == 0) return "no TEB";
            try
            {
                var emu = BuildEmulator(rt, tid, teb);
                return ((int)emu.Call(rt.LoadBase + claThreadRva)).ToString();
            }
            catch (Exception ex) { return "(" + ex.GetType().Name + ")"; }
        }

        private static DateTime ThreadCreationTime(IntPtr hThread)
        {
            long c, e, k, u;
            return GetThreadTimes(hThread, out c, out e, out k, out u)
                ? DateTime.FromFileTimeUtc(c).ToLocalTime() : default(DateTime);
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(IntPtr hProcess);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadTimes(IntPtr hThread, out long creation, out long exit,
                                                  out long kernel, out long user);

        private static string Trunc(string s, int n)
            => s == null ? "" : (s.Length <= n ? s : s.Substring(0, n - 1) + "…");

        private string ThreadScanJson(uint stoppedTid, List<ThreadProbe> probes)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"threadscan\",\"stopped\":").Append(stoppedTid).Append(",\"threads\":[");
            for (int i = 0; i < probes.Count; i++)
            {
                var p = probes[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"tid\":").Append(p.Tid)
                  .Append(",\"seq\":").Append(p.Seq)
                  .Append(",\"stopped\":").Append(p.IsStopped ? "true" : "false")
                  .Append(",\"state\":").Append(Json.Str(p.State))
                  .Append(",\"eip\":\"0x").Append(p.Eip.ToString("X8")).Append('"')
                  .Append(",\"image\":").Append(Json.Str(p.EipImage))
                  .Append(",\"sym\":").Append(Json.Str(p.EipSym))
                  .Append(",\"clarionFrames\":").Append(p.ClarionFrames)
                  .Append(",\"uncertain\":").Append(p.FramesUncertain ? "true" : "false")
                  .Append(",\"proc\":").Append(Json.Str(p.TopProc))
                  .Append(",\"module\":").Append(Json.Str(p.TopModule))
                  .Append(",\"line\":").Append(p.TopLine)
                  .Append(",\"clarionThread\":").Append(Json.Str(p.ClarionThread))
                  .Append(",\"start\":\"0x").Append(p.StartAddr.ToString("X8")).Append('"')
                  .Append(",\"startImage\":").Append(Json.Str(p.StartImage))
                  .Append(",\"probed\":").Append(Json.Str(p.Probed))
                  .Append(",\"visibleWindows\":").Append(p.VisibleWindows)
                  .Append(",\"hiddenWindows\":").Append(p.HiddenWindows)
                  .Append(",\"crossRank\":").Append(p.CrossRank == int.MaxValue ? -1 : p.CrossRank)
                  .Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }
    }
}
