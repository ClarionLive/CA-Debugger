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
        // THIS FILE IS THE DIAGNOSTIC ONLY — the command, its `threadscan NAME` per-thread probe, and the
        // JSON it emits. It does not MEASURE anything: the evidence layer it prints (ProbeAllThreads, the
        // stack/window/Cla$THREAD probes) lives in DebugEngine.Threads.cs and is shared with the `threads`
        // picker and with PickPauseThread. Split out per the one-concern-per-partial convention.
        //
        // The STRICTLY READ-ONLY prohibition that governs those probes lives with them, at the top of
        // DebugEngine.Threads.cs, not here — a rule belongs beside the code it constrains. It applies to
        // everything this command reaches, and nothing in this file runs target code either.

        /// <summary>threadscan [NAME] — emit the per-thread evidence table for the current stop (read-only).
        /// With NAME, additionally resolve that data name on EVERY thread and show the value that thread
        /// would read, which is the direct evidence for "the browse's copy is filled, the frame's is not".</summary>
        private void HandleThreadScanCommand(uint stoppedTid, string[] parts)
        {
            var probes = ProbeAllThreads(stoppedTid, withClarionThread: true, withDiagnostics: true);
            string probeName = parts != null && parts.Length > 1 ? parts[1] : null;
            if (probeName != null) ProbeNameOnEachThread(probeName, probes);
            // Guarded the same way the pause path guards it (PickPauseThread). Window evidence is
            // best-effort on BOTH paths: it is a display column here and a tiebreak there, and neither is
            // worth losing the command — or the session — to a window-manager hiccup. The reason is shown
            // rather than swallowed, so a genuine defect in the walk is not indistinguishable from an app
            // with no windows up.
            try { FillWindowEvidence(probes, ProcessId()); }
            catch (Exception ex) { Console.WriteLine("  (window evidence unavailable: " + ex.GetType().Name + ")"); }

            Console.WriteLine($"  threadscan (read-only diagnostic; runs no target code): {probes.Count} live thread(s), stopped tid={stoppedTid}");
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
                    Trunc(top, 37), ClarionThreadText(p), p.Created == default(DateTime) ? "-" : p.Created.ToString("HH:mm:ss.fff")));
            }
            foreach (var p in probes)
            {
                Console.WriteLine($"    --- tid {p.Tid} (seq {p.Seq}){(p.IsStopped ? " [STOPPED]" : "")} ---");
                Console.WriteLine($"        eip=0x{p.Eip:X8} esp=0x{p.Esp:X8} ebp=0x{p.Ebp:X8} image={p.EipImage ?? "(none)"}{(p.EipSym != null ? " sym=" + p.EipSym : "")}");
                Console.WriteLine($"        start=0x{p.StartAddr:X8} in {p.StartImage ?? "(unknown)"}   clarionThread={ClarionThreadText(p)}");
                if (p.Probed != null) Console.WriteLine($"        {probeName} = {p.Probed}");
                Console.WriteLine($"        windows: {p.VisibleWindows} visible, {p.HiddenWindows} hidden"
                                  + (p.CrossRank != int.MaxValue ? $", crossRank={p.CrossRank}" : ""));
                foreach (var w in p.Windows) Console.WriteLine("          " + w);
                if (p.TopFrames.Count == 0) Console.WriteLine("        clarion frames: (none)");
                else for (int i = 0; i < p.TopFrames.Count; i++) Console.WriteLine($"        #{i} {p.TopFrames[i]}");
            }

            if (EmitJson) Console.WriteLine("@JSON " + ThreadScanJson(stoppedTid, probes));
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

        /// <summary>The top-level "stopped" here is a thread id under another name, so it goes through the
        /// shared writer exactly as "tid" does (ticket 3b043dfc) — absent when unknown, never 0. The
        /// per-row "stopped" below is a boolean about the row and keeps its name and its literal.</summary>
        private static string ThreadScanJson(uint stoppedTid, List<ThreadProbe> probes)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"threadscan\"");
            AppendTidValuedMember(sb, TidMemberStopped, stoppedTid);
            sb.Append(",\"threads\":[");
            for (int i = 0; i < probes.Count; i++)
            {
                var p = probes[i];
                if (i > 0) sb.Append(',');
                // The tid goes through AppendTidMember like every other tid the engine writes, which means
                // it lands at the END of the row rather than the front. Member order is not significant to
                // any consumer (all of them parse the object), and one guarded writer is worth more than a
                // familiar field order — see the rule holder in DebugEngine.cs.
                sb.Append("{\"seq\":").Append(p.Seq)
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
                  .Append(",\"clarionThread\":").Append(ClarionThreadJson(p.ClarionThread))
                  .Append(",\"clarionThreadWhyNot\":").Append(Json.Str(p.ClarionThreadWhyNot))
                  .Append(",\"start\":\"0x").Append(p.StartAddr.ToString("X8")).Append('"')
                  .Append(",\"startImage\":").Append(Json.Str(p.StartImage))
                  .Append(",\"probed\":").Append(Json.Str(p.Probed))
                  .Append(",\"visibleWindows\":").Append(p.VisibleWindows)
                  .Append(",\"hiddenWindows\":").Append(p.HiddenWindows)
                  .Append(",\"crossRank\":").Append(p.CrossRank == int.MaxValue ? -1 : p.CrossRank);
                AppendTidMember(sb, p.Tid);
                sb.Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }
        // ---------------------------------------------------------------- test seam for the scan emitter

        internal static string ThreadScanJsonForTest(uint stoppedTid, uint[] tids)
        {
            return ThreadScanJson(stoppedTid, ProbesForTest(tids, stoppedTid));
        }
    }
}
