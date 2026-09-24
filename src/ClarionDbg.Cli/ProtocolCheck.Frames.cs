using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The EBP-chain walk above a foreign top frame (ticket 70b58a1a): after a Pause the thread sits in
        /// win32u under user32 and ClaRUN, and the Clarion frame's base is found by following saved-EBP links
        /// up through that code. Drives the shipped DebugEngine.FindForeignTopLink over synthetic stacks, so
        /// no process is needed. The stack shapes are the ones measured live on clbrws on 2026-09-24: a Pause
        /// at the splash screen had a stale SPLASHSCREEN return between two runtime links, one slot above
        /// user32's frame, which the old scan reported as the innermost frame.
        ///
        /// NOT COVERED: what BuildStack does with the link (the ordinary chain walk from it), the TEB bounds
        /// read, and whether a slot really is a Clarion return (TSWD + CALL-precedes). Those need a live
        /// target; the live acceptance is a Pause on clbrws showing SPLASHSCREEN/MAIN with a real ebp.
        /// </summary>
        private static void CheckForeignTopChain(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a foreign top frame (a Pause in the OS) is walked up its saved-EBP links to the first link "
                         + "whose return is Clarion code, skipping a stale Clarion return between links; a frameless "
                         + "callee (DebugBreak) yields its caller from the Clarion return AT ESP, and only when EBP "
                         + "itself is the first Clarion link; a Clarion return higher in [ESP, EBP) is reported as "
                         + "uncertain, and one past the scan cap not at all; a link that is misaligned, below ESP, too "
                         + "close to StackBase, not climbing, or unreadable fails the walk, as does a chain longer than "
                         + "the link cap. Not covered: the chain walk from the link, the TEB read, return validation.");

            // Pause: esp 0x1000; user32's frame at 0x1040 -> ClaRUN 0x1080 -> ClaRUN 0x10C0, whose return slot
            // 0x10C4 is Clarion. 0x1048 is a stale Clarion return INSIDE a runtime frame, 0x1004 another below.
            var pause = new Dictionary<uint, uint> { { 0x1040, 0x1080 }, { 0x1080, 0x10C0 }, { 0x10C0, 0x1100 } };
            ExpectLink(failures, "pause", 0x1040, 0x1000, 0x2000, pause, new uint[] { 0x1004, 0x1048, 0x10C4 },
                       true, 0x10C0, 0);

            // DebugBreak: esp 0x2000 holds the return into the Clarion caller, whose own frame is EBP = 0x2040;
            // 0x2044 returns into ITS caller. 0x2010 is a stale Clarion return in the caller's locals: the
            // frameless callee's slot is the one AT ESP.
            var brk = new Dictionary<uint, uint> { { 0x2040, 0x2080 } };
            ExpectLink(failures, "DebugBreak", 0x2040, 0x2000, 0x3000, brk, new uint[] { 0x2000, 0x2010, 0x2044 },
                       true, 0x2040, 0x2000);

            // A FRAMED foreign function called straight from Clarion looks the same from EBP: its EBP 0x2040 is
            // the first Clarion link. ESP 0x2000 is its own data, and 0x2010 a stale Clarion return among its
            // locals. That is no proof of a caller, so it is reported uncertain (no frame base).
            ExpectLink(failures, "a stale return above ESP (framed foreign callee)", 0x2040, 0x2000, 0x3000, brk,
                       new uint[] { 0x2010, 0x2044 }, true, 0x2040, 0x2010, true);

            // The frameless scan is capped like every other walk: 0x5000 above ESP is past it. Nothing is
            // reported, and the scan asked about no slot past the cap.
            uint capLo = 0x10000, capEbp = capLo + 0x8000;
            var capAsked = new List<uint>();
            uint capLink, capSlot; bool capUnc;
            bool capFound = DebugEngine.FindForeignTopLink(capEbp, capLo, capEbp + 0x100,
                va => (uint?)null, s => { capAsked.Add(s); return s == capLo + 0x5000 || s == capEbp + 4; },
                out capLink, out capSlot, out capUnc);
            if (!capFound || capLink != capEbp || capSlot != 0)
                failures.Add("foreign top: a Clarion return 0x5000 above ESP was taken from a capped scan: found="
                             + capFound + " link=0x" + capLink.ToString("X") + " frameless=0x" + capSlot.ToString("X"));
            if (capAsked.Exists(s => s != capEbp + 4 && s >= capLo + 0x4000))
                failures.Add("foreign top: the frameless scan read past its cap (0x4000 above ESP)");

            // A frameless candidate is taken ONLY when EBP is the first Clarion link. Here the first link is
            // one runtime frame up, so 0x2000 lies inside that frame and is no caller.
            var brk2 = new Dictionary<uint, uint> { { 0x2040, 0x2080 } };
            ExpectLink(failures, "no frameless past a runtime link", 0x2040, 0x2000, 0x3000, brk2,
                       new uint[] { 0x2000, 0x2084 }, true, 0x2080, 0);

            // Fail-closed shapes. Each has a Clarion return where a guessing walk would land.
            // FPO: the runtime used EBP as a scratch register, and it happens to hold a stack address BELOW the
            // link it was read from - still inside the stack, and a Clarion return sits above it.
            ExpectLink(failures, "FPO: a link that goes DOWN", 0x1080, 0x1000, 0x2000,
                       new Dictionary<uint, uint> { { 0x1080, 0x1040 } }, new uint[] { 0x1044 }, false, 0, 0);
            ExpectLink(failures, "a link that repeats", 0x1040, 0x1000, 0x2000,
                       new Dictionary<uint, uint> { { 0x1040, 0x1040 } }, new uint[0], false, 0, 0);
            ExpectLink(failures, "a link below ESP", 0x0F80, 0x1000, 0x2000,
                       new Dictionary<uint, uint>(), new uint[] { 0x0F84 }, false, 0, 0);
            ExpectLink(failures, "a misaligned link", 0x1040, 0x1000, 0x2000,
                       new Dictionary<uint, uint> { { 0x1040, 0x1082 } }, new uint[] { 0x1086 }, false, 0, 0);
            ExpectLink(failures, "a link past StackBase", 0x1040, 0x1000, 0x2000,
                       new Dictionary<uint, uint> { { 0x1040, 0x1FFC } }, new uint[] { 0x2000 }, false, 0, 0);
            ExpectLink(failures, "a link AT StackBase - 8 is the last one allowed", 0x1FF8, 0x1000, 0x2000,
                       new Dictionary<uint, uint>(), new uint[] { 0x1FFC }, true, 0x1FF8, 0);
            ExpectLink(failures, "an unreadable link", 0x1040, 0x1000, 0x2000,
                       new Dictionary<uint, uint>(), new uint[] { 0x1084 }, false, 0, 0);
            ExpectLink(failures, "a null EBP", 0, 0, 0x2000,
                       new Dictionary<uint, uint>(), new uint[] { 4 }, false, 0, 0);
            ExpectLink(failures, "a StackBase below 8 (hi - 8 would wrap)", 4, 0, 4,
                       new Dictionary<uint, uint>(), new uint[] { 8 }, false, 0, 0);

            // The link cap: an endless climbing chain with no Clarion return must end, and fail.
            uint link, framelessSlot; bool uncertainSlot; int reads = 0;
            bool found = DebugEngine.FindForeignTopLink(0x1000, 0x1000, 0x7FFFFFF0,
                va => { reads++; return va + 0x10000; }, slot => false, out link, out framelessSlot, out uncertainSlot);
            if (found)
                failures.Add("foreign top: an endless chain with no Clarion return reported link 0x" + link.ToString("X"));
            if (reads > 1000)
                failures.Add("foreign top: an endless chain was read " + reads + " times - the link cap did not stop it");
        }

        /// <summary>
        /// The frame-bound watch (ticket bae5f46d): a local-headed watch resolves in Clarion's scope order (the
        /// Owner's decision of 2026-09-24): the stopped frame's locals, then global data, then the INNERMOST
        /// caller frame whose procedure declares the head, and it says which frame when it is not frame 0. Drives the
        /// shipped DebugEngine.WatchFrameFor (the scope order), InnermostFrameWith (the caller-frame choice),
        /// Json.Watch (the frozen frameIdx/frameProc contract, 2026-09-24) and the per-stop frame cache through
        /// its seams.
        ///
        /// NOT COVERED: whether a frame's procedure declares a name (TSWD locals), the slot arithmetic, and
        /// that PausedWait clears the cache at every stop, which tools/test-engine-framecache-sites.ps1 pins by
        /// position. The live acceptance is a watch on a calling procedure's local while stopped in an ABC
        /// method on clbrws.
        /// </summary>
        private static void CheckFrameBoundWatch(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a watched name resolves in Clarion's scope order: the stopped frame's local (after a Pause, "
                         + "the first Clarion frame), then a global, and only then the INNERMOST caller frame that "
                         + "declares it, so a caller's local never shadows a global the stopped code reads, and a name "
                         + "found in the first Clarion frame is labelled as the current frame (frameIdx 0) while a "
                         + "caller keeps its stack index; a frame "
                         + "with no procedure or no frame base is never asked, and a recursive procedure answers from "
                         + "its innermost activation; the watch event carries frameIdx/frameProc flat only for a frame other than 0; "
                         + "the per-stop frame cache is reused for the same registers and re-walked after a clear or "
                         + "for other registers. Not covered: TSWD local lookup, the PausedWait call site.");

            // A Pause-shaped stack: 0 the OS call (no proc), 1 a scanned frame (no ebp), then BROWSE twice
            // (recursion) and MAIN. BROWSE and MAIN both declare the name.
            var frames = new List<StackFrame>
            {
                new StackFrame { Proc = null, Ebp = 0x1000 },
                new StackFrame { Proc = "BROWSE", Ebp = 0, Uncertain = true },
                new StackFrame { Proc = "BROWSE", Ebp = 0x2000 },
                new StackFrame { Proc = "BROWSE", Ebp = 0x3000 },
                new StackFrame { Proc = "MAIN", Ebp = 0x4000 },
            };
            var asked = new List<uint>();
            int got = DebugEngine.InnermostFrameWith(frames, f => { asked.Add(f.Ebp); return f.Proc == "BROWSE" || f.Proc == "MAIN"; });
            if (got != 2)
                failures.Add("frame-bound watch: the innermost declaring frame is 2 (BROWSE's inner activation), got " + got);
            if (asked.Contains(0x1000) || asked.Contains(0))
                failures.Add("frame-bound watch: a frame with no procedure or no frame base was asked for a local");
            got = DebugEngine.InnermostFrameWith(frames, f => f.Proc == "MAIN");
            if (got != 4)
                failures.Add("frame-bound watch: a local only MAIN declares resolves in frame 4, got " + got);
            got = DebugEngine.InnermostFrameWith(frames, f => false);
            if (got != -1)
                failures.Add("frame-bound watch: a name no frame declares resolves nowhere (-1), got " + got);

            // The scope order. Stopped in Q (frame 0), called from P (frame 1), called from MAIN (frame 2).
            var stop = new List<StackFrame>
            {
                new StackFrame { Proc = "Q", Ebp = 0x1000 },
                new StackFrame { Proc = "P", Ebp = 0x2000 },
                new StackFrame { Proc = "MAIN", Ebp = 0x3000 },
            };
            Func<string[], Func<StackFrame, bool>> declaredBy = procs => f => Array.IndexOf(procs, f.Proc) >= 0;
            got = DebugEngine.WatchFrameFor(stop, declaredBy(new[] { "P" }), true);
            if (got != -1)
                failures.Add("watch scope: Q has no local X and a global X exists, so X is the global Q reads (-1); "
                             + "got frame " + got + ", the CALLER's local, whose edit would write into P's stack");
            got = DebugEngine.WatchFrameFor(stop, declaredBy(new[] { "P", "MAIN" }), false);
            if (got != 1)
                failures.Add("watch scope: with no global, a local only callers declare resolves in the innermost "
                             + "of them, frame 1 (P); got " + got);
            got = DebugEngine.WatchFrameFor(stop, declaredBy(new[] { "Q", "P" }), true);
            if (got != 0)
                failures.Add("watch scope: the stopped frame's own local shadows the global (frame 0); got " + got);
            got = DebugEngine.WatchFrameFor(stop, declaredBy(new string[0]), false);
            if (got != -1)
                failures.Add("watch scope: a name nothing declares resolves nowhere (-1); got " + got);

            // After a Pause: frame 0 is the OS call, and the stopped Clarion frame is Q at 1.
            var paused = new List<StackFrame>
            {
                new StackFrame { Proc = null, Ebp = 0x0F00 },
                new StackFrame { Proc = "Q", Ebp = 0x1000 },
                new StackFrame { Proc = "P", Ebp = 0x2000 },
            };
            got = DebugEngine.WatchFrameFor(paused, declaredBy(new[] { "Q" }), true);
            if (got != 1)
                failures.Add("watch scope: after a Pause the first Clarion frame's local (frame 1) comes before the "
                             + "global; got " + got);
            got = DebugEngine.WatchFrameFor(paused, declaredBy(new[] { "P" }), true);
            if (got != -1)
                failures.Add("watch scope: after a Pause a caller of the first Clarion frame still comes after the "
                             + "global (-1); got " + got);

            // The label: the first Clarion frame IS the stopped frame, so it reports 0 (no frame fields) even
            // after a Pause, where it sits at 1; a caller beyond it keeps its own stack index.
            int rep = DebugEngine.ReportedFrameIdx(paused, 1);
            if (rep != 0)
                failures.Add("watch label: after a Pause a name in the first Clarion frame (1) must report frameIdx 0, "
                             + "not \"frame " + rep + ", not the current procedure\"");
            rep = DebugEngine.ReportedFrameIdx(paused, 2);
            if (rep != 2)
                failures.Add("watch label: a caller beyond the first Clarion frame keeps its stack index 2; got " + rep);
            rep = DebugEngine.ReportedFrameIdx(stop, 0);
            if (rep != 0)
                failures.Add("watch label: an ordinary stop's frame 0 reports 0; got " + rep);

            // The contract: flat, only for a frame other than 0.
            var bytes = new byte[4];
            Func<int, string, string> watch = (idx, proc) => Json.Watch("L", true, 0x2000, 0x2000, false, 0x11, "LONG", 4, 0,
                                                                         "1", bytes, 4, true, null, frameIdx: idx, frameProc: proc);
            foreach (var idx in new[] { -1, 0 })
            {
                string j = watch(idx, idx == 0 ? "BROWSE" : null);
                if (j.Contains("frameIdx") || j.Contains("frameProc"))
                    failures.Add("frame-bound watch: frameIdx " + idx + " must carry no frame fields: " + j);
            }
            string j2 = watch(2, "BROWSE");
            if (!j2.Contains(",\"frameIdx\":2,\"frameProc\":\"BROWSE\""))
                failures.Add("frame-bound watch: a caller-frame local must carry \"frameIdx\":2,\"frameProc\":\"BROWSE\" flat: " + j2);

            // The cache: one walk per stop and register set.
            var eng = NewEngine();
            var a = eng.FramesForStopForTest(0x401000, 0x19F000, 0x19F100);
            var b = eng.FramesForStopForTest(0x401000, 0x19F000, 0x19F100);
            if (!ReferenceEquals(a, b))
                failures.Add("frame cache: the same registers at the same stop walked the stack twice");
            var c = eng.FramesForStopForTest(0x401004, 0x19F000, 0x19F100);
            if (ReferenceEquals(a, c))
                failures.Add("frame cache: a setip (new EIP) reused the old frames");
            var d = eng.FramesForStopForTest(0x401004, 0x19E000, 0x19F100);
            if (ReferenceEquals(c, d))
                failures.Add("frame cache: another thread's registers (new ESP) reused the old frames");
            var e0 = eng.FramesForStopForTest(0x401004, 0x19E000, 0x19E100);
            if (ReferenceEquals(d, e0))
                failures.Add("frame cache: a new EBP reused the old frames");
            eng.ClearFrameCacheForTest();
            var f0 = eng.FramesForStopForTest(0x401004, 0x19E000, 0x19E100);
            if (ReferenceEquals(e0, f0))
                failures.Add("frame cache: frames survived the clear every stop makes, so a resume would reuse them");
        }

        /// <summary>
        /// A ROUTINE frame's owner (found live on clbrws, 2026-09-24): a routine has its OWN EBP frame, and its
        /// visible locals are its owning procedure's, read at the OWNER's frame base. The owner is the first
        /// return up the saved-EBP chain that does not land in a routine, in the routine's own compiland. Drives
        /// the shipped DebugEngine.FindRoutineOwner over synthetic stacks. The first shape is the measured one:
        /// REFRESHWINDOW, DOne from INITIALIZEWINDOW, DOne from BROWSEJOBSGRAPHS.
        ///
        /// NOT COVERED: ReturnSite's symbol and compiland lookup (TSWD), and the local slot arithmetic.
        /// </summary>
        private static void CheckRoutineOwnerWalk(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a routine frame's locals come from its OWNER's frame: the first return up the saved-EBP chain "
                         + "that does not land in a routine (a procedure or a method), whose saved EBP is the owner's base; "
                         + "a hop into another compiland or image, a link that does not climb, an unreadable link or a "
                         + "chain past the nesting cap finds no owner. A routine stopped at its ENTRY (prologue not run) "
                         + "takes its DOer from the return at ESP: a procedure is the owner at the current EBP, and a "
                         + "routine's owner is walked from the current EBP. Not covered: the TSWD lookup of a return "
                         + "site, and the entry test itself (AtProcEntry).");

            const int MI = 7;
            Func<SymbolKind, uint, int, DebugEngine.ReturnSiteInfo> site =
                (k, e, mi) => new DebugEngine.ReturnSiteInfo { Kind = k, EntryRva = e, ModuleIdx = mi };
            // Returns: 0x500 in INITIALIZEWINDOW (a routine), 0x600 in BROWSEJOBSGRAPHS (the procedure), 0x650 in
            // the procedure that called BROWSEJOBSGRAPHS (same compiland), 0x700 in a method, 0x800 in a routine
            // of ANOTHER compiland, 0x900 outside the image.
            var sites = new Dictionary<uint, DebugEngine.ReturnSiteInfo>
            {
                { 0x500, site(SymbolKind.Routine, 0x7CEAD, MI) },
                { 0x600, site(SymbolKind.Procedure, 0x7E000, MI) },
                { 0x650, site(SymbolKind.Procedure, 0x70000, MI) },
                { 0x700, site(SymbolKind.Method, 0x7D000, MI) },
                { 0x800, site(SymbolKind.Routine, 0x1000, MI + 1) },
            };
            Func<uint, DebugEngine.ReturnSiteInfo> siteOf = r => { DebugEngine.ReturnSiteInfo v; return sites.TryGetValue(r, out v) ? v : null; };

            // REFRESHWINDOW 0xC18 -> INITIALIZEWINDOW 0xC2C -> BROWSEJOBSGRAPHS 0xEB8
            ExpectOwner(failures, "routine DOne from a routine DOne from the procedure", 0xC18, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xC18, 0xC2C }, { 0xC1C, 0x500 }, { 0xC2C, 0xEB8 }, { 0xC30, 0x600 } },
                        true, 0x7E000, 0xEB8);
            ExpectOwner(failures, "routine DOne from a method", 0xC18, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xC18, 0xD00 }, { 0xC1C, 0x700 } }, true, 0x7D000, 0xD00);
            ExpectOwner(failures, "a hop into another compiland", 0xC18, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xC18, 0xC2C }, { 0xC1C, 0x800 }, { 0xC2C, 0xEB8 }, { 0xC30, 0x600 } },
                        false, 0, 0);
            ExpectOwner(failures, "a hop out of the image", 0xC18, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xC18, 0xC2C }, { 0xC1C, 0x900 } }, false, 0, 0);
            ExpectOwner(failures, "a link that does not climb", 0xC18, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xC18, 0xB00 }, { 0xC1C, 0x600 } }, false, 0, 0);
            ExpectOwner(failures, "an unreadable saved EBP", 0xC18, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xC1C, 0x600 } }, false, 0, 0);

            // At a routine's ENTRY its prologue has not run: EBP is still the DOer's, and the return into the
            // DOer is at ESP (0xB00). Walked from EBP, BROWSEJOBSGRAPHS's own return into ITS caller (0x650, a
            // procedure of the same compiland) would be taken as the owner, with that caller's EBP 0xF00.
            var atEntry = new Dictionary<uint, uint>
            {
                { 0xB00, 0x600 },                       // [ESP]: the routine's return into BROWSEJOBSGRAPHS
                { 0xEB8, 0xF00 }, { 0xEBC, 0x650 },     // BROWSEJOBSGRAPHS's frame: its return into its caller
            };
            ExpectOwner(failures, "a routine at its entry, DOne from the procedure", 0xEB8, MI, siteOf, atEntry,
                        true, 0x7E000, 0xEB8, 0xB00);
            // DOne from another routine: EBP is INITIALIZEWINDOW's own frame, whose owner is walked from there.
            ExpectOwner(failures, "a routine at its entry, DOne from a routine", 0xC2C, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xB00, 0x500 }, { 0xC2C, 0xEB8 }, { 0xC30, 0x600 } },
                        true, 0x7E000, 0xEB8, 0xB00);
            ExpectOwner(failures, "a routine at its entry, DOer in another compiland", 0xEB8, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xB00, 0x800 }, { 0xEB8, 0xF00 }, { 0xEBC, 0x600 } },
                        false, 0, 0, 0xB00);
            ExpectOwner(failures, "a routine at its entry, unreadable ESP", 0xEB8, MI, siteOf,
                        new Dictionary<uint, uint> { { 0xEB8, 0xF00 }, { 0xEBC, 0x600 } }, false, 0, 0, 0xB00);

            // The nesting cap: routines all the way up must end, and fail.
            int reads = 0; uint oe, ob;
            bool found = DebugEngine.FindRoutineOwner(0x1000, MI, 0, va => { reads++; return (va & 4) != 0 ? 0x500u : va + 0x10000; },
                                                      siteOf, out oe, out ob);
            if (found)
                failures.Add("routine owner: an endless chain of routines reported owner 0x" + oe.ToString("X"));
            if (reads > 1000)
                failures.Add("routine owner: an endless chain of routines was read " + reads + " times - the nesting cap did not stop it");
        }

        private static void ExpectOwner(List<string> failures, string what, uint ebp, int mi,
                                        Func<uint, DebugEngine.ReturnSiteInfo> siteOf, Dictionary<uint, uint> mem,
                                        bool wantFound, uint wantEntry, uint wantEbp, uint entrySlot = 0)
        {
            uint entry, oebp;
            bool found = DebugEngine.FindRoutineOwner(ebp, mi, entrySlot, va => { uint v; return mem.TryGetValue(va, out v) ? v : (uint?)null; },
                                                      siteOf, out entry, out oebp);
            if (found != wantFound || entry != wantEntry || oebp != wantEbp)
                failures.Add("routine owner: " + what + ": got found=" + found + " entry=0x" + entry.ToString("X")
                             + " ebp=0x" + oebp.ToString("X") + ", expected found=" + wantFound + " entry=0x"
                             + wantEntry.ToString("X") + " ebp=0x" + wantEbp.ToString("X"));
        }

        private static void ExpectLink(List<string> failures, string what, uint ebp, uint lo, uint hi,
                                       Dictionary<uint, uint> mem, uint[] clarionSlots,
                                       bool wantFound, uint wantLink, uint wantFrameless, bool wantUncertain = false)
        {
            var slots = new HashSet<uint>(clarionSlots);
            uint link, framelessSlot; bool uncertain;
            bool found = DebugEngine.FindForeignTopLink(ebp, lo, hi,
                va => { uint v; return mem.TryGetValue(va, out v) ? v : (uint?)null; },
                slots.Contains, out link, out framelessSlot, out uncertain);
            if (found != wantFound || link != wantLink || framelessSlot != wantFrameless || uncertain != wantUncertain)
                failures.Add("foreign top: " + what + ": got found=" + found + " link=0x" + link.ToString("X")
                             + " frameless=0x" + framelessSlot.ToString("X") + " uncertain=" + uncertain
                             + ", expected found=" + wantFound + " link=0x" + wantLink.ToString("X") + " frameless=0x"
                             + wantFrameless.ToString("X") + " uncertain=" + wantUncertain);
        }
    }
}
