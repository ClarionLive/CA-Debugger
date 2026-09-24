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
                         + "callee (DebugBreak) yields its caller at the LOWEST Clarion return below EBP, and only when "
                         + "EBP itself is the first Clarion link; a link that is misaligned, below ESP, too close to "
                         + "StackBase, not climbing, or unreadable fails the walk, as does a chain longer than the link "
                         + "cap. Not covered: the chain walk from the link, the TEB read, return validation.");

            // Pause: esp 0x1000; user32's frame at 0x1040 -> ClaRUN 0x1080 -> ClaRUN 0x10C0, whose return slot
            // 0x10C4 is Clarion. 0x1048 is a stale Clarion return INSIDE a runtime frame, 0x1004 another below.
            var pause = new Dictionary<uint, uint> { { 0x1040, 0x1080 }, { 0x1080, 0x10C0 }, { 0x10C0, 0x1100 } };
            ExpectLink(failures, "pause", 0x1040, 0x1000, 0x2000, pause, new uint[] { 0x1004, 0x1048, 0x10C4 },
                       true, 0x10C0, 0);

            // DebugBreak: esp 0x2000 holds the return into the Clarion caller, whose own frame is EBP = 0x2040;
            // 0x2044 returns into ITS caller. 0x2010 is a stale Clarion return in the caller's locals: the
            // frameless callee's slot is the LOWEST one.
            var brk = new Dictionary<uint, uint> { { 0x2040, 0x2080 } };
            ExpectLink(failures, "DebugBreak", 0x2040, 0x2000, 0x3000, brk, new uint[] { 0x2000, 0x2010, 0x2044 },
                       true, 0x2040, 0x2000);

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
            uint link, framelessSlot; int reads = 0;
            bool found = DebugEngine.FindForeignTopLink(0x1000, 0x1000, 0x7FFFFFF0,
                va => { reads++; return va + 0x10000; }, slot => false, out link, out framelessSlot);
            if (found)
                failures.Add("foreign top: an endless chain with no Clarion return reported link 0x" + link.ToString("X"));
            if (reads > 1000)
                failures.Add("foreign top: an endless chain was read " + reads + " times - the link cap did not stop it");
        }

        /// <summary>
        /// The frame-bound watch (ticket bae5f46d): a local-headed watch resolves against the INNERMOST stack
        /// frame whose procedure declares the head, and says which frame when it is not frame 0. Drives the
        /// shipped DebugEngine.InnermostFrameWith (the frame choice), Json.Watch (the frozen frameIdx/frameProc
        /// contract, 2026-09-24) and the per-stop frame cache through its seams.
        ///
        /// NOT COVERED: whether a frame's procedure declares a name (TSWD locals), the slot arithmetic, and
        /// that PausedWait clears the cache at every stop, which tools/test-engine-framecache-sites.ps1 pins by
        /// position. The live acceptance is a watch on a calling procedure's local while stopped in an ABC
        /// method on clbrws.
        /// </summary>
        private static void CheckFrameBoundWatch(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a local-headed watch takes the INNERMOST frame that declares the head, never asking a frame "
                         + "with no procedure or no frame base, so a recursive procedure answers from its innermost "
                         + "activation; the watch event carries frameIdx/frameProc flat only for a frame other than 0; "
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
                         + "chain past the nesting cap finds no owner. Not covered: the TSWD lookup of a return site.");

            const int MI = 7;
            Func<SymbolKind, uint, int, DebugEngine.ReturnSiteInfo> site =
                (k, e, mi) => new DebugEngine.ReturnSiteInfo { Kind = k, EntryRva = e, ModuleIdx = mi };
            // Returns: 0x500 in INITIALIZEWINDOW (a routine), 0x600 in BROWSEJOBSGRAPHS (the procedure), 0x700 in a
            // method, 0x800 in a routine of ANOTHER compiland, 0x900 outside the image.
            var sites = new Dictionary<uint, DebugEngine.ReturnSiteInfo>
            {
                { 0x500, site(SymbolKind.Routine, 0x7CEAD, MI) },
                { 0x600, site(SymbolKind.Procedure, 0x7E000, MI) },
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

            // The nesting cap: routines all the way up must end, and fail.
            int reads = 0; uint oe, ob;
            bool found = DebugEngine.FindRoutineOwner(0x1000, MI, va => { reads++; return (va & 4) != 0 ? 0x500u : va + 0x10000; },
                                                      siteOf, out oe, out ob);
            if (found)
                failures.Add("routine owner: an endless chain of routines reported owner 0x" + oe.ToString("X"));
            if (reads > 1000)
                failures.Add("routine owner: an endless chain of routines was read " + reads + " times - the nesting cap did not stop it");
        }

        private static void ExpectOwner(List<string> failures, string what, uint ebp, int mi,
                                        Func<uint, DebugEngine.ReturnSiteInfo> siteOf, Dictionary<uint, uint> mem,
                                        bool wantFound, uint wantEntry, uint wantEbp)
        {
            uint entry, oebp;
            bool found = DebugEngine.FindRoutineOwner(ebp, mi, va => { uint v; return mem.TryGetValue(va, out v) ? v : (uint?)null; },
                                                      siteOf, out entry, out oebp);
            if (found != wantFound || entry != wantEntry || oebp != wantEbp)
                failures.Add("routine owner: " + what + ": got found=" + found + " entry=0x" + entry.ToString("X")
                             + " ebp=0x" + oebp.ToString("X") + ", expected found=" + wantFound + " entry=0x"
                             + wantEntry.ToString("X") + " ebp=0x" + wantEbp.ToString("X"));
        }

        private static void ExpectLink(List<string> failures, string what, uint ebp, uint lo, uint hi,
                                       Dictionary<uint, uint> mem, uint[] clarionSlots,
                                       bool wantFound, uint wantLink, uint wantFrameless)
        {
            var slots = new HashSet<uint>(clarionSlots);
            uint link, framelessSlot;
            bool found = DebugEngine.FindForeignTopLink(ebp, lo, hi,
                va => { uint v; return mem.TryGetValue(va, out v) ? v : (uint?)null; },
                slots.Contains, out link, out framelessSlot);
            if (found != wantFound || link != wantLink || framelessSlot != wantFrameless)
                failures.Add("foreign top: " + what + ": got found=" + found + " link=0x" + link.ToString("X")
                             + " frameless=0x" + framelessSlot.ToString("X") + ", expected found=" + wantFound
                             + " link=0x" + wantLink.ToString("X") + " frameless=0x" + wantFrameless.ToString("X"));
        }
    }
}
