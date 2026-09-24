using System;
using System.Collections.Generic;

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
