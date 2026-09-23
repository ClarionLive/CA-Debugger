using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        // ------------------------------------------------------------------ set next statement (a77abd94)
        //
        // WHAT THESE DO NOT GUARD, stated so a green run is not read as more than it is:
        //  - that the pause loop dispatches `setip` to HandleSetIpCommand, that the running loop answers it with
        //    not-paused, or that a successful move re-runs AnnounceStop. Those need a live stop.
        //  - the re-arm handover (re-plant the old VA before restoring the target's byte). It writes target
        //    memory, which no seam here can do. The live test on item 1 covers it: a breakpoint on the origin
        //    line still fires after a setip away from it.
        //  - that ClaRUN compiles every ACCEPT in the measured shape. The fixtures are hand-built from the two
        //    clbrws loops measured on 2026-09-23 (SplashScreen 0x754F8/0x7569D, BrowseAuthors 0x2EB71/0x2EE62).

        private const uint FxStart = 0x4E1960;   // IAT slot of ClaRUN.dll!Cla$StartEventLoop in clbrws.exe
        private const uint FxEnd   = 0x4E1688;   // ... Cla$EndEventLoop
        private const uint FxOther = 0x4E19D8;   // ... _malloc: an import that is not an event loop
        private const uint FxBase  = 0x475400;

        private static string FxSlotName(uint abs)
        {
            if (abs == FxStart) return "ClaRUN.dll!Cla$StartEventLoop";
            if (abs == FxEnd) return "ClaRUN.dll!Cla$EndEventLoop";
            if (abs == FxOther) return "ClaRUN.dll!_malloc";
            return null;
        }

        /// <summary>A tiny x86 assembler for the fixtures: only the shapes ClaRUN's ACCEPT compiles to.</summary>
        private sealed class Fx
        {
            private readonly List<byte> _b = new List<byte>();
            public uint Here { get { return FxBase + (uint)_b.Count; } }
            public Fx Nop(int n = 1) { for (int i = 0; i < n; i++) _b.Add(0x90); return this; }
            public Fx CallSlot(uint slot) { _b.Add(0xFF); _b.Add(0x15); U32(slot); return this; }
            /// <summary>call rel32 (E8) to an absolute target.</summary>
            public Fx CallRel(uint target) { _b.Add(0xE8); U32(target - (Here + 4)); return this; }
            public Fx CallEax() { _b.Add(0xFF); _b.Add(0xD0); return this; }
            public Fx Raw(params byte[] bytes) { _b.AddRange(bytes); return this; }
            public Fx MovEaxImm(uint v) { _b.Add(0xB8); U32(v); return this; }
            public Fx CmpAl0() { _b.Add(0x3C); _b.Add(0x00); return this; }
            public Fx CmpBl0() { _b.Add(0x80); _b.Add(0xFB); _b.Add(0x00); return this; }
            /// <summary>je rel32 to an absolute target.</summary>
            public Fx Je32(uint target) { _b.Add(0x0F); _b.Add(0x84); U32(target - (Here + 4)); return this; }
            public Fx Je8(uint target) { _b.Add(0x74); _b.Add((byte)(sbyte)(int)(target - (Here + 1))); return this; }
            public Fx Jne32(uint target) { _b.Add(0x0F); _b.Add(0x85); U32(target - (Here + 4)); return this; }
            private void U32(uint v) { _b.AddRange(BitConverter.GetBytes(v)); }
            public byte[] Bytes { get { return _b.ToArray(); } }
        }

        private static string FxRegions(Fx fx, List<DebugEngine.EventLoopRegion> regions)
        {
            var b = fx.Bytes;
            return DebugEngine.FindEventLoopRegions(b, b.Length, FxBase, FxSlotName, regions);
        }

        /// <summary>
        /// ACCEPT-region detection, over hand-built byte fixtures: one loop, two nested loops, an unpaired
        /// Start, an unpaired End, a back-edge whose je targets the wrong place, a back-edge without its
        /// `cmp al,0`, and a slot reference the decoder cannot see. Each malformed fixture must REFUSE (a
        /// non-null reason and no regions): a structure read as "no ACCEPT here" when there is one would let
        /// a setip cross a loop boundary.
        /// </summary>
        private static void CheckSetIpEventLoopRegions(List<string> failures, ClaimLog claims)
        {
            claims.Claim("setip's ACCEPT-region finder pairs each Cla$StartEventLoop call with the "
                         + "Cla$EndEventLoop back-edge whose je targets its return address, names the INNERMOST "
                         + "loop for nested ones, and refuses (fails closed) on an unpaired Start, an unpaired End, "
                         + "a je aimed elsewhere, a back-edge without cmp al,0, and a slot reference the decoder "
                         + "missed. Not covered: that ClaRUN compiles every ACCEPT in this shape.");
            var regions = new List<DebugEngine.EventLoopRegion>();

            // ---- one loop, in the measured shape (a je rel32, as clbrws has it)
            var fx = new Fx().Nop(2);
            uint before = fx.Here; fx.MovEaxImm(0);
            uint startCall = fx.Here; fx.CallSlot(FxStart);
            uint lo = fx.Here; fx.MovEaxImm(0);
            uint body = fx.Here; fx.CallSlot(FxOther).Nop(3);
            uint backEdgeLine = fx.Here; fx.Nop();
            fx.CallSlot(FxEnd).CmpAl0().Je32(lo);
            uint after = fx.Here; fx.Nop(2);
            string err = FxRegions(fx, regions);
            if (err != null || regions.Count != 1)
                failures.Add("setip regions: the single measured-shape loop was not found (" + (err ?? regions.Count + " regions") + ")");
            else
            {
                var r = regions[0];
                if (r.StartCall != startCall || r.Lo != lo || r.Hi != after)
                    failures.Add("setip regions: single loop read as start 0x" + r.StartCall.ToString("X") + " [0x" + r.Lo.ToString("X")
                                 + ",0x" + r.Hi.ToString("X") + "), expected 0x" + startCall.ToString("X") + " [0x" + lo.ToString("X") + ",0x" + after.ToString("X") + ")");
                if (DebugEngine.InnermostEventLoop(regions, body) != startCall || DebugEngine.InnermostEventLoop(regions, backEdgeLine) != startCall)
                    failures.Add("setip regions: a body address and the back-edge's own line are not inside the loop");
                if (DebugEngine.InnermostEventLoop(regions, before) != 0 || DebugEngine.InnermostEventLoop(regions, startCall) != 0)
                    failures.Add("setip regions: the ACCEPT line itself (the Start call) or code before it read as INSIDE the loop; "
                                 + "measured: ESP there is the procedure's base, not the loop's");
                if (DebugEngine.InnermostEventLoop(regions, after) != 0)
                    failures.Add("setip regions: the first address after the back-edge read as inside the loop");
            }

            // ---- a je rel8 back-edge is the same loop
            fx = new Fx();
            startCall = fx.Here; fx.CallSlot(FxStart);
            lo = fx.Here; fx.Nop(4).CallSlot(FxEnd).CmpAl0().Je8(lo);
            err = FxRegions(fx, regions);
            if (err != null || regions.Count != 1)
                failures.Add("setip regions: a short (rel8) je back-edge was not paired (" + (err ?? regions.Count + " regions") + ")");

            // ---- nested: the innermost loop wins
            fx = new Fx().Nop();
            uint outerCall = fx.Here; fx.CallSlot(FxStart);
            uint outerLo = fx.Here; fx.Nop(2);
            uint outerBody = fx.Here; fx.Nop(2);
            uint innerCall = fx.Here; fx.CallSlot(FxStart);
            uint innerLo = fx.Here; fx.Nop(2);
            uint innerBody = fx.Here; fx.Nop(2);
            fx.CallSlot(FxEnd).CmpAl0().Je32(innerLo);
            uint outerBody2 = fx.Here; fx.Nop(2);
            fx.CallSlot(FxEnd).CmpAl0().Je32(outerLo);
            fx.Nop();
            err = FxRegions(fx, regions);
            if (err != null || regions.Count != 2)
                failures.Add("setip regions: two nested loops were not both found (" + (err ?? regions.Count + " regions") + ")");
            else
            {
                if (DebugEngine.InnermostEventLoop(regions, innerBody) != innerCall)
                    failures.Add("setip regions: an address in the INNER loop resolved to the outer one - a move between the two loops would pass");
                if (DebugEngine.InnermostEventLoop(regions, outerBody) != outerCall || DebugEngine.InnermostEventLoop(regions, outerBody2) != outerCall)
                    failures.Add("setip regions: an outer-loop address outside the inner loop did not resolve to the outer loop");
            }

            // ---- malformed: every one must refuse, and leave no regions behind
            var bad = new List<KeyValuePair<string, Fx>>();

            fx = new Fx().CallSlot(FxStart).Nop(4);
            bad.Add(new KeyValuePair<string, Fx>("a Start with no back-edge", fx));

            fx = new Fx().Nop(4);
            lo = fx.Here; fx.Nop(2).CallSlot(FxEnd).CmpAl0().Je32(lo);
            bad.Add(new KeyValuePair<string, Fx>("an End whose je targets no Start", fx));

            fx = new Fx().CallSlot(FxStart);
            lo = fx.Here; fx.Nop(2);
            uint wrong = fx.Here; fx.Nop(2).CallSlot(FxEnd).CmpAl0().Je32(wrong);
            bad.Add(new KeyValuePair<string, Fx>("a back-edge whose je targets an address that is not the Start call's return", fx));

            fx = new Fx().CallSlot(FxStart);
            lo = fx.Here; fx.Nop(2).CallSlot(FxEnd).CmpBl0().Je32(lo);
            bad.Add(new KeyValuePair<string, Fx>("a back-edge testing BL instead of AL", fx));

            fx = new Fx().CallSlot(FxStart);
            lo = fx.Here; fx.Nop(2).CallSlot(FxEnd).CmpAl0().Jne32(lo);
            bad.Add(new KeyValuePair<string, Fx>("a back-edge with jne instead of je", fx));

            fx = new Fx().CallSlot(FxStart);
            lo = fx.Here; fx.Nop(2).CallSlot(FxEnd).CmpAl0().Je32(lo).CallSlot(FxEnd).CmpAl0().Je32(lo);
            bad.Add(new KeyValuePair<string, Fx>("one Start claimed by two back-edges", fx));

            // A starts, B starts, A's back-edge, B's back-edge: each pairs, but the regions cross.
            fx = new Fx().CallSlot(FxStart);
            uint aLo = fx.Here; fx.Nop().CallSlot(FxStart);
            uint bLo = fx.Here; fx.Nop().CallSlot(FxEnd).CmpAl0().Je32(aLo).Nop().CallSlot(FxEnd).CmpAl0().Je32(bLo);
            bad.Add(new KeyValuePair<string, Fx>("two loops whose regions overlap without nesting", fx));

            fx = new Fx().CallSlot(FxStart);
            lo = fx.Here; fx.MovEaxImm(FxStart).Nop(2).CallSlot(FxEnd).CmpAl0().Je32(lo);
            bad.Add(new KeyValuePair<string, Fx>("a paired loop plus a slot reference that is not a call (the raw scan must see it)", fx));

            foreach (var kv in bad)
            {
                err = FxRegions(kv.Value, regions);
                if (err == null)
                    failures.Add("setip regions: " + kv.Key + " was ACCEPTED (" + regions.Count + " region(s)) - it must refuse, so setip "
                                 + "cannot treat a loop it failed to read as no loop at all");
                else if (regions.Count != 0)
                    failures.Add("setip regions: " + kv.Key + " refused but left " + regions.Count + " region(s) behind");
            }
        }

        // A measured import (ClaRUN's PUSHBIND, the one clbrws reaches through its thunk at 0x401300) and the
        // in-image addresses the call fixtures aim at.
        private const uint FxListed = 0x4E1838;
        private const string FxListedName = "ClaRUN.dll!Cla$PushBind";
        private const uint FxProcEntry = 0x475158;     // a routine entry (LookupRelated)
        private const uint FxThunkListed = 0x401300;   // jmp [FxListed]
        private const uint FxThunkOther = 0x4012B0;    // jmp [FxOther]
        private const uint FxThunkStart = 0x401100;    // jmp [FxStart]
        private const uint FxUnnamed = 0x401500;       // in-image code that is neither a symbol nor a thunk

        private static string FxSlotNameWithListed(uint abs) { return abs == FxListed ? FxListedName : FxSlotName(abs); }
        private static bool FxIsEntry(uint va) { return va == FxProcEntry; }
        private static uint FxThunk(uint va)
        {
            if (va == FxThunkListed) return FxListed;
            if (va == FxThunkOther) return FxOther;
            if (va == FxThunkStart) return FxStart;
            return 0;
        }
        private static string FxProve(Fx fx, IEnumerable<uint> records = null)
        {
            var b = fx.Bytes;
            return DebugEngine.ProveCallsBalanced(b, b.Length, FxBase, FxSlotNameWithListed, FxIsEntry, FxThunk, records);
        }

        /// <summary>
        /// Every call in the procedure must have a known effect on ESP (pipeline run 1 on a77abd94): a Clarion
        /// procedure, a MEASURED import (directly or through the image's own thunk), or the modelled ACCEPT pair.
        /// Anything else refuses the whole procedure - including the locally-linked build, whose runtime is
        /// reached by E8 calls to unnamed code in the EXE, and which the old rule passed with no proof.
        /// </summary>
        private static void CheckSetIpCallsBalanced(List<string> failures, ClaimLog claims)
        {
            claims.Claim("setip proves every call in the procedure has a known effect on ESP: a call to a Clarion "
                         + "procedure/routine, to a MEASURED import (directly or through the image's jmp [slot] thunk) "
                         + "and the modelled ACCEPT pair pass; an E8 call to unnamed in-image code (a locally-linked "
                         + "runtime), an unmeasured import either way, an indirect call, the event loop through a "
                         + "thunk, and a decode out of step with the line records or a jump target all refuse. "
                         + "Not covered: that the measured list is right for another ClaRUN version.");

            if (!DebugEngine.IsMeasuredBalancedImport(FxListedName))
                failures.Add("setip calls: CONTROL - the fixture's 'measured' import " + FxListedName + " is not on "
                             + "MeasuredBalancedImports, so every 'allowed' case below would be testing the wrong thing");
            if (DebugEngine.IsMeasuredBalancedImport("ClaRUN.dll!_malloc"))
                failures.Add("setip calls: CONTROL - the fixture's unmeasured import is on the measured list");

            Action<string, Fx, bool, string> expect = (what, fx, pass, mustSay) =>
            {
                string err = FxProve(fx);
                if (pass && err != null) failures.Add("setip calls: " + what + " was REFUSED: " + err);
                else if (!pass && err == null) failures.Add("setip calls: " + what + " was ALLOWED - it must refuse (stack-unproven)");
                else if (!pass && mustSay != null && !err.Contains(mustSay))
                    failures.Add("setip calls: " + what + " refused, but the reason does not name '" + mustSay + "': " + err);
            };

            expect("a procedure with no calls", new Fx().Nop(4).MovEaxImm(0), true, null);
            expect("an E8 call to a Clarion routine entry", new Fx().Nop().CallRel(FxProcEntry).Nop(), true, null);
            expect("a call [slot] to a measured import", new Fx().Nop().CallSlot(FxListed).Nop(), true, null);
            expect("an E8 call through the image's thunk to a measured import", new Fx().Nop().CallRel(FxThunkListed).Nop(), true, null);
            var accept = new Fx().CallSlot(FxStart);
            uint lo = accept.Here; accept.Nop(2).CallSlot(FxEnd).CmpAl0().Je32(lo).Nop();
            expect("the modelled ACCEPT pair through call [slot]", accept, true, null);

            expect("an E8 call to unnamed in-image code (a locally-linked runtime)", new Fx().Nop().CallRel(FxUnnamed).Nop(), false, "neither a procedure nor an import");
            expect("a call [slot] to an unmeasured import", new Fx().Nop().CallSlot(FxOther).Nop(), false, "ClaRUN.dll!_malloc not measured");
            expect("an E8 call through a thunk to an unmeasured import", new Fx().Nop().CallRel(FxThunkOther).Nop(), false, "ClaRUN.dll!_malloc not measured");
            expect("a call through an absolute address that is no import slot", new Fx().Nop().CallSlot(0x4E0000).Nop(), false, "not an import slot");
            expect("an indirect call (call eax, as a CLASS method call is)", new Fx().Nop().CallEax().Nop(), false, "indirect call");
            expect("Cla$StartEventLoop reached through a thunk", new Fx().Nop().CallRel(FxThunkStart).Nop(), false, "through a thunk");
            expect("undecodable bytes", new Fx().Nop().Raw(0x0F, 0x04).Nop(), false, "undecodable");

            // In step with the code: a jump into the middle of an instruction, and a line record that is not
            // an instruction boundary, both say the linear sweep cannot be trusted.
            var mid = new Fx();
            uint movAt = mid.Here; mid.MovEaxImm(0x90909090);
            mid.Raw(0xEB, (byte)(sbyte)(int)(movAt + 1 - (mid.Here + 2)));   // jmp short into the mov's immediate
            expect("a jump landing inside an instruction", mid, false, "lands inside an instruction");

            // The prologue exemption, and its edge: an unmeasured call BEFORE the second line record (where
            // every large frame calls __a_chkstk) is not held against the procedure; the same call at or after
            // the second record is. With only ONE record nothing is exempt, and with none nothing is either.
            var pro = new Fx();
            uint entryRec = pro.Here; pro.MovEaxImm(0x1000).CallSlot(FxOther);
            uint bodyRec = pro.Here; pro.Nop(2);
            uint afterBody = pro.Here; pro.Nop();
            string proErr = FxProve(pro, new[] { entryRec, bodyRec });
            if (proErr != null) failures.Add("setip calls: an unmeasured call in the PROLOGUE (before the second record) was held against the procedure: " + proErr);
            proErr = FxProve(pro, new[] { entryRec });
            if (proErr == null) failures.Add("setip calls: with only the entry record the prologue call was exempted - nothing should be exempt then");
            var pro2 = new Fx();
            uint e2 = pro2.Here; pro2.MovEaxImm(0x1000);
            uint b2 = pro2.Here; pro2.CallSlot(FxOther).Nop();
            proErr = FxProve(pro2, new[] { e2, b2 });
            if (proErr == null) failures.Add("setip calls: an unmeasured call AT the second record (the first statement) was exempted as prologue");

            var rec = new Fx();
            uint recMov = rec.Here; rec.MovEaxImm(0).Nop();
            string err2 = FxProve(rec, new[] { recMov + 2 });
            if (err2 == null || !err2.Contains("not on an instruction boundary"))
                failures.Add("setip calls: a line record inside an instruction was not refused: " + (err2 ?? "ALLOWED"));
            if (FxProve(rec, new[] { recMov, recMov + 5 }) != null)
                failures.Add("setip calls: CONTROL - line records on instruction boundaries were refused");
        }

        /// <summary>A SetIpFacts that passes: stopped and selected on one thread, exactly on a statement, the
        /// target one record in the same symbol, past the entry record, no ACCEPT in the procedure.</summary>
        private static DebugEngine.SetIpFacts FxPassingFacts()
        {
            return new DebugEngine.SetIpFacts
            {
                StoppedTid = 100, SelectedTid = 100, HaveCtx = true, Resolved = true, Gap = 0,
                ModuleInImage = true, TargetRvaCount = 1,
                StopSymKnown = true, TargetSymKnown = true, StopEntryRva = 0x75424, TargetEntryRva = 0x75424,
                NextEntryRva = 0x756C0, FirstRecordRva = 0x75424, StopRva = 0x754A7, TargetRva = 0x754D7,
                CodeRead = true, RegionError = null, LoadBase = 0x400000,
            };
        }

        /// <summary>
        /// The setip decision, one input moved at a time from a case that passes, so each refusal is shown
        /// to come from ITS test and not from a neighbour that happens to cover the same case. The ACCEPT
        /// rule is driven with the SplashScreen loop's real addresses.
        /// </summary>
        private static void CheckSetIpDecision(List<string> failures, ClaimLog claims)
        {
            claims.Claim("setip's decision passes a same-procedure move between two statements and refuses each "
                         + "unsafe case with its own code, one input moved at a time: another thread selected, no "
                         + "context, a stop off a statement, another module, a line with no code, an ambiguous "
                         + "line, another symbol or a target outside its span, the entry record as target or as "
                         + "stop, unreadable code, unpaired ACCEPTs, and every ACCEPT boundary crossing (into, out "
                         + "of, BREAK past the end, between nested loops) while moves inside one loop pass.");

            Func<string, Action<DebugEngine.SetIpFacts>, string, bool> expect = (what, move, code) =>
            {
                var f = FxPassingFacts();
                move(f);
                string got = DebugEngine.DecideSetIp(f);
                if (got != code)
                {
                    failures.Add("setip decision: " + what + " -> " + (got ?? "GO") + ", expected " + (code ?? "GO"));
                    return false;
                }
                return true;
            };

            expect("the baseline same-procedure move", f => { }, null);
            expect("another thread selected", f => f.SelectedTid = 200, DebugEngine.SetIpOtherThread);
            expect("no thread context", f => f.HaveCtx = false, DebugEngine.SetIpNoContext);
            expect("a stop that resolved to no line", f => f.Resolved = false, DebugEngine.SetIpNotOnStatement);
            expect("a stop 3 bytes into a statement", f => f.Gap = 3, DebugEngine.SetIpNotOnStatement);
            expect("a module the stopped image does not carry", f => f.ModuleInImage = false, DebugEngine.SetIpOtherModule);
            expect("a line with no code record", f => f.TargetRvaCount = 0, DebugEngine.SetIpNoCode);
            expect("a line with two code records", f => f.TargetRvaCount = 2, DebugEngine.SetIpAmbiguousLine);
            expect("a target in another symbol (a ROUTINE of this procedure)", f => f.TargetEntryRva = 0x752FC, DebugEngine.SetIpOtherProc);
            expect("a stop in no verified symbol", f => f.StopSymKnown = false, DebugEngine.SetIpOtherProc);
            expect("a target in no verified symbol", f => f.TargetSymKnown = false, DebugEngine.SetIpOtherProc);
            // Same symbol name but past the span: the two tests are separate, so each is moved alone.
            expect("a target at the next symbol's entry", f => f.TargetRva = 0x756C0, DebugEngine.SetIpOtherProc);
            expect("a target below the symbol's entry", f => f.TargetRva = 0x75400, DebugEngine.SetIpOtherProc);
            expect("the entry record as TARGET", f => f.TargetRva = 0x75424, DebugEngine.SetIpPrologue);
            expect("the entry record as the STOP (a step-into landed there)", f => f.StopRva = 0x75424, DebugEngine.SetIpPrologue);
            expect("a procedure with no record of its own", f => f.FirstRecordRva = 0, null);
            expect("code that could not be read", f => f.CodeRead = false, DebugEngine.SetIpCodeUnreadable);
            expect("an unpaired ACCEPT", f => f.RegionError = "a StartEventLoop call has no back-edge", DebugEngine.SetIpAcceptUnpaired);
            expect("an unmeasured call in the procedure", f => f.StackError = "ClaRUN.dll!_malloc not measured", DebugEngine.SetIpStackUnproven);
            // Both ends outside every ACCEPT is exactly the case the old rule passed with no proof at all.
            expect("an unmeasured call with both ends outside every ACCEPT", f => { f.StackError = "x not measured"; f.StopRva = 0x754A7; f.TargetRva = 0x754D7; }, DebugEngine.SetIpStackUnproven);

            // The ACCEPT rule, over SplashScreen's measured loop: Start call 0x754F8, body [0x754FE, 0x756AB).
            // Lines: 42 @0x754EB (before), 44 @0x75503 and 88 @0x7569B (inside), 89 @0x756AB (after).
            var splash = new DebugEngine.EventLoopRegion { StartCall = 0x4754F8, Lo = 0x4754FE, Hi = 0x4756AB };
            Action<DebugEngine.SetIpFacts> withLoop = f => f.Regions.Add(splash);
            expect("a move between two lines before the ACCEPT", f => { withLoop(f); f.StopRva = 0x754A7; f.TargetRva = 0x754EB; }, null);
            expect("a move between two lines inside one ACCEPT", f => { withLoop(f); f.StopRva = 0x75503; f.TargetRva = 0x7569B; }, null);
            expect("a move INTO an ACCEPT from before it", f => { withLoop(f); f.StopRva = 0x754EB; f.TargetRva = 0x75503; }, DebugEngine.SetIpAcceptBoundary);
            expect("a move OUT of an ACCEPT to the line after it (BREAK)", f => { withLoop(f); f.StopRva = 0x75503; f.TargetRva = 0x756AB; }, DebugEngine.SetIpAcceptBoundary);
            expect("a move from inside an ACCEPT back to the ACCEPT line itself", f => { withLoop(f); f.StopRva = 0x75503; f.TargetRva = 0x754F8; }, DebugEngine.SetIpAcceptBoundary);

            // Nested: both addresses are "in some loop", so only an INNERMOST comparison refuses this.
            var inner = new DebugEngine.EventLoopRegion { StartCall = 0x475580, Lo = 0x475586, Hi = 0x475600 };
            expect("a move from an inner ACCEPT to its outer ACCEPT", f => { withLoop(f); f.Regions.Add(inner); f.StopRva = 0x75590; f.TargetRva = 0x75620; }, DebugEngine.SetIpAcceptBoundary);
            expect("a move within the inner ACCEPT", f => { withLoop(f); f.Regions.Add(inner); f.StopRva = 0x75590; f.TargetRva = 0x755F0; }, null);
        }

        /// <summary>The setip wire: one sentence per frozen code, the refusal and success shapes, the tid
        /// rule, the argument parser, and that setip is not a resume verb.</summary>
        private static void CheckSetIpWire(List<string> failures, ClaimLog claims)
        {
            var codes = DebugEngine.SetIpRefusalCodes;
            claims.Claim("setip's " + codes.Length + " frozen refusal codes each carry a distinct user-facing "
                         + "sentence, and the refusal and success replies carry no tid of their own (an unknown "
                         + "tid stays absent, a known one is stamped once), `candidates` only on ambiguous-line, "
                         + "no module/line when unparsable; the parser takes a bare module:line only; setip is "
                         + "not a resume verb.");

            var seenCode = new HashSet<string>();
            var seenText = new HashSet<string>();
            foreach (var c in codes)
            {
                if (!seenCode.Add(c)) failures.Add("setip wire: refusal code '" + c + "' is listed twice");
                string msg = DebugEngine.SetIpMessage(c);
                if (string.IsNullOrWhiteSpace(msg)) failures.Add("setip wire: refusal code '" + c + "' has no user-facing sentence");
                else if (!seenText.Add(msg)) failures.Add("setip wire: refusal code '" + c + "' shares its sentence with another code");
                string j = DebugEngine.SetIpRefusedJson(c, "x.clw", 12, 3);
                if (!j.StartsWith("{\"event\":\"setip\",\"ok\":false,\"reason\":\"" + c + "\",\"error\":"))
                    failures.Add("setip wire: refusal for '" + c + "' has the wrong head: " + j);
                if (j.Contains("\"tid\"")) failures.Add("setip wire: refusal for '" + c + "' writes a tid of its own: " + j);
                if ((c == DebugEngine.SetIpAmbiguousLine) != j.Contains("\"candidates\":3"))
                    failures.Add("setip wire: `candidates` must appear on ambiguous-line and nowhere else; '" + c + "' gave " + j);
            }
            if (DebugEngine.SetIpMessage("frobnicate") != null)
                failures.Add("setip wire: an unknown code has a sentence, so a typo in a code would still read as a real refusal");

            // stack-unproven names WHAT was not measured, after the sentence.
            string unproven = DebugEngine.SetIpRefusedJson(DebugEngine.SetIpStackUnproven, "x.clw", 5, 0, "ClaRUN.dll!Cla$FOO not measured");
            if (!unproven.Contains(DebugEngine.SetIpMessage(DebugEngine.SetIpStackUnproven) +" (ClaRUN.dll!Cla$FOO not measured)\""))
                failures.Add("setip wire: a stack-unproven refusal does not carry its detail after the sentence: " + unproven);

            string unparsable = DebugEngine.SetIpRefusedJson(DebugEngine.SetIpBadArgs, null, 0, 0);
            if (unparsable.Contains("\"module\"") || unparsable.Contains("\"line\""))
                failures.Add("setip wire: an unparsable request still wrote module/line: " + unparsable);

            string ok = DebugEngine.SetIpOkJson("clbrws026.clw", 44, 88, 0x75503, 0x475503);
            if (ok != "{\"event\":\"setip\",\"ok\":true,\"module\":\"clbrws026.clw\",\"line\":44,\"fromLine\":88,\"rva\":\"0x75503\",\"va\":\"0x475503\"}")
                failures.Add("setip wire: success shape is " + ok);
            if (DebugEngine.WithTidForTest(ok, 0).Contains("\"tid\""))
                failures.Add("setip wire: an unknown tid became a tid member on the success reply");
            string stamped = DebugEngine.WithTidForTest(DebugEngine.SetIpRefusedJson(DebugEngine.SetIpPrologue, "x.clw", 8, 0), 4242);
            if (stamped.Split(new[] { "\"tid\"" }, StringSplitOptions.None).Length != 2)
                failures.Add("setip wire: a stamped refusal does not carry exactly one tid: " + stamped);

            // the parser: a bare .clw basename and a positive line, split on the LAST colon
            string mod; int line;
            if (!DebugEngine.TryParseSetIpArgs(new[] { "setip", "clbrws026.clw:44" }, out mod, out line) || mod != "clbrws026.clw" || line != 44)
                failures.Add("setip wire: 'setip clbrws026.clw:44' did not parse");
            string[][] rejects =
            {
                new[] { "setip" }, new[] { "setip", "clbrws026.clw" }, new[] { "setip", "clbrws026.clw:" },
                new[] { "setip", ":44" }, new[] { "setip", "clbrws026.clw:0" }, new[] { "setip", "clbrws026.clw:-3" },
                new[] { "setip", "clbrws026.clw:4x" }, new[] { "setip", "c:\\src\\a.clw:4" }, new[] { "setip", "..\\a.clw:4" },
                new[] { "setip", "a.clw:4", "extra" }, new[] { "setip", "a.clw:+4" },
            };
            foreach (var r in rejects)
                if (DebugEngine.TryParseSetIpArgs(r, out mod, out line))
                    failures.Add("setip wire: '" + string.Join(" ", r) + "' parsed as " + mod + ":" + line + ", expected bad-args");

            if (DebugEngine.IsResumeVerbForTest("setip"))
                failures.Add("setip wire: setip is accepted as a resume verb - it would reset the thread selection and never reach its case");
        }
    }
}
