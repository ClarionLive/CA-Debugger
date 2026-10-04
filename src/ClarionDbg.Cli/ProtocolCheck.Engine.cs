using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    // Engine-correctness checks added by wave 3 stream A (ticket f367a04f). See ProtocolCheck.cs for the
    // claim registry and the shared helpers (NewEngine, CaptureConsole) these use.
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The call-entry anchor belongs to the STEPPING thread (f367a04f item 1).
        ///
        /// A silently-resumed breakpoint hit re-anchors <c>_prevVa</c> on the hit address, so the re-arm trap
        /// that follows is not read as a call entry. That is right for the thread that is stepping, and wrong
        /// for every other: StepMachine runs for <c>tid == _stepTid</c> alone, so a tracepoint firing on
        /// thread B has no step to re-anchor, and writing the anchor anyway moved thread A's to an address A
        /// never executed.
        ///
        /// TWO CASES, and the second is not optional. The first (a thread-B hit leaves A's anchor alone) is
        /// the bug. On its own it would also pass against a guard that never lets the write through at all -
        /// `if (false &amp;&amp; ...)` - so the second asserts that a hit on the stepping thread itself STILL
        /// re-anchors.
        /// </summary>
        private static void CheckStepAnchorBelongsToSteppingThread(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a silently-resumed breakpoint hit re-anchors the step's call-entry detector only "
                         + "on the STEPPING thread: a tracepoint on another thread leaves the anchor and the "
                         + "step session untouched, and one on the stepping thread still moves the anchor to "
                         + "the hit address. Not covered: what StepMachine's next trap does with the anchor.");

            // Neither is a multiple of 4, so Windows never assigns them: OpenThread fails, haveCtx stays
            // false, and no thread on this machine is touched (same reasoning as CheckBpHitVsStep).
            const uint stepTid = 0xFFFFFFF1;   // thread A, the one stepping
            const uint otherTid = 0xFFFFFFF5;  // thread B, which hits the tracepoint
            const uint loadBase = 0x00400000;
            const uint va = 0x00401100;        // the tracepoint's address, where both hits arrive
            const uint prevVa = 0x00401000;    // thread A's anchor: its previous trap's EIP
            const uint tempVa = 0x00402000;    // thread A's call-skip temp INT3

            // ---- case 1: THE BUG. Thread B hits a tracepoint while thread A is mid-Step-Over.
            var eng = NewEngine();
            eng.ArmUserBpForTest(loadBase, va, null, null, 0, "other-thread probe");
            eng.ArmStepOverSessionForTest(stepTid, prevVa, tempVa);
            string log = CaptureConsole(() => { eng.OnUserBpForTest(otherTid, va); });

            // CONTROLS: the hit reached the non-pausing path, on thread B.
            if (log.IndexOf("[TRACE] pc001.clw:100: other-thread probe", StringComparison.Ordinal) < 0)
                failures.Add("step-anchor control: the thread-B tracepoint never logged - this case did not "
                             + "reach the silent-resume path: " + log.Replace("\r\n", " | "));
            if (!eng.HasUserBpRearmForTest(otherTid, va))
                failures.Add("step-anchor control: no user-breakpoint re-plant was scheduled for thread B, "
                             + "so the hit did not run as thread B");
            if (!eng.StepInFlightForTest)
                failures.Add("step-anchor control: a thread-B tracepoint cancelled thread A's step, so the "
                             + "anchor assertion below would be about a session that no longer exists");

            if (eng.PrevVaForTest != prevVa)
                failures.Add("step-anchor: a silently-resumed hit on thread B moved thread A's call-entry "
                             + "anchor from 0x" + prevVa.ToString("X") + " to 0x" + eng.PrevVaForTest.ToString("X")
                             + " - A's next trap tests `ret > _prevVa` against an address A never ran, and "
                             + "can read an ordinary instruction as a call entry");

            // ---- case 2: the stepping thread's own hit still re-anchors. Without it a guard that blocks
            // the write for EVERY thread passes case 1.
            var own = NewEngine();
            own.ArmUserBpForTest(loadBase, va, null, null, 0, "own-thread probe");
            own.ArmStepOverSessionForTest(stepTid, prevVa, tempVa);
            string ownLog = CaptureConsole(() => { own.OnUserBpForTest(stepTid, va); });
            if (ownLog.IndexOf("[TRACE] pc001.clw:100: own-thread probe", StringComparison.Ordinal) < 0)
                failures.Add("step-anchor control: the thread-A tracepoint never logged - this case did not "
                             + "reach the silent-resume path: " + ownLog.Replace("\r\n", " | "));
            if (own.PrevVaForTest != va)
                failures.Add("step-anchor: a silently-resumed hit on the STEPPING thread left its anchor at 0x"
                             + own.PrevVaForTest.ToString("X") + " instead of the hit address 0x"
                             + va.ToString("X") + " - the thread guard is blocking the re-anchor it exists "
                             + "to scope, not scoping it");
        }

        /// <summary>
        /// The <c>endLine</c> member of the <c>symbols</c> event (ticket 6fa242ae), over a symbol table the REAL
        /// TswdDebugInfo parser built from <see cref="BuildExtentsBlob"/>, run through the shipped
        /// <see cref="Json.Symbols"/>.
        ///
        /// Two layers. Per symbol, the exact expected value or its ABSENCE, because each fixture symbol pins one
        /// rule:
        /// <list type="bullet">
        /// <item>routines compiled BELOW their procedure still extend it (the real layout, measured on clbrws.exe);</item>
        /// <item>a runtime symbol's code in the gap does not;</item>
        /// <item>another compiland's record does not;</item>
        /// <item>a record on the next procedure's start line does not;</item>
        /// <item>a procedure whose own code is owned by a same-entry alias gets NO extent rather than an earlier
        /// procedure's;</item>
        /// <item>routines, runtime symbols and a procedure with no record carry no member.</item>
        /// </list>
        /// Then, over everything emitted, the property the host relies on: endLine &gt;= line, endLine &lt; the
        /// next procedure's line in the same module, and never a literal 0.
        ///
        /// NOT COVERED: that the fixture is byte-faithful to real compiler output. It holds only the fields the
        /// parser reads on this path. Also not covered: the host's containment lookup, which is Eli's side.
        /// </summary>
        private static void CheckSymbolsEndLine(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the symbols event's endLine, over a PARSED TSWD symbol table: a procedure's extent "
                         + "includes its routines even where they are compiled below it, and excludes runtime-symbol "
                         + "code, other compilands and the next procedure's start line. It is omitted (never 0) for "
                         + "routines, runtime symbols, a procedure with no record, and one whose own records are "
                         + "owned by a same-entry alias. Every emitted endLine is >= its line and < the next "
                         + "procedure's line. A procedure or method with no endLine says \"extent\":\"unknown\" and nothing "
                         + "else does (f1a98318). Not covered: byte-faithfulness to real compiler output, or the host's lookup.");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildExtentsBlob(), 0, 0x1000, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("symbols endLine: the fixture blob did not parse - " + ex.Message); return; }

            // CONTROLS: the parser saw what the fixture meant, or the assertions below are about nothing.
            if (dbg.Symbols.Count != 9)
                failures.Add("symbols endLine control: the parser found " + dbg.Symbols.Count + " symbol(s), expected 9");
            if (dbg.AddrTable.Count != 16)
                failures.Add("symbols endLine control: the parser found " + dbg.AddrTable.Count + " address record(s), expected 16");
            // The alias case rests on ResolveSymbol handing PROCY's code to the alias that shares its entry. That
            // is an ordering detail of the parser's sort, so it is asserted rather than assumed.
            ProcSymbol owner;
            if (!dbg.ResolveSymbol(0x1808, out owner) || owner.Kind != SymbolKind.Other)
                failures.Add("symbols endLine control: PROCY's code resolves to "
                             + (owner == null ? "nothing" : owner.Name + " (" + owner.Kind + ")")
                             + ", not to the runtime alias at its entry - the alias case is not being tested");

            string json = Json.Symbols(dbg.Symbols, dbg);
            var rows = new Dictionary<string, System.Text.RegularExpressions.Match>(StringComparer.Ordinal);
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(json,
                         "\\{\"name\":\"([^\"]+)\"[^{}]*?\"line\":(\\d+)(?:,\"endLine\":(-?\\d+))?[^{}]*\\}"))
                rows[m.Groups[1].Value] = m;
            if (rows.Count != 9)
                failures.Add("symbols endLine control: read " + rows.Count + " symbol row(s) back from the event, expected 9: " + json);

            Action<string, int, int> expect = (name, line, endLine) =>   // endLine 0 = must be ABSENT
            {
                System.Text.RegularExpressions.Match m;
                if (!rows.TryGetValue(name, out m)) { failures.Add("symbols endLine: no row for " + name); return; }
                int gotLine = int.Parse(m.Groups[2].Value);
                if (gotLine != line)
                    failures.Add("symbols endLine control: " + name + " starts at line " + gotLine + ", expected " + line);
                bool has = m.Groups[3].Success;
                if (endLine == 0 && has)
                    failures.Add("symbols endLine: " + name + " carries endLine " + m.Groups[3].Value
                                 + " where the extent is unknown - the member must be absent");
                else if (endLine != 0 && !has)
                    failures.Add("symbols endLine: " + name + " carries no endLine, expected " + endLine);
                else if (endLine != 0 && int.Parse(m.Groups[3].Value) != endLine)
                    failures.Add("symbols endLine: " + name + " ends at line " + m.Groups[3].Value + ", expected " + endLine);
            };
            // PROCA: its routine PREP (18, 20) sits BELOW it in address and still counts. Not the runtime trailer's
            // 25, other.clw's 22, or its own record on line 30, which is PROCB's start.
            expect("PROCA", 10, 20);
            expect("PREP", 18, 0);                // a routine: its procedure's extent covers it
            expect("PROCB", 30, 36);              // its routine B1 (36), also compiled below it
            expect("B1", 36, 0);
            expect("demo$$$__trailer", 25, 0);    // runtime code: never a candidate, never an extent
            expect("PROCD", 50, 55);
            expect("PROCX", 0, 0);                // no line record at all
            expect("PROCY", 60, 0);               // its records belong to the alias: unknown, NOT PROCD's 55
            expect("demo$$$__alias", 60, 0);
            // f1a98318: a procedure or method with no endLine SAYS "extent":"unknown"; nothing else carries it.
            int saidUnknown = 0;
            foreach (var kv in rows)
            {
                string row = kv.Value.Value;
                bool extentKind = row.Contains("\"kind\":\"procedure\"") || row.Contains("\"kind\":\"method\"");
                bool said = row.Contains("\"extent\":\"unknown\"");
                if (said) saidUnknown++;
                if (said != (extentKind && !kv.Value.Groups[3].Success))
                    failures.Add("symbols extent: " + kv.Key + (said ? " says extent unknown but is not an unbounded procedure"
                                                                     : " omits endLine without saying extent unknown"));
            }
            if (saidUnknown != 2)   // PROCX (no record) and PROCY (alias-owned)
                failures.Add("symbols extent control: " + saidUnknown + " row(s) say extent unknown, expected 2 (PROCX, PROCY)");

            // THE PROPERTY, over every row emitted, independent of the per-symbol table above.
            if (json.IndexOf("\"endLine\":0", StringComparison.Ordinal) >= 0 || json.IndexOf("\"endLine\":-", StringComparison.Ordinal) >= 0)
                failures.Add("symbols endLine: the event writes an endLine of 0 or below - unknown must be an ABSENT member");
            // "Next procedure" is per module, and only a procedure or method is one: the host bounds by neither
            // a routine nor a runtime symbol.
            Func<Match, string> moduleOf = m => Regex.Match(m.Value, "\"module\":\"([^\"]*)\"").Groups[1].Value;
            var starts = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in rows.Values)
            {
                int line = int.Parse(m.Groups[2].Value);
                if (line <= 0 || !(m.Value.Contains("\"kind\":\"procedure\"") || m.Value.Contains("\"kind\":\"method\""))) continue;
                List<int> l;
                if (!starts.TryGetValue(moduleOf(m), out l)) { l = new List<int>(); starts[moduleOf(m)] = l; }
                l.Add(line);
            }
            foreach (var l in starts.Values) l.Sort();
            int bounded = 0;
            foreach (var kv in rows)
            {
                var m = kv.Value;
                if (!m.Groups[3].Success) continue;
                int line = int.Parse(m.Groups[2].Value), end = int.Parse(m.Groups[3].Value);
                if (end < line)
                    failures.Add("symbols endLine: " + kv.Key + " ends at " + end + ", before its own start " + line);
                List<int> l;
                if (!starts.TryGetValue(moduleOf(m), out l)) continue;
                foreach (int next in l)
                    if (next > line)
                    {
                        bounded++;
                        if (end >= next)
                            failures.Add("symbols endLine: " + kv.Key + " ends at " + end
                                         + ", inside the next procedure (starting at line " + next + ")");
                        break;
                    }
            }
            // CONTROL for the loop above: PROCA and PROCB each have a next procedure, so at least two
            // endLines were actually compared against one. Zero would mean the property was never tested.
            if (bounded < 2)
                failures.Add("symbols endLine control: only " + bounded + " emitted endLine(s) had a next procedure "
                             + "to be bounded by, expected at least 2 - the overlap property went untested");
        }

        /// <summary>
        /// A minimal TSWD blob for <see cref="CheckSymbolsEndLine"/>: two compilands, a +0x1C address table and
        /// nine text symbols, laid out as TswdDebugInfo reads them. Blob-relative offsets, base 0; text is RVA
        /// 0x1000..0x2000. Only the +0x1C table carries lines (Table A/B are empty), and there is no type stream.
        /// Module 0 is demo.clw; module 1 is other.clw, whose one record sits INSIDE PROCA's address range on a
        /// line inside PROCA's span. Each procedure's routine is placed BELOW it in address, the layout
        /// clbrws.exe shows (2026-09-22).
        /// </summary>
        private static byte[] BuildExtentsBlob()
        {
            const uint Back0 = 0x00C0FFEE, Back1 = 0x00C0FFEF;
            // {rva, line, moduleIdx}, RVA-ascending as the table is.
            var recs = new[]
            {
                new[] { 0x1000u, 18u, 0u }, new[] { 0x1010u, 20u, 0u },                                // routine PREP (PROCA's)
                new[] { 0x1100u, 10u, 0u }, new[] { 0x1108u, 12u, 0u },                                // PROCA
                new[] { 0x1110u, 22u, 1u },                                                             // other.clw
                new[] { 0x1118u, 14u, 0u }, new[] { 0x1120u, 30u, 0u },                                // PROCA; 30 = PROCB's start
                new[] { 0x1200u, 36u, 0u },                                                             // routine B1 (PROCB's)
                new[] { 0x1300u, 30u, 0u }, new[] { 0x1310u, 33u, 0u },                                // PROCB
                new[] { 0x1400u, 25u, 0u },                                                             // runtime trailer, in the gap
                new[] { 0x1500u, 50u, 0u }, new[] { 0x1510u, 55u, 0u },                                // PROCD
                new[] { 0x1700u, 70u, 1u },                                                             // other.clw
                new[] { 0x1808u, 60u, 0u }, new[] { 0x1810u, 62u, 0u },                                // PROCY, owned by the alias
            };
            // {raw name, entry RVA, backref}, in BLOB order. PROCX has no module-0 record in [0x1600, 0x1800).
            // The alias comes AFTER PROCY at the same entry: fewer than 17 symbols sort by insertion sort, which
            // keeps that order, and ResolveSymbol takes the last of equal entries. The control asserts the result.
            var syms = new[]
            {
                Tuple.Create("R$PREP", 0x1000u, Back0), Tuple.Create("PROCA@F", 0x1100u, Back0),
                Tuple.Create("R$B1", 0x1200u, Back0), Tuple.Create("PROCB@F", 0x1300u, Back0),
                Tuple.Create("demo$$$__trailer", 0x1400u, Back0), Tuple.Create("PROCD@F", 0x1500u, Back0),
                Tuple.Create("PROCX@F", 0x1600u, Back0), Tuple.Create("PROCY@F", 0x1800u, Back0),
                Tuple.Create("demo$$$__alias", 0x1800u, Back0),
            };

            var pool = new List<byte> { 0 };                  // leading NUL: every name NUL-preceded
            var nameRef = new Dictionary<string, uint>();
            foreach (var s in syms) { nameRef[s.Item1] = (uint)pool.Count; pool.AddRange(Encoding.ASCII.GetBytes(s.Item1)); pool.Add(0); }
            while (pool.Count % 4 != 0) pool.Add(0);

            const int modArray = 0x40, modPool = 0x48, modRange = 0x60, lines = 0x70;
            int symPool = lines + recs.Length * 8;           // the +0x1C table is [lines, symPool)
            int symNameArray = symPool + pool.Count;
            int symRecs = symNameArray + 8;                   // two backref entries
            int t2c = symRecs + syms.Length * 12;
            int t34 = t2c + 0x40;
            var b = new byte[t34 + 0x40];

            Action<int, uint> u32 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            Action<int, ushort> u16 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            u32(0x00, TswdDebugInfo.TswdMagic);
            u32(0x04, 0x38);
            u32(0x08, modArray); u32(0x0C, modPool); u32(0x10, modRange);
            u32(0x14, lines); u32(0x18, lines); u32(0x1C, lines);
            u32(0x20, (uint)symPool); u32(0x24, 2); u32(0x28, (uint)symNameArray); u32(0x2C, (uint)t2c);
            u32(0x30, (uint)syms.Length); u32(0x34, (uint)t34);

            u32(modArray, 0); u32(modArray + 4, 9);           // two module names
            Encoding.ASCII.GetBytes("demo.clw").CopyTo(b, modPool);
            Encoding.ASCII.GetBytes("other.clw").CopyTo(b, modPool + 9);
            // modRange stays zero: no Table A slices.
            for (int i = 0; i < recs.Length; i++)
            {
                u32(lines + i * 8, recs[i][0]); u16(lines + i * 8 + 4, (ushort)recs[i][1]); u16(lines + i * 8 + 6, (ushort)recs[i][2]);
            }
            pool.ToArray().CopyTo(b, symPool);
            u32(symNameArray, Back0); u32(symNameArray + 4, Back1);   // backref value -> module index 0, 1
            for (int i = 0; i < syms.Length; i++)
            {
                int o = symRecs + i * 12;
                u32(o, nameRef[syms[i].Item1]); u32(o + 4, syms[i].Item2); u32(o + 8, syms[i].Item3);
            }
            return b;
        }

        /// <summary>
        /// A call-skip temp INT3 belongs to the STEPPING thread's skip (65931ddd).
        ///
        /// The temp sits at a return address in shared code, so another thread can execute it while thread A's
        /// Step Over runs to that return. OnTempBp used to decide on the hitting thread's ESP against A's
        /// <c>_skipEntryEsp</c>, so thread B arriving high ended A's skip: the temp was removed,
        /// <c>_skipRunning</c> cleared, and A's anchor and TF went to B. A's step then had nothing to stop it.
        ///
        /// THREE CASES. Case 1 is the bug. Case 2 (A's own return still ends the skip) is what stops a guard
        /// that swallows EVERY hit from passing case 1. Case 3 (A's own deeper, recursive hit still re-arms)
        /// pins that the old `returned` test still runs for the stepping thread.
        /// </summary>
        private static void CheckTempBpBelongsToSteppingThread(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a call-skip temp INT3 hit by a thread OTHER than the stepping one leaves the step session "
                         + "untouched (temp still recorded, skip still running, anchor unmoved) and schedules only "
                         + "that thread's temp re-plant; the stepping thread's own return still ends the skip, and "
                         + "its own deeper hit still re-arms. The two seams refuse an attached engine. Not "
                         + "covered: the race while thread B steps off the restored byte.");

            // Not multiples of 4, so Windows never assigns them (see CheckStepAnchorBelongsToSteppingThread).
            const uint stepTid = 0xFFFFFFF1;
            const uint otherTid = 0xFFFFFFF5;
            const uint prevVa = 0x00401000;
            const uint tempVa = 0x00402000;      // thread A's call-skip return address
            const uint entryEsp = 0x0012F000;    // ESP at the callee's entry; returned = ESP >= this + 4
            const uint highEsp = entryEsp + 4;   // exactly back at the caller's depth
            const uint lowEsp = entryEsp - 0x40; // a deeper (recursive) frame
            const uint frameEbp = 0x0012F100;    // the stepping frame's EBP

            Func<DebugEngine> armed = () =>
            {
                var e = NewEngine();
                e.ArmStepOverSessionForTest(stepTid, prevVa, tempVa);
                e.ArmCallSkipForTest(tempVa, 0, entryEsp + 4, entryEsp, frameEbp, 0);   // an ordinary call
                return e;
            };

            // ---- case 1: THE BUG. Thread B passes A's return address at an ESP that reads as "returned".
            var b = armed();
            string outcome = SeamOutcome(() => b.OnTempBpForTest(otherTid, tempVa, highEsp, frameEbp));
            if (outcome != "returned without refusing")
                failures.Add("temp-bp control: OnTempBpForTest " + (outcome ?? "refused") + " on an engine with no target");
            if (b.TempBpCountForTest != 1)
                failures.Add("temp-bp: a thread-B hit removed thread A's call-skip temp INT3 - A runs to its "
                             + "return with nothing planted there, and its Step Over becomes a Continue");
            if (!b.SkipRunningForTest)
                failures.Add("temp-bp: a thread-B hit cleared thread A's run-to-return (_skipRunning) - B's ESP "
                             + "was compared with A's callee-entry ESP");
            if (!b.StepInFlightForTest)
                failures.Add("temp-bp: a thread-B hit ended thread A's step session");
            if (b.PrevVaForTest != prevVa)
                failures.Add("temp-bp: a thread-B hit moved thread A's call-entry anchor from 0x" + prevVa.ToString("X")
                             + " to 0x" + b.PrevVaForTest.ToString("X"));
            if (!b.HasTempRearmForTest(otherTid, tempVa))
                failures.Add("temp-bp: a thread-B hit scheduled no temp re-plant for thread B - the INT3 stays "
                             + "restored after B steps off it, so A's return is no longer caught");

            // ---- case 2: the stepping thread's own return still ends the skip. No line table, so IsStepStop
            // is false and the handler takes the resume-stepping route, which re-anchors on the return address.
            var a = armed();
            SeamOutcome(() => a.OnTempBpForTest(stepTid, tempVa, highEsp, frameEbp));
            if (a.TempBpCountForTest != 0 || a.SkipRunningForTest || a.PrevVaForTest != tempVa)
                failures.Add("temp-bp: the STEPPING thread's own return did not end its skip (temps "
                             + a.TempBpCountForTest + ", skipRunning " + a.SkipRunningForTest + ", anchor 0x"
                             + a.PrevVaForTest.ToString("X") + ") - the thread guard is swallowing the hit it "
                             + "exists to pass through");

            // ---- case 3: the stepping thread's own DEEPER hit (recursion through the same return address).
            var r = armed();
            SeamOutcome(() => r.OnTempBpForTest(stepTid, tempVa, lowEsp, frameEbp));
            if (r.TempBpCountForTest != 1 || !r.SkipRunningForTest || !r.HasTempRearmForTest(stepTid, tempVa))
                failures.Add("temp-bp: a deeper hit on the stepping thread did not re-arm and run on - the "
                             + "recursion guard no longer applies to the stepping thread");

            // ---- the two new seams refuse an attached engine (CheckSeamsRefuseLiveTarget's six predate them).
            var hProcField = typeof(DebugEngine).GetField("_hProcess",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (hProcField == null) { failures.Add("temp-bp control: DebugEngine._hProcess not found"); return; }
            var att = armed();
            hProcField.SetValue(att, new IntPtr(0x1234));
            string o1 = SeamOutcome(() => att.OnTempBpForTest(otherTid, tempVa, highEsp, frameEbp));
            string o2 = SeamOutcome(() => att.ArmCallSkipForTest(tempVa, 0, entryEsp + 4, entryEsp, frameEbp, 0));
            if (o1 != null) failures.Add("temp-bp seam-guard: OnTempBpForTest " + o1 + " against an ATTACHED engine");
            if (o2 != null) failures.Add("temp-bp seam-guard: ArmCallSkipForTest " + o2 + " against an ATTACHED engine");
        }

        /// <summary>
        /// A procedure record whose name sits at symbol-pool offset 0 still owns its locals (c4910921).
        ///
        /// ReadLocals skipped every +0x2C record with nameRef 0, but offset 0 is the pool's first string, a real
        /// name. Dropping a PROCEDURE record there left the previous procedure current, so the dropped one's
        /// locals were keyed to it (measured 2026-10-03 on fixture samename-w8: OTHERPROC's CNT2 under
        /// SHAREDPROC). THREE CASES over one synthetic blob: (i) a nameRef-0 procedure record that a symbol
        /// confirms (same raw name, same entry) becomes the current procedure; (ii) a nameRef-0 tag-05 record
        /// whose entry matches no symbol does NOT change it, which is what fails a fix without the symbol
        /// cross-check; (iii) a nameRef-0 LOCAL is still dropped, so a stray zero dword cannot invent a local
        /// named after the pool's first string.
        ///
        /// NOT COVERED: that the fixture is byte-faithful to real compiler output (the live samename-w8 suite
        /// runs a real build). It holds only the fields ReadLocals reads.
        /// </summary>
        private static void CheckLocalsOwnerAtPoolOffsetZero(List<string> failures, ClaimLog claims)
        {
            claims.Claim("locals over a PARSED +0x2C tree: a procedure record whose name is at symbol-pool offset 0 "
                         + "owns the locals after it when a symbol has that raw name at that entry; a nameRef-0 record "
                         + "at an entry no symbol has leaves the current procedure alone; a nameRef-0 local is dropped "
                         + "(c4910921). Not covered: byte-faithfulness to real compiler output.");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildPoolZeroLocalsBlob(), 0, 0x1000, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("pool-zero locals: the fixture blob did not parse - " + ex.Message); return; }

            // CONTROL: the symbols the cross-check reads are the ones the fixture meant.
            string syms = string.Join(",", dbg.Symbols.ConvertAll(s => s.RawName + "@0x" + s.EntryRva.ToString("X")));
            if (syms != "PROCA@0x1000,PROCZ@0x1100")
                failures.Add("pool-zero locals control: the parser found symbols [" + syms
                             + "], expected PROCA@0x1000 and PROCZ@0x1100 (named at pool offset 0)");

            var locals = dbg.ReadLocals();
            Func<uint, string> namesAt = entry =>
            {
                List<LocalSym> l;
                return locals.TryGetValue(entry, out l) ? string.Join(",", l.ConvertAll(x => x.Name)) : "(no entry)";
            };
            string all = "";
            foreach (var kv in locals) all += " 0x" + kv.Key.ToString("X") + "=[" + namesAt(kv.Key) + "]";

            // CONTROL: the records around the offset-0 one are read at all.
            if (!namesAt(0x1000).StartsWith("LOCA", StringComparison.Ordinal))
                failures.Add("pool-zero locals control: PROCA's own local LOCA was not read -" + all);
            // (i) PROCZ (pool offset 0) owns LOCZ, and PROCA does not.
            if (namesAt(0x1000) != "LOCA" || !namesAt(0x1100).StartsWith("LOCZ", StringComparison.Ordinal))
                failures.Add("pool-zero locals (i): a procedure record named at pool offset 0 does not own the local "
                             + "after it - LOCZ must be keyed to PROCZ's entry 0x1100, not PROCA's 0x1000 -" + all);
            // (ii) the nameRef-0 record at 0x1180 (no symbol there) leaves PROCZ current: LOCN is PROCZ's too.
            if (locals.ContainsKey(0x1180) || namesAt(0x1100) != "LOCZ,LOCN")
                failures.Add("pool-zero locals (ii): a nameRef-0 record at an entry no symbol has changed the current "
                             + "procedure - LOCN must stay with PROCZ (0x1100) and 0x1180 must not be a key -" + all);
            // (iii) the nameRef-0 LOCAL (its name would read as PROCZ) is dropped everywhere.
            foreach (var kv in locals)
                foreach (var l in kv.Value)
                    if (l.Name == "PROCZ")
                        failures.Add("pool-zero locals (iii): a nameRef-0 local was kept as 'PROCZ' under 0x"
                                     + kv.Key.ToString("X") + " - a local must never take the pool's first string -" + all);
        }

        /// <summary>
        /// The stack walk reads the caller's CALL through our planted INT3s (1d371325).
        ///
        /// CallPrecedes decides whether a candidate return address follows a CALL. It read the code raw, so a
        /// breakpoint on the caller's CALL line (our 0xCC over the E8) made the real caller fail the test: the
        /// EBP chain ended at frame 0 and a watch on the caller's local was out of scope (measured 2026-10-03
        /// on fixture samename-w8). Driven through the REAL BuildStack over a fake image and stack in THIS
        /// process: CALLEE stopped, called from CALLER by `call rel32` at RVA 0x1110, return 0x1115.
        /// FIVE CASES: a user breakpoint over the E8 and a call-skip temp over it each still give CALLER as
        /// frame 1 with its saved EBP; the clean E8 gives the same (the fixture control); an INT3 nobody
        /// planted is NOT a call, so the walk stops at frame 0 (the read restores only our bytes, and the
        /// test is consulted at all); and with no EBP chain, the stack scan still finds CALLER through a
        /// planted E8, as an uncertain frame.
        ///
        /// NOT COVERED: the other CALL encodings (FF /2, 9A), whose byte tests are unchanged; a real debuggee.
        /// </summary>
        private static void CheckStackWalkReadsCallUnderInt3(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the stack walk's CALL-before-return test reads the code with our INT3s restored: a "
                         + "user breakpoint or a call-skip temp over the caller's CALL leaves the caller as frame 1 "
                         + "with its saved EBP, and the stack scan still finds it; an INT3 the engine did not plant "
                         + "is not a CALL (1d371325). Not covered: a real debuggee.");

            IntPtr region = VirtualAlloc(IntPtr.Zero, (UIntPtr)0x4000u, MemReserve | MemCommitFlag, PageReadWriteFlag);
            if (region == IntPtr.Zero) { failures.Add("call-under-INT3 control: could not commit four pages in this process"); return; }
            try
            {
                uint r = unchecked((uint)region.ToInt32());
                TswdDebugInfo dbg;
                try { dbg = new TswdDebugInfo(BuildCallerCalleeBlob(), 0, 0x1000, 0x2000, 0x3000); }
                catch (Exception ex) { failures.Add("call-under-INT3: the fixture blob did not parse - " + ex.Message); return; }

                uint callVa = r + 0x1110, eip = r + 0x1408, esp = r + 0x3000, ebp = r + 0x3100, callerEbp = r + 0x3200;
                // byte opcode at the CALL; plant: 0 none, 1 user breakpoint, 2 call-skip temp. hasChain: EBP set.
                Func<byte, int, bool, List<StackFrame>> walk = (opcode, plant, hasChain) =>
                {
                    var page = new byte[0x4000];
                    for (int i = 0x1000; i < 0x2000; i++) page[i] = 0x90;
                    page[0x1110] = opcode;                           // E8 rel32 (rel 0), return at 0x1115
                    BitConverter.GetBytes(callerEbp).CopyTo(page, 0x3100);   // [ebp]   = caller's saved EBP
                    BitConverter.GetBytes(r + 0x1115).CopyTo(page, 0x3104);  // [ebp+4] = return into CALLER
                    Marshal.Copy(page, 0, region, page.Length);
                    var eng = NewEngine();
                    eng.SetProcessHandleForTest(System.Diagnostics.Process.GetCurrentProcess().Handle);
                    if (plant != 0) eng.PlantForTest(callVa, 0xE8, plant == 2);
                    var m = new LoadedModule { Name = "walk.dll", LoadBase = r, Size = 0x3000, Dbg = dbg };
                    return eng.BuildStackForTest(m, eip, esp, hasChain ? ebp : 0);
                };
                Func<List<StackFrame>, string> show = fs =>
                {
                    var parts = new List<string>();
                    foreach (var f in fs) parts.Add((f.Proc ?? "?") + ":" + f.Line + (f.Uncertain ? "?" : "") + "@ebp0x" + f.Ebp.ToString("X"));
                    return "[" + string.Join(", ", parts) + "]";
                };
                Func<List<StackFrame>, bool, bool> callerIsFrame1 = (fs, scanned) =>
                    fs.Count >= 2 && fs[0].Proc == "CALLEE" && fs[1].Proc == "CALLER" && fs[1].Line == 12
                    && fs[1].Uncertain == scanned && fs[1].Ebp == (scanned ? 0u : callerEbp);

                var clean = walk(0xE8, 0, true);
                if (!callerIsFrame1(clean, false))
                    failures.Add("call-under-INT3 control: with the CALL's own E8 in memory the walk is " + show(clean)
                                 + ", expected CALLEE then CALLER:12 at ebp 0x" + callerEbp.ToString("X") + " - the fixture does not walk");
                var user = walk(0xCC, 1, true);
                if (!callerIsFrame1(user, false))
                    failures.Add("call-under-INT3: a user breakpoint over the caller's CALL ended the walk - " + show(user)
                                 + ", expected CALLER as frame 1 with its saved EBP");
                var temp = walk(0xCC, 2, true);
                if (!callerIsFrame1(temp, false))
                    failures.Add("call-under-INT3: a call-skip temp over the caller's CALL ended the walk - " + show(temp)
                                 + ", expected CALLER as frame 1 with its saved EBP");
                var foreign = walk(0xCC, 0, true);
                if (foreign.Count != 1)
                    failures.Add("call-under-INT3: an INT3 the engine never planted was read as a CALL - " + show(foreign)
                                 + ", expected the walk to stop at frame 0");
                var scan = walk(0xCC, 1, false);
                if (!callerIsFrame1(scan, true))
                    failures.Add("call-under-INT3: with no EBP chain the stack scan missed the caller whose CALL carries "
                                 + "a user breakpoint - " + show(scan) + ", expected CALLER:12 as an uncertain frame 1");
            }
            finally { VirtualFree(region, UIntPtr.Zero, MemRelease); }
        }

        /// <summary>
        /// The disassembly names a call through a stub under our INT3 (1d371325, the audit's second raw read).
        ///
        /// FollowThunk decodes the instruction at a call target that has no symbol, to name what the stub jumps
        /// to. It read the code raw, so a breakpoint on the stub decoded as int3 and the listing lost the
        /// callee's name. Driven through the REAL NameForCodeVa over a stub in THIS process, outside the fake
        /// image: `jmp rel32` to CALLEE. THREE CASES: the clean stub names walk.dll!CALLEE (the control); a
        /// planted user breakpoint over the E9 still names it; an INT3 nobody planted names nothing.
        /// NOT COVERED: the `jmp [slot]` stub form, whose slot read is data, not code.
        /// </summary>
        private static void CheckDisasmThunkNameUnderInt3(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the disassembly's stub-following reads the stub with our INT3s restored: a call target "
                         + "that is a `jmp` stub carrying a user breakpoint still names the callee it jumps to, while "
                         + "an INT3 the engine did not plant names nothing (1d371325). Not covered: a real debuggee.");

            IntPtr region = VirtualAlloc(IntPtr.Zero, (UIntPtr)0x3000u, MemReserve | MemCommitFlag, PageReadWriteFlag);
            if (region == IntPtr.Zero) { failures.Add("thunk-under-INT3 control: could not commit three pages in this process"); return; }
            try
            {
                uint r = unchecked((uint)region.ToInt32());
                TswdDebugInfo dbg;
                try { dbg = new TswdDebugInfo(BuildCallerCalleeBlob(), 0, 0x1000, 0x2000, 0x3000); }
                catch (Exception ex) { failures.Add("thunk-under-INT3: the fixture blob did not parse - " + ex.Message); return; }

                uint stub = r + 0x2800, callee = r + 0x1400;   // the stub sits past the image (Size 0x2000): no symbol
                // plant: 0 none, 1 user breakpoint over the stub's opcode.
                Func<byte, int, string> name = (opcode, plant) =>
                {
                    var page = new byte[0x3000];
                    for (int i = 0x1000; i < 0x2000; i++) page[i] = 0x90;
                    page[0x2800] = opcode;                                                  // E9 rel32 -> CALLEE
                    BitConverter.GetBytes(unchecked(callee - (stub + 5))).CopyTo(page, 0x2801);
                    Marshal.Copy(page, 0, region, page.Length);
                    var eng = NewEngine();
                    eng.SetProcessHandleForTest(System.Diagnostics.Process.GetCurrentProcess().Handle);
                    if (plant != 0) eng.PlantForTest(stub, 0xE9, false);
                    var m = new LoadedModule { Name = "walk.dll", LoadBase = r, Size = 0x2000, Dbg = dbg };
                    return eng.NameForCodeVaForTest(m, stub);
                };

                string clean = name(0xE9, 0);
                if (clean != "walk.dll!CALLEE")
                    failures.Add("thunk-under-INT3 control: the clean stub names " + (clean ?? "nothing")
                                 + ", expected walk.dll!CALLEE - the fixture does not follow");
                string user = name(0xCC, 1);
                if (user != "walk.dll!CALLEE")
                    failures.Add("thunk-under-INT3: a user breakpoint over the stub lost the callee's name - got "
                                 + (user ?? "nothing") + ", expected walk.dll!CALLEE");
                string foreign = name(0xCC, 0);
                if (foreign != null)
                    failures.Add("thunk-under-INT3: an INT3 the engine never planted was followed as a stub - got " + foreign);
            }
            finally { VirtualFree(region, UIntPtr.Zero, MemRelease); }
        }

        /// <summary>
        /// A TSWD blob for <see cref="CheckStackWalkReadsCallUnderInt3"/> and <see cref="CheckDisasmThunkNameUnderInt3"/>: one compiland (walk.clw), five +0x1C line
        /// records and two procedures. CALLER (entry 0x1100) calls at 0x1110 and resumes at 0x1115 (line 12); CALLEE
        /// (entry 0x1400) is where the thread stops. Text is RVA 0x1000..0x2000. No +0x2C tree.
        /// </summary>
        private static byte[] BuildCallerCalleeBlob()
        {
            const uint Back0 = 0x00C0FFEE;
            var recs = new[]   // {rva, line}, RVA-ascending
            {
                new[] { 0x1100u, 10u }, new[] { 0x1110u, 11u }, new[] { 0x1115u, 12u },
                new[] { 0x1400u, 20u }, new[] { 0x1408u, 21u },
            };
            var syms = new[] { Tuple.Create("CALLER@F", 0x1100u), Tuple.Create("CALLEE@F", 0x1400u) };
            var pool = new List<byte> { 0 };
            var nameRef = new Dictionary<string, uint>();
            foreach (var s in syms) { nameRef[s.Item1] = (uint)pool.Count; pool.AddRange(Encoding.ASCII.GetBytes(s.Item1)); pool.Add(0); }
            while (pool.Count % 4 != 0) pool.Add(0);

            const int modArray = 0x40, modPool = 0x48, modRange = 0x60, lines = 0x70;
            int symPool = lines + recs.Length * 8;
            int symNameArray = symPool + pool.Count;
            int symRecs = symNameArray + 4;
            int t2c = symRecs + syms.Length * 12;
            int t34 = t2c + 0x40;
            var b = new byte[t34 + 0x40];

            Action<int, uint> u32 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            Action<int, ushort> u16 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            u32(0x00, TswdDebugInfo.TswdMagic);
            u32(0x04, 0x38);
            u32(0x08, modArray); u32(0x0C, modPool); u32(0x10, modRange);
            u32(0x14, lines); u32(0x18, lines); u32(0x1C, lines);
            u32(0x20, (uint)symPool); u32(0x24, 1); u32(0x28, (uint)symNameArray); u32(0x2C, (uint)t2c);
            u32(0x30, (uint)syms.Length); u32(0x34, (uint)t34);

            u32(modArray, 0);
            Encoding.ASCII.GetBytes("walk.clw").CopyTo(b, modPool);
            for (int i = 0; i < recs.Length; i++)
            {
                u32(lines + i * 8, recs[i][0]); u16(lines + i * 8 + 4, (ushort)recs[i][1]); u16(lines + i * 8 + 6, 0);
            }
            pool.ToArray().CopyTo(b, symPool);
            u32(symNameArray, Back0);
            for (int i = 0; i < syms.Length; i++)
            {
                int o = symRecs + i * 12;
                u32(o, nameRef[syms[i].Item1]); u32(o + 4, syms[i].Item2); u32(o + 8, Back0);
            }
            return b;
        }

        /// <summary>
        /// A minimal TSWD blob for <see cref="CheckLocalsOwnerAtPoolOffsetZero"/>: one compiland, no line records,
        /// two text symbols and a +0x2C tree of seven tag records, laid out as TswdDebugInfo reads them. The symbol
        /// pool starts with PROCZ's name (offset 0, no leading NUL), as a real pool does. Text is RVA 0x1000..0x2000.
        /// </summary>
        private static byte[] BuildPoolZeroLocalsBlob()
        {
            const uint Back0 = 0x00C0FFEE;
            var pool = new List<byte>();
            var nameRef = new Dictionary<string, uint>();
            foreach (var n in new[] { "PROCZ", "PROCA", "LOCA", "LOCZ", "LOCN" })
            {
                nameRef[n] = (uint)pool.Count; pool.AddRange(Encoding.ASCII.GetBytes(n)); pool.Add(0);
            }
            while (pool.Count % 4 != 0) pool.Add(0);
            var syms = new[] { Tuple.Create("PROCZ", 0x1100u), Tuple.Create("PROCA", 0x1000u) };
            // {tag, nameRef, 2nd field}: a .text entry RVA (a procedure) or a negative frame offset (a local).
            var tree = new[]
            {
                Tuple.Create((byte)0x04, nameRef["PROCA"], 0x1000u),
                Tuple.Create((byte)0x04, nameRef["LOCA"], unchecked((uint)-4)),
                Tuple.Create((byte)0x04, 0u, 0x1100u),                  // (i)  PROCZ, named at pool offset 0
                Tuple.Create((byte)0x04, nameRef["LOCZ"], unchecked((uint)-4)),
                Tuple.Create((byte)0x05, 0u, 0x1180u),                  // (ii) offset 0, but no symbol at 0x1180
                Tuple.Create((byte)0x04, nameRef["LOCN"], unchecked((uint)-8)),
                Tuple.Create((byte)0x04, 0u, unchecked((uint)-12)),     // (iii) a nameRef-0 local
            };

            const int modArray = 0x40, modPool = 0x48, modRange = 0x60, lines = 0x70;
            int symPool = lines;                              // no line records
            int symNameArray = symPool + pool.Count;
            int symRecs = symNameArray + 4;                   // one backref entry
            int t2c = symRecs + syms.Length * 12;
            const int recSize = 0x20;
            int t34 = t2c + tree.Length * recSize + 0x20;
            var b = new byte[t34 + 0x40];

            Action<int, uint> u32 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            u32(0x00, TswdDebugInfo.TswdMagic);
            u32(0x04, 0x38);
            u32(0x08, modArray); u32(0x0C, modPool); u32(0x10, modRange);
            u32(0x14, lines); u32(0x18, lines); u32(0x1C, lines);
            u32(0x20, (uint)symPool); u32(0x24, 1); u32(0x28, (uint)symNameArray); u32(0x2C, (uint)t2c);
            u32(0x30, (uint)syms.Length); u32(0x34, (uint)t34);

            u32(modArray, 0);
            Encoding.ASCII.GetBytes("demo.clw").CopyTo(b, modPool);
            pool.ToArray().CopyTo(b, symPool);
            u32(symNameArray, Back0);                         // backref value -> module index 0
            for (int i = 0; i < syms.Length; i++)
            {
                int o = symRecs + i * 12;
                u32(o, nameRef[syms[i].Item1]); u32(o + 4, syms[i].Item2); u32(o + 8, Back0);
            }
            for (int i = 0; i < tree.Length; i++)
            {
                int p = t2c + i * recSize;
                b[p] = tree[i].Item1;                         // typeRef at +1 stays 0
                u32(p + 5, tree[i].Item2);
                u32(p + 9, tree[i].Item3);
                if ((tree[i].Item3 & 0x80000000) != 0)
                {
                    b[p + 18] = 0x11;                         // LONG (the storage byte at +17 stays 0)
                    u32(p + 19, 4);
                }
            }
            return b;
        }
    }
}
