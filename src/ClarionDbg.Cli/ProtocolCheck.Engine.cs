using System;
using System.Collections.Generic;
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
    }
}
