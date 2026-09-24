using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// `ClarionDbg protocolcheck` — asserts the engine/pad wire contract for task 0128a37e. Exit 0 = pass.
    ///
    /// This exists because the rule it guards CANNOT be produced by a live run. Every thread-scoped event
    /// the engine emits today comes from inside the pause loop, where the thread id is always known, so a
    /// harness against a real debuggee can only ever show the happy path. The contract Piper's pad depends
    /// on is about the OTHER case:
    ///
    ///     An unknown thread id is an ABSENT field. Never 0, never -1.
    ///
    /// The pad treats an unstamped reply as UNSCOPED and accepts it, which is correct and safe. A literal 0
    /// or -1 would read as a real thread id, match nothing, and make the pad drop replies it should have
    /// shown — a silently blank panel rather than an error. So "unknown" has exactly one representation,
    /// and this asserts it directly instead of trusting that no future caller introduces a sentinel.
    /// <para>
    /// PARTIAL (wave 3, 2026-09-22): a stream that adds checks writes them in its OWN file,
    /// ProtocolCheck.&lt;Area&gt;.cs, as methods of this class. The only shared edit is one line per check in
    /// the <c>checks</c> array in <c>Run</c>, so parallel streams stop colliding in this file.
    /// </para>
    /// </summary>
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// What the run is allowed to SAY it verified. One claim per check, registered by the check itself.
        ///
        /// The success message used to be a single ~1,400-character eight-clause sentence, assembled by hand
        /// and structurally unrelated to the list of checks below it. Nothing forced a new check to add a
        /// clause or a retired check to drop one, and it showed: the sentence went on advertising "the expand
        /// path is a known gap" for a whole wave after another branch had closed that gap, and the clause was
        /// eventually removed by a human noticing. A success message that overstates coverage is this
        /// project's recurring defect, and that one was the defect in its purest form — a paragraph nobody
        /// re-reads, making claims nothing could falsify.
        ///
        /// So a claim is now DATA, emitted where the work happens. The registry cannot be written from a
        /// parallel list kept alongside the checks — that would be the same defect in a new shape — because
        /// the only thing that adds to it is a check, while it is running.
        /// </summary>
        private sealed class ClaimLog
        {
            private readonly List<string> _claims = new List<string>();
            internal int Count { get { return _claims.Count; } }
            internal IList<string> Lines { get { return _claims; } }

            /// <summary>State what THIS check verified, in the present tense, with any count taken from the
            /// code rather than retyped. It becomes one line of the summary, in check order.</summary>
            internal void Claim(string what) { _claims.Add(what); }
        }

        internal static int Run()
        {
            var failures = new List<string>();
            var claims = new ClaimLog();

            // THE CHECK LIST IS THE INVOCATION LIST. There is no second list of names, counts or clauses to
            // drift out of step with it: adding a line here runs a check AND obliges it to register a claim,
            // deleting one removes both, and the summary is printed from what actually ran.
            var checks = new Action<List<string>, ClaimLog>[]
            {
                CheckSplicedEventShapes,
                CheckHandBuiltTidEmitters,
                CheckTidValuedMembersUnderOtherNames,
                CheckResumeVerbs,
                CheckStepGuards,
                CheckBpHitVsStep,
                CheckSeamsRefuseLiveTarget,
                CheckEditVeto,
                CheckThreadedWriteGuard,
                CheckOnceOnlyDiagnostics,
                CheckWinCapKeyIsIdentityNotPosition,
                CheckRefusalsNeverShowARawTid,
                CheckFieldNameResolvesToFileRecord,
                CheckStepAnchorBelongsToSteppingThread,
                CheckTempBpBelongsToSteppingThread,
                CheckEventLoopStepOver,
                CheckSymbolsEndLine,
                CheckTemplateSpanDiscriminator,
                CheckFileRecordShape,
                CheckDataNameIndexFromParsedBlob,
                CheckEmulationFaultBranches,
                CheckEmulatorImportsPerImage,
                CheckStackWindowRevalidated,
                CheckWatchPathWalker,
                CheckHoverHitTest,
                CheckMemReadIsCleanAndPageSafe,
                CheckVarRowAddrIsNotAnEditGrant,
                CheckRefKindOnEveryRefNode,
                CheckSetIpEventLoopRegions,
                CheckSetIpDecision,
                CheckSetIpWire,
                CheckSetIpCallsBalanced,
                CheckSetIpObserved,
                CheckDetach,
                CheckCommandsNeverStarved,
                CheckDetachHardening,
            };

            foreach (var check in checks)
            {
                int before = claims.Count;
                check(failures, claims);
                int added = claims.Count - before;

                // EXACTLY ONE, checked here so the failure NAMES the method rather than reporting a total
                // that leaves someone counting. A check that claims nothing is the case the old sentence
                // could not express; a check that claims twice is how a claim moves house during a refactor
                // and starts describing the wrong code.
                if (added != 1)
                    failures.Add("claim registry: " + check.Method.Name + " registered " + added
                                 + " claim(s), expected exactly 1 — the summary prints one line per check, "
                                 + "so a check with no claim is a check nobody can see ran");
                for (int k = before; k < claims.Count; k++)
                    if (string.IsNullOrWhiteSpace(claims.Lines[k]))
                        failures.Add("claim registry: " + check.Method.Name + " registered a BLANK claim — "
                                     + "it would print as an empty summary line, which is the 1,400-char "
                                     + "sentence's defect in miniature: it appears, and says nothing");
            }

            // The TOTAL, which is not implied by the per-check assertion above and catches what that one
            // cannot see: a claim registered from Run itself, or anywhere outside a check. Each check would
            // still have added exactly one relative to its own starting count, so only this notices.
            if (claims.Count != checks.Length)
                failures.Add("claim registry: " + claims.Count + " claims from " + checks.Length
                             + " checks — a claim was registered outside a check, so the summary would "
                             + "assert something no check backs");

            foreach (var f in failures) Console.WriteLine("  FAIL  " + f);
            if (failures.Count == 0)
            {
                Console.WriteLine("protocolcheck: " + claims.Count + " checks, all OK.");
                for (int i = 0; i < claims.Count; i++)
                    Console.WriteLine("  " + (i + 1).ToString().PadLeft(2) + ". " + claims.Lines[i]);
                return 0;
            }
            Console.WriteLine($"protocolcheck: {failures.Count} failure(s).");
            return 1;
        }

        /// <summary>
        /// The eight spliced event shapes — every event WithTid stamps whole, rather than by appending a
        /// member. Lifted out of Run so that it, like every other check, owns the claim it makes: the count
        /// in that claim is `shapes.Length`, read off the array beside it instead of retyped into a sentence
        /// somewhere else.
        /// </summary>
        private static void CheckSplicedEventShapes(List<string> failures, ClaimLog claims)
        {
            // The real event shapes the engine emits, one per stamped event in the frozen protocol.
            var shapes = new[]
            {
                "{\"event\":\"paused\",\"reason\":\"breakpoint\",\"module\":\"clbrws026.clw\",\"line\":42,\"regs\":{\"eip\":\"0x4754EB\"}}",
                "{\"event\":\"stack\",\"frames\":[{\"frame\":0,\"proc\":\"MAIN\",\"line\":129}]}",
                "{\"event\":\"regs\",\"regs\":{\"eax\":\"0x0\"}}",
                "{\"event\":\"moduledata\",\"module\":\"clbrws026.clw\",\"items\":[]}",
                "{\"event\":\"framelocals\",\"reqId\":\"9\",\"items\":[]}",
                "{\"event\":\"watch\",\"name\":\"PUB:PUB_NAME\",\"found\":true,\"value\":\"'New Moon Books'\"}",
                "{\"event\":\"libstate\",\"reqId\":\"7\",\"items\":[]}",
                "{\"event\":\"disasm\",\"addr\":\"0x4754EB\",\"tag\":\"\",\"instrs\":[{\"va\":\"0x4754EB\"}]}",
            };

            foreach (var shape in shapes)
            {
                string name = EventNameOf(shape);

                // 1. A known tid is stamped, and the rest of the event survives unchanged.
                string stamped = DebugEngine.WithTidForTest(shape, 116932);
                if (stamped.IndexOf("\"tid\":116932", StringComparison.Ordinal) < 0)
                    failures.Add(name + ": a known tid was not stamped");
                if (stamped.IndexOf(shape.Substring(1), StringComparison.Ordinal) < 0)
                    failures.Add(name + ": stamping altered the rest of the event");
                if (EventNameOf(stamped) != name)
                    failures.Add(name + ": stamping changed the event name to " + EventNameOf(stamped));

                // 2. THE RULE: an unknown tid emits NO tid member at all — not 0, not -1.
                string unknown = DebugEngine.WithTidForTest(shape, 0);
                if (unknown != shape)
                    failures.Add(name + ": tid 0 must leave the event untouched, got " + unknown);
                if (HasTopLevelTid(unknown))
                    failures.Add(name + ": tid 0 emitted a tid member — the pad would read it as a real thread");
            }

            // 3. Sentinels must not appear anywhere, including the -1 an int cast could produce.
            //
            // This check used to search the stamped output for the literal `"tid":-1` — which a uint tid can
            // never produce, so it passed without asserting anything: `(uint)-1` stamps as 4294967295, a
            // number the pad would have read as a real thread. The assertion is now the same one the rest of
            // the file makes, that NO tid member is written at all, and it is made against the value that
            // actually reaches the writer.
            string neg = DebugEngine.WithTidForTest(shapes[0], unchecked((uint)-1));
            if (HasTopLevelTid(neg))
                failures.Add("paused: a -1 sentinel reached the wire as " + unchecked((uint)-1)
                             + " — an unknown tid must be an absent member");
            if (neg != shapes[0])
                failures.Add("paused: a -1 tid must leave the event untouched, got " + neg);

            // 4. A thread-scoped event with no payload is still well-formed JSON when stamped.
            if (DebugEngine.WithTidForTest("{}", 42) != "{\"tid\":42}")
                failures.Add("empty object: stamping produced malformed JSON");

            claims.Claim(shapes.Length + " spliced event shapes: a KNOWN tid is stamped and the rest of the "
                         + "event survives byte-identical, while an unknown tid - 0 or the (uint)-1 an int "
                         + "cast produces - writes no tid member at all; an empty object still stamps as "
                         + "well-formed JSON.");
        }

        /// <summary>
        /// The absent-tid rule, asserted against the FOUR hand-built emitters — the ones WithTid never saw.
        ///
        /// WithTid splices whole events and so was the only tid writer the checks above could reach. The
        /// emitters in DebugEngine.Threads.cs build their JSON by hand, which is why all three recorded
        /// breakages of this rule happened on one of them: `threadselected` carried a second, duplicated copy
        /// of the rule, and `LogPauseChoice` carried none at all and wrote a top-level `"tid":` whatever the
        /// value was — including the 0 that LastResortThread returns when there is no main thread.
        ///
        /// These run the REAL builders through internal seams, not copies of their shapes. A check written
        /// against a hand-written copy asserts only that two hand-written strings agree, which is exactly the
        /// evidence that was missing when this rule was broken three times in one day.
        ///
        /// Each emitter is checked three ways: a known tid IS written (the CONTROL — without it, a builder
        /// that dropped the member entirely would pass the other two for the wrong reason), and both unknown
        /// values (0 and the (uint)-1 that an int cast produces) write no member.
        ///
        /// FOUR is a count that can be checked against the code: threadselected, the pause-choice console
        /// event, the `threads` rows and the `threadscan` rows. If a fifth hand-built emitter appears, this
        /// check does not grow to meet it — add it here, and see the rule holder's note in DebugEngine.cs.
        /// </summary>
        private static void CheckHandBuiltTidEmitters(List<string> failures, ClaimLog claims)
        {
            claims.Claim("all 5 hand-built tid emitters - threadselected, the pause-choice log, the "
                         + "`threads` rows, the `threadscan` rows and `hover` - driven through their REAL builders: a "
                         + "known tid is written exactly once, and neither 0 nor (uint)-1 writes a member.");

            const uint known = 116932;
            const uint minusOne = unchecked((uint)-1);

            // --- 1. threadselected: a top-level tid, so the pad's own extraction rule applies directly.
            string sel = DebugEngine.ThreadSelectedJsonForTest(known, true, null);
            if (!HasTopLevelTid(sel) || sel.IndexOf("\"tid\":116932", StringComparison.Ordinal) < 0)
                failures.Add("threadselected control: a KNOWN tid was not written at all — " + sel);
            foreach (var bad in new[] { 0u, minusOne })
            {
                string r = DebugEngine.ThreadSelectedJsonForTest(bad, false, "unknown or exited thread");
                if (HasTopLevelTid(r))
                    failures.Add("threadselected: tid " + bad + " emitted a tid member — " + r);
                if (r.IndexOf("\"error\":", StringComparison.Ordinal) < 0)
                    failures.Add("threadselected: a refusal with an unknown tid dropped its error text — " + r);
            }

            // --- 2. the pause-choice console event: the emitter that was writing the member unconditionally.
            string pc = DebugEngine.PauseChoiceJsonForTest("pause: thread 116932 chosen by window-z", known);
            if (!HasTopLevelTid(pc))
                failures.Add("pause-choice control: a KNOWN tid was not written at all — " + pc);
            foreach (var bad in new[] { 0u, minusOne })
            {
                // tid 0 is REACHABLE here: LastResortThread returns _mainTid, else breakTid, else 0.
                string r = DebugEngine.PauseChoiceJsonForTest("pause: thread 0 chosen by main", bad);
                if (HasTopLevelTid(r))
                    failures.Add("pause-choice: tid " + bad + " emitted a tid member — the pad would read it "
                                 + "as a real thread: " + r);
                if (r.IndexOf("\"text\":", StringComparison.Ordinal) < 0)
                    failures.Add("pause-choice: the log text was lost when the tid was absent — " + r);
            }

            // --- 3+4. threads rows and threadscan rows: PER-ROW tids, one nesting level down.
            //     HasTopLevelTid deliberately ignores those (a row's tid is not the event's own), so they are
            //     checked by counting the member instead — which is also how a sentinel would show up.
            string rows = DebugEngine.ThreadsJsonForTest(known, known, new[] { known, 0u, minusOne });
            CheckNoSentinelRows(failures, "threads", rows, known);
            string scan = DebugEngine.ThreadScanJsonForTest(known, new[] { known, 0u, minusOne });
            CheckNoSentinelRows(failures, "threadscan", scan, known);

            // --- 5. hover (f6e547ce): a top-level tid naming the thread under the cursor; none is ABSENT.
            string hv = DebugEngine.HoverJsonForTest(true, true, known);
            if (!HasTopLevelTid(hv) || hv.IndexOf("\"tid\":116932", StringComparison.Ordinal) < 0)
                failures.Add("hover control: a KNOWN tid was not written at all — " + hv);
            foreach (var bad in new[] { 0u, minusOne })
            {
                string r = DebugEngine.HoverJsonForTest(true, false, bad);
                if (HasTopLevelTid(r))
                    failures.Add("hover: tid " + bad + " emitted a tid member — the page would name a thread "
                                 + "under a cursor that is over none: " + r);
            }
        }

        /// <summary>
        /// The same rule for thread ids that are NOT called "tid" — ticket 3b043dfc, hole 1.
        ///
        /// `threads` writes a top-level "stopped" and "selected"; `threadscan` writes a top-level "stopped".
        /// All three are thread ids and none of them went through the writer, because the guard that existed
        /// was written around the NAME. They were safe only by ordering — PausedWait sets _selectedTid
        /// before the pause loop can dispatch — while AcquireView already treats _selectedTid == 0 as a
        /// state that happens. The engine disagreed with itself; that, not an observed failure, is the bug.
        ///
        /// THREE members over TWO events, and both numbers are checkable against DebugEngine's declared
        /// TidValuedMemberNames, which this reads rather than retypes.
        ///
        /// Each is checked the same three ways the "tid" emitters are — the known CONTROL first, because
        /// without it a builder that dropped the member entirely would pass the two absence cases for the
        /// wrong reason — and then INDEPENDENTLY, one unknown at a time with the other known. A pair tested
        /// only together cannot tell "the rule is applied per member" from "the builder gave up on both".
        /// </summary>
        private static void CheckTidValuedMembersUnderOtherNames(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the same rule holds under all "
                         + DebugEngine.TidValuedMemberNamesForTest().Length + " names the engine declares "
                         + "for a thread-id member, putting 3 more top-level ids across 2 events under it "
                         + "(`threads`.stopped, `threads`.selected, `threadscan`.stopped) - each tested with "
                         + "the OTHERS KNOWN, so an omission is per member rather than the builder giving "
                         + "up, while the same-named per-row booleans survive and no row claims a selection "
                         + "the event does not state.");

            const uint known = 116932;
            const uint other = 4812;
            const uint minusOne = unchecked((uint)-1);
            var unknowns = new[] { 0u, minusOne };

            // The declared set is the engine's, read back — so "three" below cannot drift from the code.
            string[] declared = DebugEngine.TidValuedMemberNamesForTest();
            if (declared.Length != 3)
                failures.Add("tid-valued names: this check covers 3 declared names but the engine declares "
                             + declared.Length + " (" + string.Join(", ", declared) + ") — a name was added "
                             + "without a check to hold it");
            foreach (var n in new[] { "tid", "stopped", "selected" })
                if (Array.IndexOf(declared, n) < 0)
                    failures.Add("tid-valued names: the engine no longer declares \"" + n + "\"");

            // The writer validates the name instead of trusting it. Falsifiable, and this is what falsifies
            // it: a name outside the set must be refused, and every declared name must be accepted.
            foreach (var n in declared)
            {
                string w = DebugEngine.AppendTidValuedMemberForTest("{\"event\":\"x\"}", n, known);
                if (w.IndexOf("\"" + n + "\":116932", StringComparison.Ordinal) < 0)
                    failures.Add("tid writer: the declared name \"" + n + "\" was not written — " + w);
                foreach (var bad in unknowns)
                    if (DebugEngine.AppendTidValuedMemberForTest("{\"event\":\"x\"}", n, bad)
                        != "{\"event\":\"x\"}")
                        failures.Add("tid writer: \"" + n + "\" with an unknown id " + bad + " changed the "
                                     + "event — an unknown id must write nothing at all");
            }
            try
            {
                DebugEngine.AppendTidValuedMemberForTest("{\"event\":\"x\"}", "clarionThread", known);
                failures.Add("tid writer: it accepted \"clarionThread\", a name outside the declared set — "
                             + "the set is documentation, not a check");
            }
            catch (ArgumentException) { }

            // --- the `threads` event: "stopped" and "selected", each unknown on its own.
            string bothKnown = DebugEngine.ThreadsJsonForTest(known, other, new[] { known, other });
            foreach (var m in new[] { "stopped", "selected" })
                if (!HasTopLevelMember(bothKnown, m))
                    failures.Add("threads control: a KNOWN top-level \"" + m + "\" was not written — "
                                 + bothKnown);
            if (bothKnown.IndexOf("\"stopped\":116932", StringComparison.Ordinal) < 0
                || bothKnown.IndexOf("\"selected\":4812", StringComparison.Ordinal) < 0)
                failures.Add("threads control: the two top-level ids were not the ones it was given — "
                             + bothKnown);

            foreach (var bad in unknowns)
            {
                string s = DebugEngine.ThreadsJsonForTest(bad, other, new[] { other });
                if (HasTopLevelMember(s, "stopped"))
                    failures.Add("threads: an unknown stopped tid (" + bad + ") was written as a top-level "
                                 + "\"stopped\" — the pad would read it as the thread execution halted on: " + s);
                if (!HasTopLevelMember(s, "selected"))
                    failures.Add("threads: dropping an unknown \"stopped\" also dropped the KNOWN "
                                 + "\"selected\" — the rule is per member, not per event: " + s);

                string t = DebugEngine.ThreadsJsonForTest(known, bad, new[] { known });
                if (HasTopLevelMember(t, "selected"))
                    failures.Add("threads: an unknown selected tid (" + bad + ") was written as a top-level "
                                 + "\"selected\" — the pad would show a thread nobody selected: " + t);
                if (!HasTopLevelMember(t, "stopped"))
                    failures.Add("threads: dropping an unknown \"selected\" also dropped the KNOWN "
                                 + "\"stopped\": " + t);

                // With no selection, no ROW may claim to be the selected one. A row's "selected" is a
                // boolean derived from the same id, so an unguarded `p.Tid == selectedTid` would mark a row
                // with a 0 tid as selected — the sentinel defect again, one level down.
                string u = DebugEngine.ThreadsJsonForTest(known, bad, new[] { known, bad });
                if (Count(u, "\"selected\":true") != 0)
                    failures.Add("threads: a row marked itself selected while the event states no "
                                 + "selection (" + bad + ") — " + u);

                // And the event must still be a well-formed object with its list intact.
                if (!s.StartsWith("{\"event\":\"threads\"", StringComparison.Ordinal)
                    || s.IndexOf(",\"threads\":[", StringComparison.Ordinal) < 0
                    || !s.EndsWith("]}", StringComparison.Ordinal))
                    failures.Add("threads: omitting a top-level id left the event malformed — " + s);
            }

            // CONTROL for the row check above: a KNOWN selection must still mark exactly one row.
            string sel = DebugEngine.ThreadsJsonForTest(known, other, new[] { known, other });
            if (Count(sel, "\"selected\":true") != 1)
                failures.Add("threads control: a known selection marked "
                             + Count(sel, "\"selected\":true") + " rows, expected exactly 1 — " + sel);

            // --- the `threadscan` event: one top-level "stopped", same rule.
            string scanKnown = DebugEngine.ThreadScanJsonForTest(known, new[] { known });
            if (!HasTopLevelMember(scanKnown, "stopped")
                || scanKnown.IndexOf("\"stopped\":116932", StringComparison.Ordinal) < 0)
                failures.Add("threadscan control: a KNOWN top-level \"stopped\" was not written — " + scanKnown);
            foreach (var bad in unknowns)
            {
                string s = DebugEngine.ThreadScanJsonForTest(bad, new[] { known });
                if (HasTopLevelMember(s, "stopped"))
                    failures.Add("threadscan: an unknown stopped tid (" + bad + ") was written as a "
                                 + "top-level \"stopped\" — " + s);
                if (!s.StartsWith("{\"event\":\"threadscan\"", StringComparison.Ordinal)
                    || s.IndexOf(",\"threads\":[", StringComparison.Ordinal) < 0
                    || !s.EndsWith("]}", StringComparison.Ordinal))
                    failures.Add("threadscan: omitting the top-level id left the event malformed — " + s);
                // The per-row "stopped" is a BOOLEAN and must survive: dropping a top-level id must not
                // take the row flag with it, and the two are told apart by nesting, not by name.
                if (Count(s, "\"stopped\":true") + Count(s, "\"stopped\":false") == 0)
                    failures.Add("threadscan: the per-row boolean \"stopped\" disappeared along with the "
                                 + "top-level id — they share a name and nothing else: " + s);
            }
        }

        /// <summary>
        /// The resume-verb set has ONE owner, and IsResumeVerb is it.
        ///
        /// The set used to exist in THREE hand-maintained copies: IsResumeVerb, the pause-loop switch, and
        /// the running-state switch (the pad held a fourth until a9f3407 removed it). Adding a verb to one
        /// left the others stale, and the recorded symptom was silent — the pad sat under a stale "viewing
        /// thread N" banner because a verb nobody had told the other list about did not reset the selection.
        ///
        /// TWO sites remain and that number is checkable against the code: IsResumeVerb, which OWNS the set,
        /// and the pause-loop switch, whose case labels must dispatch to a handler and so cannot be a list.
        /// The running-state switch no longer holds a copy — it asks IsResumeVerb. "Every resume site" would
        /// pass silently when a third copy appeared; "two sites" does not.
        ///
        /// The REJECTIONS below are not padding. IsResumeVerb is now consulted ahead of the running-state
        /// switch, so a verb it wrongly accepts is diverted and never reaches its own case. pause/break is
        /// the dangerous one: that switch implements it, and it once WAS in this list, where it reset the
        /// selection and then fell through to "unknown command".
        /// </summary>
        private static void CheckResumeVerbs(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the resume-verb set has ONE owner across its 2 remaining sites: all 18 spellings "
                         + "the pause loop dispatches are accepted, and the verbs the running-state switch "
                         + "implements itself are refused, so none of them is diverted from its own case.");

            // The set, spelled out: 5 commands, 18 spellings. The pause loop dispatches every one of these.
            string[] resume =
            {
                "continue", "c", "g",
                "step", "stepinto", "s", "i",
                "stepover", "next", "n",
                "stepout", "out", "finish", "o",
                "stepi", "si", "nexti", "ni",
            };
            if (resume.Length != 18)
                failures.Add("resume verbs: this check claims 18 spellings but lists " + resume.Length);
            foreach (var v in resume)
                if (!DebugEngine.IsResumeVerbForTest(v))
                    failures.Add("resume verbs: '" + v + "' is dispatched by the pause loop as a resume verb "
                                 + "but IsResumeVerb rejects it — it will not reset the thread selection, and "
                                 + "the pad keeps a stale 'viewing thread N' banner");

            // Verbs the RUNNING-STATE switch implements itself. IsResumeVerb is consulted before that switch,
            // so accepting any of these would divert it from the case that handles it.
            string[] handledWhileRunning = { "pause", "break", "bp", "sym", "thread", "hover", "quit", "q", "kill" };
            foreach (var v in handledWhileRunning)
                if (DebugEngine.IsResumeVerbForTest(v))
                    failures.Add("resume verbs: '" + v + "' is handled by the running-state switch, but "
                                 + "IsResumeVerb accepts it — it would be diverted and never reach its case");

            // Verbs that are paused-only but NOT resume verbs: they must still fall to the switch's own
            // "only valid while paused" case, not the hoisted one. Same error text today, but they are a
            // different set and must not be absorbed into this one.
            string[] pausedOnlyReads = { "mem", "regs", "stack", "watch", "locals", "moduledata", "disasm",
                                         "setval", "threads", "threadscan", "framelocals", "libstate", "expand",
                                         "setip" };
            foreach (var v in pausedOnlyReads)
                if (DebugEngine.IsResumeVerbForTest(v))
                    failures.Add("resume verbs: the read verb '" + v + "' is not a resume verb, but "
                                 + "IsResumeVerb accepts it — it would reset the thread selection");

            // And an unknown verb must still reach `default` rather than be swallowed as a resume.
            if (DebugEngine.IsResumeVerbForTest("runtocursor") || DebugEngine.IsResumeVerbForTest("frobnicate"))
                failures.Add("resume verbs: an unimplemented verb was accepted — it would reset the selection "
                             + "and then report 'unknown command', silently discarding the user's thread <tid>");
        }

        /// <summary>
        /// The three Step Over guards from ticket f83d5eec, each isolated with the others intact.
        ///
        /// These are impractical to produce against a live debuggee — not impossible, and the difference is
        /// worth stating in a file whose job is keeping claims honest. A Step Over reaches the ESP gate only
        /// on StepMachine's documented "couldn't plant — fall through and keep instruction-stepping" path,
        /// which needs a return address the debugger cannot write a byte to; that is reachable in principle
        /// (a read-only or guarded page at a return site) and simply does not arise in a normal run.
        ///
        /// Isolation is the point, not coverage. A guard that is only ever exercised alongside another guard
        /// covering the same case is a DEAD guard whose test still passes — this repo shipped exactly that
        /// (armPendingSweep's `!isPaused` clause, dead to its test because a real resume also bumped the
        /// switch generation). So each case below moves ONE input and leaves the rest where a real step
        /// would have them.
        /// </summary>
        private static void CheckStepGuards(List<string> failures, ClaimLog claims)
        {
            claims.Claim("Step Over's ESP gate and its prologue bypass each hold with the OTHER one out of "
                         + "the way, so neither is a dead guard passing on the other's behalf.");

            // ---- guard 1: THE ESP GATE, isolated from the bypass (bypass OFF, everything else real).
            // A candidate 0x40 below the starting frame is deeper than ESP_SLACK (0x10) allows.
            const uint startEsp = 0x0012F000;
            if (DebugEngine.PassesEspGateForTest(false, startEsp - 0x40, startEsp))
                failures.Add("esp gate: a stop 0x40 deeper than the step start passed the gate with the "
                             + "prologue bypass OFF — Step Over would stop inside the callee");
            // CONTROL: the gate must still admit a legitimate stop, or Step Over stops nowhere at all.
            if (!DebugEngine.PassesEspGateForTest(false, startEsp, startEsp))
                failures.Add("esp gate control: a stop at the starting frame depth was refused");
            if (!DebugEngine.PassesEspGateForTest(false, startEsp - 0x10, startEsp))
                failures.Add("esp gate control: a stop exactly ESP_SLACK deep was refused — the slack exists "
                             + "because a single ENTER opcode can reserve the frame in one instruction");

            // ---- guard 2: THE BYPASS, isolated from the gate (gate FAILING, so only the bypass can pass).
            // This is the prologue case the bypass exists for: ESP has legitimately dropped past the slack
            // because the procedure's own `sub esp,N` ran, and the stop is still in that same procedure.
            if (!DebugEngine.PassesEspGateForTest(true, startEsp - 0x40, startEsp))
                failures.Add("prologue bypass: a stop in the starting procedure's own frame was refused — "
                             + "the prologue's `sub esp,N` drops ESP before any nested call happens");

            // ---- guard 3: THE PROCEDURE BOUND on the bypass.
            // The bypass is armed by _startAtProcEntry AND the candidate resolving to the same symbol. The
            // defect being guarded was the first half alone: armed once in BeginStep, never cleared, so the
            // gate was skipped for every stop in the session INCLUDING one in a different procedure. That
            // conjunction lives in PrologueBypassApplies, which needs a live module to resolve a symbol; what
            // IS assertable here is that a false bypass leaves the gate in charge — which is case 1 above,
            // and is what a different-procedure candidate produces. Stated so the claim is not overread:
            // this file asserts the CONSEQUENCE of the bound, not the symbol comparison itself.

            // ---- guard 4: THE PROLOGUE PREDICATE — "below the procedure's own first line record".
            // A record table for one procedure at 0x1000 whose first own statement is at 0x1040, with the
            // next procedure at 0x2000. The old test (rva - entry <= 0x100) called everything up to 0x1100
            // "at entry"; the new one stops at 0x1040.
            var table = new List<AddrRec>
            {
                new AddrRec(0x0800, 10, 0),   // the PREVIOUS procedure's records
                new AddrRec(0x0900, 11, 0),
                new AddrRec(0x1040, 20, 1),   // this procedure's first own statement
                new AddrRec(0x1080, 21, 1),
                new AddrRec(0x2010, 30, 2),   // the NEXT procedure's
            };
            uint first = DebugEngine.FirstRecordRvaInProc(table, 0x1000, 0x2000);
            if (first != 0x1040)
                failures.Add("prologue predicate: the procedure's first own record resolved to 0x"
                             + first.ToString("X") + ", expected 0x1040 — a record BELOW the entry belongs "
                             + "to the previous procedure");

            // THE CASE THE OLD PROLOGUE_WINDOW TEST GOT WRONG: 0x1080 is 0x80 into the procedure, inside a
            // 0x100 window, but it is a real statement of the BODY. It must not read as prologue. Asserted
            // through the predicate the engine actually uses, not re-derived from `first` — a check that
            // only restates a value another check already pinned is a dead check that always passes.
            if (DebugEngine.IsPrologueRva(0x1080, first))
                failures.Add("prologue predicate: 0x1080 is a statement of the procedure body but still "
                             + "counted as prologue — this is the 256-byte hole PROLOGUE_WINDOW left open");
            // CONTROL: an address genuinely in the prologue still is one, or the fix broke what it fixed.
            if (!DebugEngine.IsPrologueRva(0x1008, first))
                failures.Add("prologue predicate control: 0x1008 sits below the procedure's first statement "
                             + "and must still count as prologue");
            // A procedure with no first record of its own is never "in the prologue", whatever the RVA.
            if (DebugEngine.IsPrologueRva(0x1008, 0))
                failures.Add("prologue predicate: a procedure with no line record of its own still armed "
                             + "the bypass — there is nothing to measure against, so the ESP gate must hold");

            // A procedure with NO line record of its own gets NO bypass: 0x2010 belongs to the next
            // procedure, so there is nothing to measure against and the safe answer is the ESP gate.
            uint none = DebugEngine.FirstRecordRvaInProc(table, 0x1800, 0x2000);
            if (none != 0)
                failures.Add("prologue predicate: a procedure with no record of its own claimed 0x"
                             + none.ToString("X") + " — that record is the NEXT procedure's");
            // ... and with no following symbol, the same record IS this procedure's. Without this control
            // the check above would pass for a builder that always returned 0.
            if (DebugEngine.FirstRecordRvaInProc(table, 0x1800, 0) != 0x2010)
                failures.Add("prologue predicate control: with no following symbol, the last record belongs "
                             + "to the procedure that precedes it");

            // ---- guard 5: CancelStep CLEARS the bypass. It was set once in BeginStep and never cleared,
            // so it survived into the next step session. Asserted directly: arm it, cancel, read it back.
            var eng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            eng.ArmPrologueBypassForTest(0x1000);
            if (!eng.PrologueBypassArmedForTest)
                failures.Add("cancel-step control: the bypass could not be armed, so the reset below "
                             + "asserts nothing");
            eng.CancelStepForTest();
            if (eng.PrologueBypassArmedForTest)
                failures.Add("cancel-step: the prologue bypass survived CancelStep — the next step session "
                             + "starts with its ESP gate already disabled");
            if (eng.PrologueBypassEntryRvaForTest != 0)
                failures.Add("cancel-step: the bypass flag cleared but its procedure bound did not, leaving "
                             + "the next session bounded to a procedure it never started in");
        }

        /// <summary>
        /// A breakpoint hit that does NOT pause leaves an in-flight step exactly as it was; a hit that DOES
        /// pause supersedes it.
        ///
        /// OnUserBp used to call CancelStep unconditionally, BEFORE the advanced-breakpoint gate decided
        /// whether the hit pauses at all. On the silent-resume path that left <c>_mode = StepMode.None</c>,
        /// every call-skip temp INT3 restored and the temp re-arms dropped — so on the next trap
        /// OnSingleStep's step-2 guard (<c>_mode != StepMode.None</c>) was false, StepMachine never ran, and
        /// nothing stopped the target. The user's Step Over silently became a Continue while the pad still
        /// showed Running.
        ///
        /// 465a3873 is what made it common rather than theoretical: a condition over THREADed data used to
        /// return indeterminate and PAUSE, so the silent-resume path was nearly unreachable; it now evaluates
        /// and false is an ordinary answer.
        ///
        /// Each case moves ONE thing and leaves the rest where a real step would have them. The silent-resume
        /// case asserts its three consequences separately — the session, the temp bytes and the call-entry
        /// anchor are three different repairs, and a half-applied fix must name which half is missing. The
        /// two PAUSING cases exist because CancelStep has to be reachable from BOTH pausing routes: a plain
        /// breakpoint that never enters the gate, and an advanced one whose gate said pause. A fix that
        /// handled only one of those would pass the other's case.
        /// </summary>
        private static void CheckBpHitVsStep(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a breakpoint hit supersedes an in-flight step only when it PAUSES: both pausing "
                         + "routes cancel the step, and a silently-resumed hit leaves the step session, its "
                         + "temp INT3s and its call-entry anchor untouched.");

            // Not a multiple of 4, so Windows never assigns it: OpenThread fails, haveCtx stays false, and
            // no thread on this machine is touched. Everything asserted below is engine bookkeeping.
            const uint tid = 0xFFFFFFF1;
            const uint loadBase = 0x00400000;
            const uint va = 0x00401100;   // where the breakpoint is planted, and where the hit arrives
            const uint prevVa = 0x00401000;   // the previous trap's EIP, the call-entry detector's anchor
            const uint tempVa = 0x00402000;   // the step's one call-skip temp INT3

            // ---- case 1: THE RULE. A hit-count rule that is not yet satisfied resumes SILENTLY.
            var eng = NewEngine();
            var bp = eng.ArmUserBpForTest(loadBase, va, null, "eq", 99, null);
            eng.ArmStepOverSessionForTest(tid, prevVa, tempVa);
            uint rc = 0;
            string log = CaptureConsole(() => { rc = eng.OnUserBpForTest(tid, va); });

            // CONTROLS first: without these the case could pass because nothing ran at all.
            if (bp.HitCount != 1)
                failures.Add("bp-hit control: the hit-count gate never ran (HitCount " + bp.HitCount
                             + ", expected 1) — this case did not reach the silent-resume path, so its "
                             + "assertions prove nothing");
            if (log.IndexOf("*** BREAKPOINT HIT ***", StringComparison.Ordinal) >= 0)
                failures.Add("bp-hit control: an unmet hit-count rule reported a breakpoint hit — it must "
                             + "resume silently");
            if (rc != Native.DBG_CONTINUE)
                failures.Add("bp-hit control: the silent-resume path returned 0x" + rc.ToString("X")
                             + ", not DBG_CONTINUE");

            if (!eng.StepInFlightForTest)
                failures.Add("bp-hit: a hit that resumed SILENTLY cancelled the in-flight step — "
                             + "OnSingleStep's `_mode != StepMode.None` guard is now false, StepMachine "
                             + "never runs, and the user's Step Over has become a Continue");
            if (eng.TempBpCountForTest != 1)
                failures.Add("bp-hit: a silently-resumed hit restored the step's call-skip temp INT3 ("
                             + eng.TempBpCountForTest + " left, expected 1) — the skipped call's return "
                             + "address is no longer covered, so the step has nothing left to stop on");
            if (eng.PrevVaForTest != va)
                failures.Add("bp-hit: a silently-resumed hit left the call-entry anchor at 0x"
                             + eng.PrevVaForTest.ToString("X") + " instead of the hit address 0x"
                             + va.ToString("X") + " — StepMachine's `ret > _prevVa && ret - _prevVa <= "
                             + "CALL_WINDOW` test can read the re-arm trap as a call entry and plant a temp "
                             + "INT3 at a bogus return address");
            if (!eng.HasUserBpRearmForTest(tid, va))
                failures.Add("bp-hit: the user-breakpoint re-plant for this thread was lost on the "
                             + "silent-resume path — the breakpoint stops firing after its first hit");

            // ---- case 2: PAUSING ROUTE A — a plain breakpoint, which never enters the gate at all.
            var plain = NewEngine();
            plain.ArmUserBpForTest(loadBase, va, null, null, 0, null);
            plain.ArmStepOverSessionForTest(tid, prevVa, tempVa);
            string plainLog = CaptureConsole(() => { plain.OnUserBpForTest(tid, va); });
            if (plainLog.IndexOf("*** BREAKPOINT HIT ***", StringComparison.Ordinal) < 0)
                failures.Add("bp-hit control: a plain breakpoint did not report a hit, so this case never "
                             + "reached the pausing route it is asserting about");
            if (plain.StepInFlightForTest)
                failures.Add("bp-hit: a PLAIN breakpoint hit pauses, and a pausing hit must supersede the "
                             + "in-flight step — the session survived, so the next trap drives StepMachine "
                             + "while the user is stopped at a breakpoint");
            if (plain.TempBpCountForTest != 0)
                failures.Add("bp-hit: a plain breakpoint hit left " + plain.TempBpCountForTest
                             + " call-skip temp INT3(s) planted in the target");
            if (!plain.HasUserBpRearmForTest(tid, va))
                failures.Add("bp-hit: cancelling the step on a plain hit also dropped the user-breakpoint "
                             + "re-plant — it is IsTemp=false and CancelStep must leave it alone");

            // ---- case 3: PAUSING ROUTE B — an advanced breakpoint whose gate SAID pause. A fix that moved
            // CancelStep into the plain-breakpoint branch only would pass case 2 and fail here.
            var gated = NewEngine();
            var gbp = gated.ArmUserBpForTest(loadBase, va, null, "eq", 1, null);   // first hit satisfies =1
            gated.ArmStepOverSessionForTest(tid, prevVa, tempVa);
            string gatedLog = CaptureConsole(() => { gated.OnUserBpForTest(tid, va); });
            if (gbp.HitCount != 1 || gatedLog.IndexOf("*** BREAKPOINT HIT ***", StringComparison.Ordinal) < 0)
                failures.Add("bp-hit control: a hit-count rule of =1 did not pause on its first hit "
                             + "(HitCount " + gbp.HitCount + ") — this case is not testing the gated "
                             + "pausing route");
            if (gated.StepInFlightForTest)
                failures.Add("bp-hit: an ADVANCED breakpoint whose gate said PAUSE did not supersede the "
                             + "in-flight step — CancelStep is reachable from the plain route only");
            if (gated.TempBpCountForTest != 0)
                failures.Add("bp-hit: a gated pausing hit left " + gated.TempBpCountForTest
                             + " call-skip temp INT3(s) planted in the target");

            // ---- case 4: the TRACEPOINT, which is what the pipeline actually reported. A tracepoint NEVER
            // pauses, and it LOGS, so the log itself proves the non-pausing path was taken rather than the
            // breakpoint simply not matching. The message carries no {token}, so nothing is read from a
            // target that is not there.
            var trace = NewEngine();
            trace.ArmUserBpForTest(loadBase, va, null, null, 0, "step-in-flight probe");
            trace.ArmStepOverSessionForTest(tid, prevVa, tempVa);
            string traceLog = CaptureConsole(() => { trace.OnUserBpForTest(tid, va); });
            if (traceLog.IndexOf("[TRACE] pc001.clw:100: step-in-flight probe", StringComparison.Ordinal) < 0)
                failures.Add("bp-hit control: the tracepoint never logged — this case did not reach the "
                             + "non-pausing path: " + traceLog.Replace("\r\n", " | "));
            if (traceLog.IndexOf("*** BREAKPOINT HIT ***", StringComparison.Ordinal) >= 0)
                failures.Add("bp-hit control: a tracepoint reported a breakpoint hit — a tracepoint logs "
                             + "and resumes, it never pauses");
            if (!trace.StepInFlightForTest)
                failures.Add("bp-hit: a TRACEPOINT hit cancelled the in-flight step — a tracepoint never "
                             + "pauses, so it must never supersede a step");
            if (trace.PrevVaForTest != va)
                failures.Add("bp-hit: a tracepoint hit left the call-entry anchor at 0x"
                             + trace.PrevVaForTest.ToString("X") + " instead of 0x" + va.ToString("X"));
        }

        /// <summary>
        /// The mutating test seams must be safe by CONSTRUCTION, not by convention.
        ///
        /// OnUserBpForTest drives the REAL hit handler, whose body can SetThreadContext, WriteProcessMemory,
        /// block in PausedWait reading stdin, and on the --once arm TerminateProcess the target. Its safety
        /// used to rest entirely on three CALLER choices — a tid Windows never assigns, once:false,
        /// interactive:false — documented in comments at the one call site and enforced nowhere. A rule held
        /// by the caller is a convention (ticket a39d9477); the seam is the writer, so the refusal lives
        /// there and this asserts it from outside.
        ///
        /// Each arm is checked on its OWN engine so one refusal cannot be the reason the next one throws,
        /// and the no-target ISOLATION case below is what keeps "refuses when attached" distinguishable from
        /// "refuses always".
        /// </summary>
        private static void CheckSeamsRefuseLiveTarget(List<string> failures, ClaimLog claims)
        {
            claims.Claim("all 6 mutating test seams REFUSE an attached engine - OnUserBpForTest also "
                         + "refusing the --once and interactive engines, and ArmUserBpForTest a load base "
                         + "that disagrees with the module its va resolves to - while every one of them "
                         + "still WORKS with no target, so none is a seam that refuses everything.");

            // Nothing but a real Attach/Launch sets _hProcess, so an attached engine cannot be built through
            // any public path; it is set directly here. 0x1234 is not a handle this process owns, so every
            // write an UNGUARDED handler would attempt through it fails — running the pre-fix code to watch
            // this check fail touches nothing. A rename of the field fails loudly instead of passing quietly.
            //
            // THIS DEPENDS ON DebugEngine HAVING NO DISPOSER, and that is not an accident to be discovered
            // later: there is no Dispose and no finalizer, so nothing ever calls CloseHandle(_hProcess) on
            // these throwaway engines and the fake 0x1234 is never handed to the OS. If a Dispose or
            // finalizer is ever added that closes _hProcess, this check starts closing an arbitrary handle
            // belonging to the protocolcheck process itself. Give the fake engines a real-but-harmless
            // handle (e.g. a duplicate of the current process) before adding one.
            var hProcField = typeof(DebugEngine).GetField("_hProcess",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            if (hProcField == null)
            {
                failures.Add("seam-guard control: DebugEngine._hProcess was not found, so this check cannot "
                             + "build an attached engine and is asserting nothing");
                return;
            }

            // `prepare` runs BEFORE the fake handle goes in, so an arm can set up the state its seam needs
            // (OnUserBp reads the armed-byte map) without that setup being the thing that refuses.
            Action<string, Action<DebugEngine>, Action<DebugEngine>> refusesAttached = (name, prepare, call) =>
            {
                var eng = NewEngine();
                if (prepare != null) prepare(eng);
                hProcField.SetValue(eng, new IntPtr(0x1234));
                string outcome = null;
                CaptureConsole(() => { outcome = SeamOutcome(() => call(eng)); });
                if (outcome != null)
                    failures.Add("seam-guard: " + name + " " + outcome + " against an ATTACHED engine — the "
                                 + "seam must refuse rather than rely on the caller passing a tid Windows "
                                 + "never assigns");
            };

            refusesAttached("OnUserBpForTest",
                            e => e.ArmUserBpForTest(0x00400000, 0x00401100, null, null, 0, null),
                            e => e.OnUserBpForTest(0xFFFFFFF1, 0x00401100));
            refusesAttached("ArmUserBpForTest", null,
                            e => e.ArmUserBpForTest(0x00400000, 0x00401100, null, null, 0, null));
            refusesAttached("ArmStepOverSessionForTest", null,
                            e => e.ArmStepOverSessionForTest(0xFFFFFFF1, 0x00401000, 0x00402000));
            refusesAttached("CancelStepForTest", null, e => e.CancelStepForTest());
            refusesAttached("ArmPrologueBypassForTest", null, e => e.ArmPrologueBypassForTest(0x1000));
            refusesAttached("RegisterThreadedModuleForTest", null,
                            e => e.RegisterThreadedModuleForTest("t.dll", 0x00400000, 0x1000, 0x2000));

            // The other two caller choices, ISOLATED from the attached-target guard above: this engine has NO
            // target, so only the --once / interactive refusal can stop it. Pre-fix, the --once arm reached
            // TerminateProcess and the interactive arm never returned at all.
            foreach (var arm in new[] { "once", "interactive" })
            {
                var eng = new DebugEngine("protocolcheck", null, null, null, null,
                                          arm == "once", 0, arm == "interactive");
                eng.ArmUserBpForTest(0x00400000, 0x00401100, null, null, 0, null);
                string outcome = null;
                CaptureConsole(() => { outcome = SeamOutcome(() => eng.OnUserBpForTest(0xFFFFFFF1, 0x00401100)); });
                if (outcome != null)
                    failures.Add("seam-guard: OnUserBpForTest " + outcome + " on a " + arm + " engine — the "
                                 + (arm == "once" ? "pausing route calls TerminateProcess"
                                                  : "pausing route blocks in PausedWait reading stdin")
                                 + ", so the seam must refuse this engine");
            }

            // ISOLATION for all of the above: with no target and neither flag set, the same seams must still
            // WORK. Without this the guards would be indistinguishable from seams that refuse everything,
            // and CheckBpHitVsStep above would be running against nothing.
            try
            {
                var ok = NewEngine();
                ok.ArmUserBpForTest(0x00400000, 0x00401100, null, null, 0, null);
                ok.ArmStepOverSessionForTest(0xFFFFFFF1, 0x00401000, 0x00402000);
                CaptureConsole(() => ok.OnUserBpForTest(0xFFFFFFF1, 0x00401100));
                ok.ArmPrologueBypassForTest(0x1000);
                ok.CancelStepForTest();
                ok.RegisterThreadedModuleForTest("t.dll", 0x00500000, 0x1000, 0x2000);
            }
            catch (Exception ex)
            {
                failures.Add("seam-guard control: the seams refused an engine with NO target and neither "
                             + "flag set (" + ex.GetType().Name + ": " + ex.Message + ") — the guard is too "
                             + "broad and every seam-driven check above is now asserting nothing");
            }

            // ---- and ArmUserBpForTest's loadBase must AGREE with the module the va resolves to ----------
            // The image is registered ONCE. On every arm after the first, ModuleAt(va) already resolved and
            // the seam dropped `loadBase` on the floor, computing the RVA from the resolved module instead
            // — so the argument was a decoration on all but the first call, and a case arming two
            // breakpoints under two different bases was quietly testing one. Rvas is what the un-patch and
            // re-arm paths work from, so this is not something a caller may be vague about.
            var lb = NewEngine();
            lb.ArmUserBpForTest(0x00400000, 0x00401100, null, null, 0, null);   // registers the image

            // CONTROL FIRST: a second arm INSIDE that image, passing the base it was registered under, is
            // still accepted. Without this the rule below would be met just as well by a seam that had
            // started refusing every arm after the first.
            string agrees = SeamOutcome(() => lb.ArmUserBpForTest(0x00400000, 0x00401200, null, null, 0, null));
            if (agrees == null)
                failures.Add("seam-loadbase control: a second arm passing the SAME load base was refused — "
                             + "the agreement check is refusing everything and asserting nothing");

            // THE RULE. Same registered image, a base that contradicts it.
            string disagrees = SeamOutcome(() => lb.ArmUserBpForTest(0x00500000, 0x00401300, null, null, 0, null));
            if (disagrees != null)
                failures.Add("seam-loadbase: ArmUserBpForTest " + disagrees + " when handed a load base that "
                             + "disagrees with the module its va resolves to — it must refuse, not plant at "
                             + "an RVA computed from a base its caller never passed");
        }

        /// <summary>How a seam call ENDED: null when it refused with InvalidOperationException, otherwise a
        /// description. The bounded join is part of the assertion rather than defensiveness — one of the
        /// caller choices the seam used to trust was interactive:false, and an interactive engine that
        /// reaches PausedWait spins forever on an empty command queue, so "never returned" has to be
        /// reportable instead of hanging the whole check.</summary>
        private static string SeamOutcome(Action body)
        {
            string outcome = "returned without refusing";
            var t = new System.Threading.Thread(() =>
            {
                try { body(); }
                catch (InvalidOperationException) { outcome = null; }
                catch (Exception ex) { outcome = "threw " + ex.GetType().Name + ": " + ex.Message; }
            });
            t.IsBackground = true;
            t.Start();
            if (!t.Join(3000)) return "never returned (still running after 3s)";
            return outcome;
        }

        /// <summary>An engine with no target: every path below is bookkeeping, and the memory access it
        /// attempts fails harmlessly on a null process handle.</summary>
        private static DebugEngine NewEngine()
        {
            return new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
        }

        /// <summary>Run <paramref name="body"/> with stdout captured, and hand back what it printed. The
        /// engine's hit reporting is console output, so it is EVIDENCE here — which route a hit took is
        /// visible in the log and nowhere else in its state.</summary>
        private static string CaptureConsole(Action body)
        {
            var prev = Console.Out;
            var buf = new System.IO.StringWriter();
            Console.SetOut(buf);
            try { body(); }
            finally { Console.SetOut(prev); }
            return buf.ToString();
        }

        /// <summary>
        /// The once-per-session diagnostics (ticket ec45805f item 5), and specifically HOW THEY KEY.
        ///
        /// Two console notes fired on a repeating event rather than a changing one: the window-walk cap on
        /// every pause, and the THREADed-emulation notes on every field read — so a conditional breakpoint
        /// over an image with no .cwtls span buried the console in identical text, up to 13 lines each.
        ///
        /// The interesting half is not "does it dedup". It is WHAT IT DEDUPS ON. These notes interpolate the
        /// instance address and the block span, so a version that keyed on the MESSAGE would dedup nothing
        /// at all while looking exactly like a working one — a suppression that never suppresses is the same
        /// class of unfalsifiable check as the `"tid":-1` search at the top of this file. So this drives the
        /// REAL reporter through its seam, not the predicate underneath it, and the decisive case is two
        /// calls with the same (image, reason) and DIFFERENT text.
        ///
        /// The set is also per ENGINE, and that is asserted: static state would carry a session's
        /// suppressions into the next one, and the note that mattered would be the one nobody saw.
        ///
        /// The window-cap site needs real windows and is not reachable here; it shares this rule holder, and
        /// that sharing is the whole reason there is one holder rather than a flag in each file.
        /// </summary>
        private static void CheckOnceOnlyDiagnostics(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the repeating console diagnostics report once per (image, reason) per ENGINE, "
                         + "keyed on the reason CATEGORY and not on the message - which interpolates "
                         + "addresses, so keying on it would dedup nothing while looking like it worked - "
                         + "with the suppression stated on the line rather than left to be inferred.");

            // ---- the rule holder, isolated: first sighting true, every later one false, keys independent.
            var eng = NewEngine();
            if (!eng.FirstReportOfForTest("k1"))
                failures.Add("once-only control: the FIRST sighting of a key was suppressed — the "
                             + "diagnostic would never be printed at all");
            if (eng.FirstReportOfForTest("k1"))
                failures.Add("once-only: a repeated key reported again — the console floods");
            if (!eng.FirstReportOfForTest("k2"))
                failures.Add("once-only: a DIFFERENT key was suppressed by the first one — one noisy "
                             + "diagnostic would silence every other");

            // ---- per session, not per process. A static set would hide the second session's first warning.
            if (!NewEngine().FirstReportOfForTest("k1"))
                failures.Add("once-only: a NEW engine inherited the previous session's suppressions — the "
                             + "set must be per engine, or a fresh run starts already silent");

            // ---- THE DECIDING CASE: same image, same reason, different TEXT reports ONCE.
            var e2 = NewEngine();
            string first = CaptureConsole(() => e2.NoteThreadedEmulationForTest(
                "app.dll", "write-outside-block", "kept instance 0x11110000 despite a write outside 0x2000"));
            string again = CaptureConsole(() => e2.NoteThreadedEmulationForTest(
                "app.dll", "write-outside-block", "kept instance 0x99990000 despite a write outside 0x7777"));

            if (first.IndexOf("app.dll", StringComparison.Ordinal) < 0
                || first.IndexOf("0x11110000", StringComparison.Ordinal) < 0)
                failures.Add("threaded-note control: the FIRST note did not print its image and detail — "
                             + "got: " + first.Trim());
            if (again.Trim().Length != 0)
                failures.Add("threaded-note: the same (image, reason) reported twice because the text "
                             + "differed — it is keyed on the MESSAGE, which interpolates addresses, so it "
                             + "dedups nothing: " + again.Trim());

            // ---- and the suppression is ANNOUNCED. This reporter's whole contract is that it is never
            //      silent; dropping repeats without saying so is a quieter way of being silent.
            if (first.IndexOf("reported once", StringComparison.OrdinalIgnoreCase) < 0)
                failures.Add("threaded-note: the note does not say it is reported once per session, so a "
                             + "reader cannot tell 'happened once' from 'happening constantly, suppressed'");

            // ---- the key's two halves, each isolated with the other held fixed.
            string otherReason = CaptureConsole(() => e2.NoteThreadedEmulationForTest(
                "app.dll", "no-cwtls-span", "no .cwtls span to test the write against"));
            if (otherReason.Trim().Length == 0)
                failures.Add("threaded-note: a DIFFERENT reason on the same image was suppressed — the two "
                             + "conditions are different findings and the second would never be seen");

            string otherImage = CaptureConsole(() => e2.NoteThreadedEmulationForTest(
                "other.dll", "write-outside-block", "kept instance 0x11110000 despite a write outside 0x2000"));
            if (otherImage.Trim().Length == 0)
                failures.Add("threaded-note: the SAME reason on a different image was suppressed — one bad "
                             + "image would mask the same fault in every other");
        }

        /// <summary>
        /// The window-walk cap's dedup key names the WINDOW, not its place in the enumeration.
        ///
        /// The key was `"wincap|root " + i`, the EnumWindows loop index. Close the app's first top-level
        /// window and the former root 1 becomes root 0, so a genuinely new pathological root is silenced
        /// under a key already reported — and the line it would have printed named a root number that by
        /// then identified nothing. Position is not identity; this session found four bugs of that shape
        /// in recycled pids alone.
        ///
        /// HALF OF THIS IS NOT TESTED HERE, AND DOES NOT NEED TO BE. That the key cannot be built from a
        /// position is guaranteed by WinCapKey's SIGNATURE, which has no index parameter — a compile-time
        /// fact, stronger than any assertion this file could make and not something a mutation could sneak
        /// past. What a signature cannot promise is that the key SEPARATES distinct roots and stays STABLE
        /// for one, and that is what is checked below: without separation the dedup suppresses a real
        /// second window, and without stability it suppresses nothing at all.
        ///
        /// The walk itself needs live windows and is unreachable from here. This covers the key, says so,
        /// and does not imply the walk.
        /// </summary>
        private static void CheckWinCapKeyIsIdentityNotPosition(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the window-walk cap's dedup key is the root window's IDENTITY (its handle and "
                         + "class), not its index in the enumeration - so closing one top-level window no "
                         + "longer silences a different one; distinct roots get distinct keys and one root "
                         + "keys the same every time. The key cannot be positional by construction: "
                         + "WinCapKey takes no index. The walk itself needs live windows and is NOT covered.");

            const long hwndA = 0x000407C2;
            const long hwndB = 0x0011045A;

            // STABLE: the same window must key identically on every pause, or the suppression never happens
            // and the flood this exists to stop comes back.
            if (DebugEngine.WinCapKeyForTest(hwndA, "ClarionFrame")
                != DebugEngine.WinCapKeyForTest(hwndA, "ClarionFrame"))
                failures.Add("wincap key: the same root keyed differently twice — nothing would ever dedup");

            // SEPARATES on the handle: this is the case the positional key got wrong. Two roots that
            // happened to occupy the same index across two stops shared a key and silenced each other.
            if (DebugEngine.WinCapKeyForTest(hwndA, "ClarionFrame")
                == DebugEngine.WinCapKeyForTest(hwndB, "ClarionFrame"))
                failures.Add("wincap key: two DIFFERENT root windows produced the same key — a new "
                             + "pathological root is silenced under one already reported, which is the "
                             + "defect the positional key had");

            // SEPARATES on the class too, which is what makes a recycled handle survivable: the same handle
            // reused by a different kind of window is a different window and must be reported.
            if (DebugEngine.WinCapKeyForTest(hwndA, "ClarionFrame")
                == DebugEngine.WinCapKeyForTest(hwndA, "#32770"))
                failures.Add("wincap key: a RECYCLED handle reused by a different window class kept the "
                             + "old key — the one mitigation the key has against handle reuse is gone");

            // A null class must not throw and must not collide with a real one. FillWindowEvidence builds
            // Cls from GetClassName, which can come back empty for a window that died mid-walk.
            string nullCls = DebugEngine.WinCapKeyForTest(hwndA, null);
            if (string.IsNullOrEmpty(nullCls))
                failures.Add("wincap key: a null class produced no key at all");
            if (nullCls == DebugEngine.WinCapKeyForTest(hwndA, "ClarionFrame"))
                failures.Add("wincap key: an unknown class keyed the same as a known one");
        }

        /// <summary>
        /// A bare field name means the FILE's record buffer, however the symbol table orders the groups
        /// that repeat it (6b48ad7c). demoleg.exe lists UpdateCountries' HISTORY::COU:RECORD, declared
        /// LIKE(COU:RECORD), ahead of COUNTRIES$COU:RECORD; first-registration-wins resolved COU:COUNTRY to
        /// the history copy, so table fields read as zeros and offered a pencil into the wrong buffer.
        /// </summary>
        private static void CheckFieldNameResolvesToFileRecord(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a field name repeated by several groups resolves to the FILE record buffer "
                         + "(FILE$PRE:RECORD) in EITHER registration order, ahead of a form's HISTORY:: copy and of "
                         + "an unscoped GROUP; a '$' without the record shape, or the record shape under a :: scope, "
                         + "buys no priority; every other collision keeps its first registration, in both orders. "
                         + "Driven through the index's own RegisterDataName; the call sites that feed it are NOT "
                         + "covered here.");

            var file    = new TswdDebugInfo.DataLocation { Rva = 0x3C3AC0, Container = "COUNTRIES$COU:RECORD" };
            var history = new TswdDebugInfo.DataLocation { Rva = 0x049D10, Container = "HISTORY::COU:RECORD" };
            var plain   = new TswdDebugInfo.DataLocation { Rva = 0x100000, Container = "SAVE:COUNTRY" };
            var dollar  = new TswdDebugInfo.DataLocation { Rva = 0x300000, Container = "VMT$COUNTRYGROUP" };
            var scopedFile = new TswdDebugInfo.DataLocation { Rva = 0x400000, Container = "UPDATE::LOCAL$COU:RECORD" };
            var stat    = new TswdDebugInfo.DataLocation { Rva = 0x500000, Container = null };

            Func<TswdDebugInfo.DataLocation[], uint> winner = order =>
            {
                var index = new Dictionary<string, TswdDebugInfo.DataLocation>(StringComparer.OrdinalIgnoreCase);
                foreach (var loc in order) TswdDebugInfo.RegisterDataName(index, "COU:COUNTRY", loc);
                return index["cou:country"].Rva;
            };

            // The reported order: the history copy registers FIRST. This is the one first-wins got wrong.
            if (winner(new[] { history, file }) != file.Rva)
                failures.Add("field name: the history copy registered first and KEPT COU:COUNTRY — table fields "
                             + "read the form's HISTORY:: buffer instead of the record (6b48ad7c)");
            if (winner(new[] { file, history }) != file.Rva)
                failures.Add("field name: a later HISTORY:: copy displaced the FILE record buffer");
            if (winner(new[] { plain, file }) != file.Rva || winner(new[] { file, plain }) != file.Rva)
                failures.Add("field name: an unscoped GROUP outranked the FILE record buffer");
            if (winner(new[] { dollar, file }) != file.Rva || winner(new[] { scopedFile, file }) != file.Rva)
                failures.Add("field name: a '$' name without the record shape, or a record shape under a :: "
                             + "scope, kept the name against the real FILE record buffer");

            // No priority among the non-record containers: each of these pairs keeps whichever registered
            // FIRST, in both orders. A third rank for scoped names was tried and reordered unrelated collisions
            // (demoleg's M_* FormatManager members, 2026-09-22); '$' alone would let any mangled name jump ahead.
            var ties = new[]
            {
                new[] { history, plain }, new[] { dollar, plain }, new[] { scopedFile, history },
                new[] { file, new TswdDebugInfo.DataLocation { Rva = 0x200000, Container = "OTHER$COU:RECORD" } },
                new[] { stat, file },
            };
            foreach (var pair in ties)
                if (winner(new[] { pair[0], pair[1] }) != pair[0].Rva || winner(new[] { pair[1], pair[0] }) != pair[1].Rva)
                    failures.Add("field name: equal-rank registrations (" + (pair[0].Container ?? "static") + " / "
                                 + (pair[1].Container ?? "static") + ") did not keep the FIRST");
        }

        /// <summary>
        /// A user-visible refusal never shows a RAW thread id.
        ///
        /// The absent-tid rule has always been about the WIRE: an unknown id is an absent member, never 0
        /// and never the 4294967295 an int cast produces. Refusal TEXT is the other half of the same rule
        /// and had no guard at all. A refusal reading "thread 0 is selected" states a falsehood about the
        /// user's own program, in the one place they are already confused enough to be reading carefully —
        /// and 4294967295 is worse, because it looks like a real id they could go and check.
        ///
        /// TidText is the rule holder, and until now NOTHING in this tree asserted it: no reference in this
        /// file, none in tools/. Reverting any of the refusal sites to raw interpolation passed every gate
        /// green. That is the same shape as the expand veto's note, one file over.
        ///
        /// HOW THIS AVOIDS ASSERTING ITS OWN EXPECTATION. The unknown rendering is not hard-coded as the
        /// thing being proved: the check requires that 0 and (uint)-1 produce the SAME string as each other
        /// and a DIFFERENT one from a known id, which is the actual contract — one representation for
        /// unknown, distinguishable from any real thread — and only then names it. A version that asserted
        /// "contains (unknown)" alone would pass against a refusal that said both.
        ///
        /// WHAT IT DOES NOT COVER, said plainly: a BRAND NEW refusal site that never calls TidText. This
        /// drives the refusal producers that are reachable with no debuggee, so it catches a revert of an
        /// existing site; it cannot catch a site nobody has written yet. That needs a source-level rule —
        /// "a `\"thread \" +` concatenation must be followed by TidText(" — which belongs in
        /// tools/test-engine-tid-members.ps1 beside the member-name scanner, not here.
        /// </summary>
        private static void CheckRefusalsNeverShowARawTid(List<string> failures, ClaimLog claims)
        {
            claims.Claim("no user-visible refusal shows a RAW thread id: both unknown values (0 and the "
                         + "(uint)-1 an int cast produces) collapse to ONE rendering, that rendering is "
                         + "TidText's \"(unknown)\" and not a number, and a KNOWN id still reads as its "
                         + "own number - so a refusal can no longer tell the user about a thread 0 or a "
                         + "thread 4294967295 that does not exist. Driven for the threaded-write refusal "
                         + "through ThreadedWriteAllowed (shared template, no own copy), and for its other "
                         + "three thread-naming wordings (own copy; another thread's instance, by owner and "
                         + "by selected id) through WriteRefusal directly, since reaching those needs a "
                         + "live thread; the decision that PICKS a wording is not covered by those three.");

            var eng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            eng.RegisterThreadedModuleForTest("app.exe", 0x400000, 0xC8000, 0xCC000, iatRva: 0);
            const uint known = 4812;
            const uint otherKnown = 5190;    // the tid NOT under test in a two-thread wording
            const uint minusOne = unchecked((uint)-1);
            const uint templateVa = 0x4C8000;

            // WriteRefusal's other wordings, rendered by the SHIPPED method on the SHIPPED struct. Both are
            // private to DebugEngine, and reaching them through ThreadedWriteAllowed needs a live thread
            // (TryInstanceBase opens one), so they are set up by reflection (ticket 6874c2d1: the
            // other-instance wording at DebugEngine.VarEdit.cs:242-243 had no runtime driver at all).
            // A renamed type, field or method is a FAILURE here, never a skipped entry.
            var bf = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public;
            var accessType = typeof(DebugEngine).GetNestedType("ThreadedAccess", bf);
            var kindType = typeof(DebugEngine).GetNestedType("ThreadedRefusal", bf);
            var writeRefusal = accessType == null ? null : accessType.GetMethod("WriteRefusal");
            if (accessType == null || kindType == null || writeRefusal == null)
                failures.Add("refusal wording: DebugEngine.ThreadedAccess / ThreadedRefusal / WriteRefusal not found "
                             + "by reflection - three refusal wordings below are no longer driven");
            Func<string, uint, uint, bool, string> render = (kind, ownerTid, selectedTid, haveOwnCopy) =>
            {
                if (writeRefusal == null || kindType == null) return null;
                object a = Activator.CreateInstance(accessType);
                accessType.GetField("Kind").SetValue(a, Enum.Parse(kindType, kind));
                accessType.GetField("Owner").SetValue(a, new LoadedModule { Name = "app.exe" });
                accessType.GetField("OwnerTid").SetValue(a, ownerTid);
                accessType.GetField("SelectedTid").SetValue(a, selectedTid);
                accessType.GetField("HaveOwnCopy").SetValue(a, haveOwnCopy);
                accessType.GetField("OwnCopyVa").SetValue(a, 0x5000u);
                return (string)writeRefusal.Invoke(a, new object[] { templateVa, 1 });
            };

            // The refusal producers reachable with no target. A table rather than three copies, so adding
            // the next drivable one is a line — and so the assertions below are applied to every entry
            // rather than to whichever one somebody remembered.
            var producers = new[]
            {
                new { Name = "threaded-write refusal", Make = (Func<uint, string>)(t =>
                {
                    string why;
                    eng.ThreadedWriteAllowedForTest(templateVa, 1, t, out why);
                    return why;
                }) },
                new { Name = "threaded-write refusal, selected thread has its own copy",
                      Make = (Func<uint, string>)(t => render("SharedTemplate", 0, t, true)) },
                new { Name = "threaded-write refusal, another thread's instance (owner id)",
                      Make = (Func<uint, string>)(t => render("OtherThreadInstance", t, otherKnown, false)) },
                new { Name = "threaded-write refusal, another thread's instance (selected id)",
                      Make = (Func<uint, string>)(t => render("OtherThreadInstance", otherKnown, t, false)) },
            };

            foreach (var p in producers)
            {
                string forKnown = p.Make(known);
                string forZero = p.Make(0);
                string forMinusOne = p.Make(minusOne);

                // CONTROL FIRST: it must actually be refusing, or everything below passes on empty strings.
                if (string.IsNullOrEmpty(forKnown) || string.IsNullOrEmpty(forZero))
                    { failures.Add(p.Name + " control: produced no refusal at all, so nothing below asserts anything"); continue; }

                // CONTROL: a KNOWN id still reads as its number. Without this, a refusal that had simply
                // stopped naming threads would satisfy every other assertion here.
                if (forKnown.IndexOf("thread " + known, StringComparison.Ordinal) < 0)
                    failures.Add(p.Name + " control: a KNOWN thread id is no longer named in the refusal — "
                                 + forKnown);

                // ONE REPRESENTATION FOR UNKNOWN. 0 and (uint)-1 are different values and the same
                // non-fact, so they must read identically. This is the contract; the wording is downstream.
                if (forZero != forMinusOne)
                    failures.Add(p.Name + ": the two unknown ids read differently — 0 gave \"" + forZero
                                 + "\" and (uint)-1 gave \"" + forMinusOne + "\", so one of them is being "
                                 + "rendered as itself");

                // ...and DISTINGUISHABLE from a real thread, or "unknown" is not being said at all.
                if (forZero == forKnown)
                    failures.Add(p.Name + ": an unknown id reads exactly like a known one — " + forZero);

                // NO RAW SENTINEL REACHES THE USER. Both spellings, because the int-cast one is the one
                // that looks like a thread they could go and check.
                foreach (var raw in new[] { "thread 0", "4294967295" })
                    foreach (var s in new[] { forZero, forMinusOne })
                        if (s.IndexOf(raw, StringComparison.Ordinal) >= 0)
                            failures.Add(p.Name + ": an unknown thread id reached the user as \"" + raw
                                         + "\" — it states a falsehood about their own program: " + s);

                // ...and it DOES name it as unknown, rather than quietly dropping the clause.
                if (forZero.IndexOf("(unknown)", StringComparison.Ordinal) < 0)
                    failures.Add(p.Name + ": an unknown thread id is not named at all — the refusal should "
                                 + "say so through TidText rather than omit the thread: " + forZero);
            }
        }

        /// <summary>A row-bearing event must carry the one KNOWN tid it was given and neither sentinel.
        /// Feeding the builder a known tid alongside 0 and (uint)-1 in the SAME event is the point: it
        /// asserts the rule is applied per row, not decided once for the whole event.</summary>
        private static void CheckNoSentinelRows(List<string> failures, string name, string json, uint known)
        {
            // The control counts the tid WITH ITS TERMINATOR, the way the zero check below already does.
            // `"tid":116932` alone is a PREFIX: a row writing 1169320 satisfies it, so the control could
            // pass while the value on the wire was a different thread entirely (ticket ec45805f item 3).
            // A false pass in the control of the check that enforces the absent-tid rule hides precisely
            // what the rule exists to catch, so it is worth the two extra Counts.
            int knownCount = Count(json, "\"tid\":" + known + ",") + Count(json, "\"tid\":" + known + "}");
            if (knownCount != 1)
                failures.Add(name + " control: the one known tid was written " + knownCount
                             + " time(s), expected exactly 1 — " + json);
            int zero = Count(json, "\"tid\":0,") + Count(json, "\"tid\":0}");
            if (zero != 0)
                failures.Add(name + ": " + zero + " row(s) wrote a 0 tid — a row the pad would attribute to a "
                             + "real thread it will never match");
            if (Count(json, "\"tid\":" + unchecked((uint)-1)) != 0)
                failures.Add(name + ": a row wrote the (uint)-1 sentinel — " + json);
        }

        /// <summary>Occurrences of <paramref name="needle"/> in <paramref name="hay"/>.</summary>
        private static int Count(string hay, string needle)
        {
            int n = 0, i = 0;
            while ((i = hay.IndexOf(needle, i, StringComparison.Ordinal)) >= 0) { n++; i += needle.Length; }
            return n;
        }

        /// <summary>
        /// A row that is NOT this thread's own must not be editable — and neither must anything INSIDE it.
        ///
        /// `moduledata` falls back to the shared .cwtls template when the selected thread has no instance of
        /// a THREADed symbol, and vetoes the edit pencil because writing a template changes the initial value
        /// every future Clarion thread starts from. The setval thread guard cannot catch a write that slips
        /// through here: the tid on such a row is perfectly honest, the ADDRESS just belongs to no thread.
        ///
        /// So the veto has to reach the descendants, and that is what this asserts — against the real
        /// NodeJson, including the group and array child builders it delegates to. A live harness cannot
        /// cover it: reaching the template fallback needs a stop whose EIP resolves to a module carrying
        /// THREADed module-scope data while a thread with no instance of it is selected, which the debuggee
        /// does not readily produce.
        /// </summary>
        private static void CheckEditVeto(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a vetoed row's descendants offer no edit metadata, INLINE and through `expand` - "
                         + "whose veto is derived from the address over the whole group's SPAN - while an "
                         + "ordinary group keeps its pencils; and the veto and the NOTE that explains it "
                         + "come from ONE classification, so a group straddling into the template is told "
                         + "the template reason and not another thread's.");

            // A DebugEngine with no target: rows still build, the values just read as nothing.
            var eng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);

            var lng = new ClarionType { Kind = TypeKind.Int, Size = 4 };
            var grp = new ClarionType
            {
                Kind = TypeKind.Group,
                Size = 8,
                Members = new List<TypeMember>
                {
                    new TypeMember { Name = "FIRST",  Offset = 0, Type = lng },
                    new TypeMember { Name = "SECOND", Offset = 4, Type = lng },
                },
            };
            var arr = new ClarionType { Kind = TypeKind.Array, Size = 8, Length = 2, LoBound = 1, ElemSize = 4, ElemType = lng };

            // Control: without a veto these DO carry edit metadata. Without this, a builder that never
            // emitted `va` at all would pass the real checks for the wrong reason.
            string groupOk = eng.NodeJsonForTest("G", grp, 0x08, 0, 8, 0, 0x400000, "m.clw", null, true);
            if (CountVa(groupOk) == 0) failures.Add("edit-veto control: an un-vetoed GROUP produced no editable member at all");
            string arrayOk = eng.NodeJsonForTest("A", arr, 0x18, 0, 8, 0, 0x400000, "m.clw", null, true);
            if (CountVa(arrayOk) == 0) failures.Add("edit-veto control: an un-vetoed ARRAY produced no editable element at all");

            // THE RULE: a vetoed row carries no edit metadata anywhere beneath it either.
            string groupVetoed = eng.NodeJsonForTest("G", grp, 0x08, 0, 8, 0, 0x400000, "m.clw",
                                                     "no thread instance - shared template value", false);
            int n = CountVa(groupVetoed);
            if (n != 0)
                failures.Add("edit-veto: a vetoed GROUP still offered " + n + " editable descendant row(s) — "
                             + "a commit would rewrite the shared template");

            string arrayVetoed = eng.NodeJsonForTest("A", arr, 0x18, 0, 8, 0, 0x400000, "m.clw",
                                                     "no thread instance - shared template value", false);
            n = CountVa(arrayVetoed);
            if (n != 0)
                failures.Add("edit-veto: a vetoed ARRAY still offered " + n + " editable element row(s)");

            // A vetoed scalar is the case that already worked; assert it so a refactor cannot lose it.
            string scalarVetoed = eng.NodeJsonForTest("S", null, 0x11, 0, 4, 0, 0x400000, "m.clw", "shared", false);
            if (CountVa(scalarVetoed) != 0) failures.Add("edit-veto: a vetoed scalar row still carried edit metadata");
            if (scalarVetoed.IndexOf("\"note\":", StringComparison.Ordinal) < 0)
                failures.Add("edit-veto: a vetoed row dropped its explanation");

            // ---- THE EXPAND PATH ------------------------------------------------------------------
            // The rows above are the ones the engine builds knowing whether they are vetoed. `expand`
            // is the path that does NOT know: until cc3ac96e the command carried only
            // reqId/module/typeRef/addr, so an expanded node's members were always built editable —
            // including when the node was a shared .cwtls template reached through a by-ref member or
            // an array-of-group element. That hole was stated in this check's own success message.
            // The engine now DERIVES the veto from the address, through the same write guard that
            // would refuse the commit, and these are the assertions that retire the claim.
            //
            // A separate engine, so registering an image cannot disturb anything asserted above.
            var xeng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            // An image at 0x400000 whose .cwtls template block is RVA 0xC8000..0xCC000 — the same
            // layout CheckThreadedWriteGuard uses. iatRva 0 (THR$GetInstance not resolved) on purpose:
            // it keeps this check off OpenThread, which protocolcheck has no target for and which a
            // bare tid cannot identify anyway, while leaving the template refusal — the branch that
            // needs nothing resolved — exactly as it ships.
            xeng.RegisterThreadedModuleForTest("app.exe", 0x400000, 0xC8000, 0xCC000, iatRva: 0);
            const uint xtid = 4812;

            // CONTROL, and it carries as much weight as the rule: expanding an ORDINARY address must
            // still produce editable members. A derive that simply vetoed everything would satisfy the
            // rule below while silently ending in-place editing for every non-threaded group.
            string expandOk = xeng.ExpandChildrenForTest(grp, 0x401000, "app.exe", xtid);
            if (CountVa(expandOk) != 2)
                failures.Add("expand-veto control: expanding an ordinary GROUP offered " + CountVa(expandOk)
                             + " editable member(s), expected 2 — the derive over-vetoes");
            if (expandOk.IndexOf("\"note\":", StringComparison.Ordinal) >= 0)
                failures.Add("expand-veto control: an ordinary expanded GROUP carried a refusal note");

            // THE RULE: expanding a row that sits on the shared template offers no pencil beneath it.
            string expandVetoed = xeng.ExpandChildrenForTest(grp, 0x4C8000, "app.exe", xtid);
            n = CountVa(expandVetoed);
            if (n != 0)
                failures.Add("expand-veto: expanding a shared-template row offered " + n + " editable "
                             + "member row(s) — a pencil promising a write HandleSetValCommand will refuse");
            if (Count(expandVetoed, "\"note\":") != 2)
                failures.Add("expand-veto: a vetoed expanded row did not explain itself on every member — "
                             + "the tree can be scrolled until only the member is on screen");

            // THE GROUP IS AN INTERVAL, exactly as a write is. Its members are read at base+offset, so
            // a group that STARTS below the template and reaches into it must be vetoed whole: one
            // flag covers every member, and the member that lands on shared bytes is the one that
            // matters. Testing only the base address would let this through.
            //   0x4C7FFC + member SECOND at +4 = 0x4C8000, the template's first byte.
            string straddling = xeng.ExpandChildrenForTest(grp, 0x4C7FFC, "app.exe", xtid);
            if (CountVa(straddling) != 0)
                failures.Add("expand-veto: a GROUP at 0x4C7FFC has a member ON the template's first byte "
                             + "but " + CountVa(straddling) + " member row(s) were still offered a pencil");
            // AND IT MUST NAME THE RIGHT REFUSAL — the guarantee ticket 49538b78 item 3 created, which
            // nothing asserted until now.
            //
            // The veto was span-based and correct. The NOTE was decided by a SECOND, INDEPENDENT point
            // test on the row's START address, so this group — outside the template at its first byte,
            // inside it at its last — was vetoed correctly and then labelled "another thread's data",
            // a different refusal entirely. Counting `va` cannot see that: the row is vetoed either way,
            // so the check stayed green while the user was told the wrong thing.
            //
            // THIS IS THE DISCRIMINATING CASE. A group whose start is outside the block and whose SPAN
            // straddles in is the only shape where a point test and a span test disagree; every other
            // case agrees by accident and proves nothing. An address inside a .cwtls block can earn only
            // the template refusal, so that is what the wording must name.
            //
            // It asserts on TEXT, which this file otherwise avoids, and the reason is worth stating: the
            // note reaches the pad as a string and nothing else about it is observable from here. The
            // structural version wants a seam over ClassifyThreadedAccess's Kind, in another owner's
            // file — noted rather than quietly settled for.
            if (straddling.IndexOf("template", StringComparison.OrdinalIgnoreCase) < 0)
                failures.Add("expand-veto: a GROUP straddling into the shared template was vetoed but "
                             + "labelled with the WRONG REFUSAL — the veto is derived over the span and "
                             + "the note is not, so they no longer come from one classification: "
                             + straddling);
            // ...and the group that really does stay below it keeps its pencils: 0x4C7FF8 + 8 ends
            // exactly at the template's first byte, which is past the last byte it touches.
            string justBelow = xeng.ExpandChildrenForTest(grp, 0x4C7FF8, "app.exe", xtid);
            if (CountVa(justBelow) != 2)
                failures.Add("expand-veto control: a GROUP ending exactly at the template's first byte was "
                             + "vetoed — it touches none of it");

            // NOT COVERED HERE, and deliberately: the two notes that distinguish "this thread has no
            // instance yet" from "it has one, at another address" both need a live THR$GetInstance
            // emulation. The VETO is fully covered above; only its wording varies with that resolve.
        }

        /// <summary>
        /// A write must never land on the shared .cwtls TEMPLATE.
        ///
        /// The template is the block every Clarion thread's instance is copied from, so writing it changes
        /// the value threads that DO NOT EXIST YET will start with — a side effect on the program's future,
        /// from a debugger that is supposed to observe it. The row-level veto stops the pencil appearing,
        /// but the veto only covers rows the engine builds and can classify: a row held from before a thread
        /// switch, an expanded node, or a hand-typed CLI setval all reach the writer directly. This asserts
        /// the guard AT THE WRITE, which is the only place that covers every path in.
        ///
        /// The template branch is pure address arithmetic, so it is fully assertable with no debuggee. The
        /// other-thread branch needs a live THR$GetInstance emulation and so is NOT covered here — it is
        /// exercised against a real target instead; see the ticket notes.
        /// </summary>
        private static void CheckThreadedWriteGuard(List<string> failures, ClaimLog claims)
        {
            claims.Claim("no write, of any length, can touch the shared THREADed template.");

            var eng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            // An image mapped at 0x400000 whose .cwtls template block is RVA 0xC8000..0xCC000.
            eng.RegisterThreadedModuleForTest("app.exe", 0x400000, 0xC8000, 0xCC000);
            const uint tid = 4812;
            string why;

            // THE RULE: the template block is refused, at its first byte, in the middle and at its last.
            uint[] inside = { 0x4C8000, 0x4CAF60, 0x4CBFFF };
            foreach (var va in inside)
            {
                if (eng.ThreadedWriteAllowedForTest(va, 1, tid, out why))
                    failures.Add("threaded-write: 0x" + va.ToString("X") + " is inside the shared template but the write was allowed");
                else if (string.IsNullOrEmpty(why))
                    failures.Add("threaded-write: 0x" + va.ToString("X") + " was refused with no reason for the pad to show");
                else if (why.IndexOf("template", StringComparison.OrdinalIgnoreCase) < 0)
                    failures.Add("threaded-write: the refusal does not say why: " + why);
            }

            // CONTROLS: ordinary addresses must still be writable, or the guard has broken editing for
            // everyone. One below the block, one above, one in a different image entirely.
            // These are SINGLE-BYTE controls and that is now said out loud. 0x4C7FFF was previously
            // asserted as "must be allowed" full stop, which is true of one byte and false of two — the
            // control case was itself the hole the claims audit found.
            uint[] outside = { 0x4C7FFF, 0x4CC000, 0x401000, 0x00A2FD00 };
            foreach (var va in outside)
            {
                if (!eng.ThreadedWriteAllowedForTest(va, 1, tid, out why))
                    failures.Add("threaded-write control: a one-byte write at ordinary address 0x"
                                 + va.ToString("X") + " was refused — " + why);
            }

            // A WRITE IS AN INTERVAL. Starting outside the block is not the same as staying outside it.
            if (eng.ThreadedWriteAllowedForTest(0x4C7FFF, 2, tid, out why))
                failures.Add("threaded-write: a 2-byte write at 0x4C7FFF runs INTO the shared template but was allowed");
            // 0x4C7C01 + 1024 = 0x4C8001, so exactly ONE byte of this write lands on the block — which is
            // the point: the overlap does not have to be large to be a write on shared data. (An earlier
            // version of this line claimed 0x3FF bytes. Wrong by three orders of magnitude, in the file
            // whose job is to keep claims honest.)
            if (eng.ThreadedWriteAllowedForTest(0x4C7C01, 1024, tid, out why))
                failures.Add("threaded-write: a 1024-byte write at 0x4C7C01 reaches the shared template's first byte but was allowed");
            // ...and the byte before the block is still fine when the write really does stay outside it.
            if (!eng.ThreadedWriteAllowedForTest(0x4C7FFE, 2, tid, out why))
                failures.Add("threaded-write control: a 2-byte write ending exactly at the template's first byte was refused — " + why);
            // The far edge: a write ending on the block's last byte overlaps; one starting after it does not.
            if (eng.ThreadedWriteAllowedForTest(0x4CBFFF, 4, tid, out why))
                failures.Add("threaded-write: a write starting on the template's last byte was allowed");
            if (!eng.ThreadedWriteAllowedForTest(0x4CC000, 4096, tid, out why))
                failures.Add("threaded-write control: a write starting just past the template was refused — " + why);

            // THE CASE WHOSE ABSENCE LET A HOLE THROUGH: an image with a real .cwtls section whose
            // THR$GetInstance import did not resolve (locally linked runtime, renamed DLL, import by
            // ordinal). Its rows are vetoed by the row-level checks, which gate on the section alone, so the
            // write guard must refuse the same template — it needs no import to do it. The existing template
            // case above runs against a module where the import DOES resolve, which is exactly why it could
            // not see this.
            var noImport = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            noImport.RegisterThreadedModuleForTest("static.exe", 0x400000, 0xC8000, 0xCC000, 0);
            if (noImport.ThreadedWriteAllowedForTest(0x4CAF60, 1, tid, out why))
                failures.Add("threaded-write: the shared template was writable on an image whose "
                             + "THR$GetInstance import did not resolve — an unrecoverable guard must not "
                             + "depend on an optional capability");
            if (!noImport.ThreadedWriteAllowedForTest(0x401000, 1, tid, out why))
                failures.Add("threaded-write control: an ordinary address was refused on a no-import image — " + why);

            // An engine with no threaded image must not refuse anything.
            var plain = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false);
            if (!plain.ThreadedWriteAllowedForTest(0x4CAF60, 1, tid, out why))
                failures.Add("threaded-write control: a target with no threaded image still refused a write — " + why);
        }

        /// <summary>How many rows in this JSON carry edit metadata (a `"va":` member).</summary>
        private static int CountVa(string json)
        {
            int n = 0, i = 0;
            while ((i = json.IndexOf("\"va\":", i, StringComparison.Ordinal)) >= 0) { n++; i += 5; }
            return n;
        }

        /// <summary>The value of the top-level "event" member, so a check can prove stamping did not
        /// displace or rename it.</summary>
        private static string EventNameOf(string json)
        {
            int i = json.IndexOf("\"event\":\"", StringComparison.Ordinal);
            if (i < 0) return null;
            i += 9;
            int end = json.IndexOf('"', i);
            return end < 0 ? null : json.Substring(i, end - i);
        }

        /// <summary>Is there a "tid" member at the TOP level of this object? Deliberately ignores nested
        /// objects and arrays — a per-frame or per-row tid is not the event's own, which is the same
        /// distinction the pad's extractor makes.</summary>
        private static bool HasTopLevelTid(string json) { return HasTopLevelMember(json, "tid"); }

        /// <summary>The same question for any member name, because the thread ids that bypassed the rule
        /// were called "stopped" and "selected" (ticket 3b043dfc). Nesting is the ONLY thing that separates
        /// the `threads` event's top-level "stopped" — a thread id — from a row's own "stopped" boolean, so
        /// asking the question by name alone would answer about the wrong member.</summary>
        private static bool HasTopLevelMember(string json, string name) { return TopLevelValueAt(json, name) >= 0; }

        /// <summary>Is the TOP-level member <paramref name="name"/> there with exactly the value
        /// <paramref name="valueJson"/>, written as JSON (a string with its quotes)? A nested row's member of
        /// the same name does not count.</summary>
        private static bool TopLevelMemberIs(string json, string name, string valueJson)
        {
            int at = TopLevelValueAt(json, name);
            if (at < 0 || string.CompareOrdinal(json, at, valueJson, 0, valueJson.Length) != 0) return false;
            int end = at + valueJson.Length;
            return end == json.Length || json[end] == ',' || json[end] == '}';
        }

        /// <summary>Where the value of the top-level member <paramref name="name"/> starts, or -1. Strings are
        /// skipped whole, because values like "{…}" and names like "[1]" carry brackets.</summary>
        private static int TopLevelValueAt(string json, string name)
        {
            string needle = "\"" + name + "\":";
            int depth = 0;
            bool inStr = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inStr) { if (c == '\\') i++; else if (c == '"') inStr = false; continue; }
                if (c == '"')
                {
                    if (depth == 1 && string.CompareOrdinal(json, i, needle, 0, needle.Length) == 0)
                        return i + needle.Length;
                    inStr = true; continue;
                }
                if (c == '{' || c == '[') depth++;
                else if (c == '}' || c == ']') depth--;
            }
            return -1;
        }
    }
}
