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
    /// </summary>
    internal static class ProtocolCheck
    {
        internal static int Run()
        {
            var failures = new List<string>();

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

            CheckHandBuiltTidEmitters(failures);
            CheckResumeVerbs(failures);
            CheckStepGuards(failures);
            CheckEditVeto(failures);
            CheckThreadedWriteGuard(failures);

            foreach (var f in failures) Console.WriteLine("  FAIL  " + f);
            if (failures.Count == 0)
            {
                Console.WriteLine($"protocolcheck: {shapes.Length} spliced event shapes + all 4 hand-built "
                                  + "emitters OK - a known tid is stamped, "
                                  + "an unknown tid is absent (never 0 or -1); a vetoed row's INLINE "
                                  + "descendants offer no edit metadata (the expand path is a known gap — "
                                  + "see HandleExpandCommand, ticket cc3ac96e); no write, of any length, "
                                  + "can touch the shared template; the resume-verb set has one owner across "
                                  + "its 2 remaining sites; and Step Over's ESP gate and its prologue bypass "
                                  + "each hold with the other one out of the way.");
                return 0;
            }
            Console.WriteLine($"protocolcheck: {failures.Count} failure(s).");
            return 1;
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
        private static void CheckHandBuiltTidEmitters(List<string> failures)
        {
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
        private static void CheckResumeVerbs(List<string> failures)
        {
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
            string[] handledWhileRunning = { "pause", "break", "bp", "sym", "thread", "quit", "q", "kill" };
            foreach (var v in handledWhileRunning)
                if (DebugEngine.IsResumeVerbForTest(v))
                    failures.Add("resume verbs: '" + v + "' is handled by the running-state switch, but "
                                 + "IsResumeVerb accepts it — it would be diverted and never reach its case");

            // Verbs that are paused-only but NOT resume verbs: they must still fall to the switch's own
            // "only valid while paused" case, not the hoisted one. Same error text today, but they are a
            // different set and must not be absorbed into this one.
            string[] pausedOnlyReads = { "mem", "regs", "stack", "watch", "locals", "moduledata", "disasm",
                                         "setval", "threads", "threadscan", "framelocals", "libstate", "expand" };
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
        /// These cannot be produced against a live debuggee for the same reason the tid rule cannot: the
        /// case that matters is the one that does NOT happen on a normal run. A Step Over only reaches the
        /// ESP gate at all on StepMachine's documented "couldn't plant — fall through and keep
        /// instruction-stepping" path, which needs a return address the debugger cannot write a byte to.
        ///
        /// Isolation is the point, not coverage. A guard that is only ever exercised alongside another guard
        /// covering the same case is a DEAD guard whose test still passes — this repo shipped exactly that
        /// (armPendingSweep's `!isPaused` clause, dead to its test because a real resume also bumped the
        /// switch generation). So each case below moves ONE input and leaves the rest where a real step
        /// would have them.
        /// </summary>
        private static void CheckStepGuards(List<string> failures)
        {
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

        /// <summary>A row-bearing event must carry the one KNOWN tid it was given and neither sentinel.
        /// Feeding the builder a known tid alongside 0 and (uint)-1 in the SAME event is the point: it
        /// asserts the rule is applied per row, not decided once for the whole event.</summary>
        private static void CheckNoSentinelRows(List<string> failures, string name, string json, uint known)
        {
            if (Count(json, "\"tid\":" + known) != 1)
                failures.Add(name + " control: the one known tid was not written exactly once — " + json);
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
        private static void CheckEditVeto(List<string> failures)
        {
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
        private static void CheckThreadedWriteGuard(List<string> failures)
        {
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
        private static bool HasTopLevelTid(string json)
        {
            int depth = 0;
            bool inStr = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inStr) { if (c == '\\') i++; else if (c == '"') inStr = false; continue; }
                if (c == '"')
                {
                    if (depth == 1 && string.CompareOrdinal(json, i, "\"tid\":", 0, 6) == 0) return true;
                    inStr = true; continue;
                }
                if (c == '{' || c == '[') depth++;
                else if (c == '}' || c == ']') depth--;
            }
            return false;
        }
    }
}
