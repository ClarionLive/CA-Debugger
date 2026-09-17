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
            string neg = DebugEngine.WithTidForTest(shapes[0], unchecked((uint)-1));
            if (neg.IndexOf("\"tid\":-1", StringComparison.Ordinal) >= 0)
                failures.Add("paused: a -1 sentinel reached the wire");

            // 4. A thread-scoped event with no payload is still well-formed JSON when stamped.
            if (DebugEngine.WithTidForTest("{}", 42) != "{\"tid\":42}")
                failures.Add("empty object: stamping produced malformed JSON");

            CheckEditVeto(failures);

            foreach (var f in failures) Console.WriteLine("  FAIL  " + f);
            if (failures.Count == 0)
            {
                Console.WriteLine($"protocolcheck: {shapes.Length} event shapes OK - a known tid is stamped, "
                                  + "an unknown tid is absent (never 0 or -1); and a vetoed row offers no "
                                  + "editable descendant.");
                return 0;
            }
            Console.WriteLine($"protocolcheck: {failures.Count} failure(s).");
            return 1;
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
