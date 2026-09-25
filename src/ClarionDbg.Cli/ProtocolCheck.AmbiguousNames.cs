using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The qualified-name grammar <c>[image!][module!]name</c> (04d7b4c8), through the two splitters the watch
        /// path uses. The qualifiers must come off BEFORE the '.' member split: an image qualifier has its own
        /// '.', and the page asks for a watch's children as "&lt;watch name&gt;.&lt;MEMBER&gt;" (debugger.html
        /// childWatchPath), so the engine receives CLBRWS.EXE!CUS:RECORD.CUS:NAME.
        /// </summary>
        private static void CheckQualifiedNameParsing(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a data name's image!/module! qualifiers come off before the '.' member split: a qualified name, "
                         + "a qualified name with a .MEMBER child, a module-only qualifier with a child, and a two-qualifier "
                         + "path split as written, an unqualified dotted path is unchanged, and an empty part or a third "
                         + "qualifier is refused.");

            Action<string, string, string, string> name = (spec, q1, q2, rest) =>
            {
                string a, b, r;
                bool ok = DebugEngine.ParseQualified(spec, out a, out b, out r);
                if (!ok || a != q1 || b != q2 || r != rest)
                    failures.Add("qualified name: " + spec + " parsed as " + (ok ? "[" + (a ?? "-") + "][" + (b ?? "-") + "] " + r : "refused")
                                 + ", expected [" + (q1 ?? "-") + "][" + (q2 ?? "-") + "] " + rest);
            };
            Action<string, string, string, string, string> path = (spec, q1, q2, head, members) =>
            {
                string a, b, h, m;
                bool ok = DebugEngine.SplitWatchPath(spec, out a, out b, out h, out m);
                if (!ok || a != q1 || b != q2 || h != head || m != members)
                    failures.Add("qualified path: " + spec + " split as " + (ok ? "[" + (a ?? "-") + "][" + (b ?? "-") + "] " + h + " | " + m : "not a path")
                                 + ", expected [" + (q1 ?? "-") + "][" + (q2 ?? "-") + "] " + head + " | " + members);
            };

            name("CLBRWS.EXE!CUS:RECORD", "CLBRWS.EXE", null, "CUS:RECORD");                          // (a)
            path("CLBRWS.EXE!CUS:RECORD.CUS:NAME", "CLBRWS.EXE", null, "CUS:RECORD", ".CUS:NAME");     // (b)
            path("filescope_a.clw!ORDERS$ORD:RECORD.ORD:ITEM", "filescope_a.clw", null, "ORDERS$ORD:RECORD", ".ORD:ITEM"); // (c)
            path("CUS:RECORD.CUS:NAME", null, null, "CUS:RECORD", ".CUS:NAME");                        // (d)
            path("app.exe!a.clw!G.INNER.LEAF", "app.exe", "a.clw", "G", ".INNER.LEAF");
            name("app.exe!a.clw!X", "app.exe", "a.clw", "X");
            name("JOB:JOBID", null, null, "JOB:JOBID");

            // Not a path: no member after the qualifiers, however many '.' the qualifiers hold.
            string q1, q2, h, mm;
            if (DebugEngine.SplitWatchPath("CLBRWS.EXE!CUS:NAME", out q1, out q2, out h, out mm))
                failures.Add("qualified path: CLBRWS.EXE!CUS:NAME was split as a path at the image's own '.'");
            foreach (var bad in new[] { "a!!b", "!x", "x!", "a!b!c!d", "" })
            {
                string r;
                if (DebugEngine.ParseQualified(bad, out q1, out q2, out r))
                    failures.Add("qualified name: '" + bad + "' was accepted");
            }
        }

        /// <summary>
        /// Two genuine FILE records answering to one name FAIL CLOSED (04d7b4c8, Owner decision 2). The index keeps
        /// every one (RegisterDataName, list form), and the engine's rule (ChooseData) answers "ambiguous" with
        /// no location, listing each candidate as the user can watch it. The same fixture's
        /// real image, tools/fixtures/filescope, is driven by tools/test-engine-filescope.ps1.
        /// </summary>
        private static void CheckAmbiguousFileRecordsFailClosed(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a name that two genuine FILE records answer to, in one image or across images, keeps both in the "
                         + "index and resolves to AMBIGUOUS with no location, listing image!, module! or record-path forms "
                         + "that a qualifier then resolves; a HISTORY:: copy, a static, or one file record among other "
                         + "names still resolves to one, EXE first. Through the real handlers on a parsed image: a watch "
                         + "of the name or of a path through it is an error with no value, address or edit metadata; "
                         + "`sym` gives no address, a condition reads it as unreadable, a thread scan records the message.");

            // ---- the index keeps both FILE records, and only them ----
            var fileA = new TswdDebugInfo.DataLocation { Rva = 0x30B4, Container = "ORDERS$ORD:RECORD", ModuleIdx = 1 };
            var fileB = new TswdDebugInfo.DataLocation { Rva = 0x30D4, Container = "ORDERS$ORD:RECORD", ModuleIdx = 2 };
            var hist  = new TswdDebugInfo.DataLocation { Rva = 0x30C0, Container = "HISTORY::ORD:RECORD", ModuleIdx = 1 };
            var stat  = new TswdDebugInfo.DataLocation { Rva = 0x4000, Container = null };
            Func<string, TswdDebugInfo.DataLocation[], string> held = (key, order) =>
            {
                var index = new Dictionary<string, List<TswdDebugInfo.DataLocation>>(StringComparer.OrdinalIgnoreCase);
                foreach (var l in order) TswdDebugInfo.RegisterDataName(index, key, l);
                var rvas = new List<string>();
                foreach (var l in index[key]) rvas.Add("0x" + l.Rva.ToString("X"));
                return string.Join(",", rvas);
            };
            Action<string, string, TswdDebugInfo.DataLocation[], string> expectHeld = (what, key, order, want) =>
            {
                string got = held(key, order);
                if (got != want) failures.Add("ambiguous index: " + what + " held [" + got + "], expected [" + want + "]");
            };
            expectHeld("two FILE records", "ORD:ITEM", new[] { fileA, fileB }, "0x30B4,0x30D4");
            expectHeld("two FILE records, other order", "ORD:ITEM", new[] { fileB, fileA }, "0x30D4,0x30B4");
            expectHeld("a HISTORY:: copy between them", "ORD:ITEM", new[] { hist, fileA, fileB }, "0x30B4,0x30D4");
            expectHeld("a HISTORY:: copy after them", "ORD:ITEM", new[] { fileA, hist, fileB }, "0x30B4,0x30D4");
            expectHeld("the same FILE record twice", "ORD:ITEM", new[] { fileA, fileA }, "0x30B4");
            expectHeld("a static then a FILE record", "ORD:ITEM", new[] { stat, fileA }, "0x4000");
            // The record symbols themselves: no container, and the NAME carries the shape.
            var recA = new TswdDebugInfo.DataLocation { Rva = 0x30B4 };
            var recB = new TswdDebugInfo.DataLocation { Rva = 0x30D4 };
            expectHeld("two record symbols of one name", "ORDERS$ORD:RECORD", new[] { recA, recB }, "0x30B4,0x30D4");
            expectHeld("two statics of one name", "SAVEDVALUE", new[] { recA, recB }, "0x30B4");
            // A record shape under a :: scope has the shape but ranks below the FILE record: never kept beside it.
            var scoped = new TswdDebugInfo.DataLocation { Rva = 0x5000, Container = "UPDATE::LOCAL$ORD:RECORD" };
            expectHeld("a scoped record shape after a FILE record", "ORD:ITEM", new[] { fileA, scoped }, "0x30B4");

            // ---- the engine's choice ----
            Func<string, string, string, bool, TswdDebugInfo.DataLocation, DebugEngine.DataCandidate> cand =
                (image, module, container, file, loc) =>
                {
                    loc.Container = container;
                    return new DebugEngine.DataCandidate { Image = image, Module = module, FileRecord = file, Loc = loc };
                };
            var inA = cand("filescope.exe", "filescope_a.clw", "ORDERS$ORD:RECORD", true, fileA);
            var inB = cand("filescope.exe", "filescope_b.clw", "ORDERS$ORD:RECORD", true, fileB);
            var inDll = cand("orders.dll", "orders.clw", "ORDERS$ORD:RECORD", true, new TswdDebugInfo.DataLocation { Rva = 0x9000 });
            var exeStatic = cand("filescope.exe", "filescope.clw", null, false, new TswdDebugInfo.DataLocation { Rva = 0x2000 });
            var outBuf = cand("clbrws.exe", "CWUTIL.CLW", "OUTFILE$OUTFILE@:RECORD", true, new TswdDebugInfo.DataLocation { Rva = 0xCE6C4 });
            var inBuf  = cand("clbrws.exe", "CWUTIL.CLW", "INFILE$INFILE@:RECORD", true, new TswdDebugInfo.DataLocation { Rva = 0xD66C8 });

            Action<string, string, DebugEngine.DataCandidate[], DebugEngine.DataResolve, uint, string> choose =
                (what, spec, cands, want, wantRva, wantMessage) =>
                {
                    string q1, q2, nm;
                    if (!DebugEngine.ParseQualified(spec, out q1, out q2, out nm)) { failures.Add("ambiguous choice: " + what + ": spec refused"); return; }
                    DebugEngine.DataCandidate c; string msg;
                    var r = DebugEngine.ChooseData(nm, q1, q2, cands, out c, out msg);
                    if (r != want)
                        failures.Add("ambiguous choice: " + what + " (" + spec + ") gave " + r + ", expected " + want);
                    else if (r == DebugEngine.DataResolve.Found && c.Loc.Rva != wantRva)
                        failures.Add("ambiguous choice: " + what + " (" + spec + ") chose 0x" + c.Loc.Rva.ToString("X") + ", expected 0x" + wantRva.ToString("X"));
                    else if (r == DebugEngine.DataResolve.Ambiguous && (c != null || msg != wantMessage))
                        failures.Add("ambiguous choice: " + what + " (" + spec + ") said \"" + msg + "\"" + (c != null ? " AND chose a location" : "")
                                     + ", expected \"" + wantMessage + "\"");
                };
            var Found = DebugEngine.DataResolve.Found; var Amb = DebugEngine.DataResolve.Ambiguous; var None = DebugEngine.DataResolve.NotFound;

            // One image, two modules: tools/fixtures/filescope's two procedure-local ORDERS files.
            choose("two modules", "ORD:ITEM", new[] { inA, inB }, Amb, 0,
                   "ambiguous: filescope_a.clw!ORD:ITEM, filescope_b.clw!ORD:ITEM - watch one of these");
            choose("module qualifier", "filescope_b.clw!ORD:ITEM", new[] { inA, inB }, Found, 0x30D4, null);
            choose("module qualifier by stem", "FILESCOPE_A!ORD:ITEM", new[] { inA, inB }, Found, 0x30B4, null);
            choose("image qualifier that does not settle it", "filescope.exe!ORD:ITEM", new[] { inA, inB }, Amb, 0,
                   "ambiguous: filescope.exe!filescope_a.clw!ORD:ITEM, filescope.exe!filescope_b.clw!ORD:ITEM - watch one of these");
            choose("image and module", "filescope.exe!filescope_a.clw!ORD:ITEM", new[] { inA, inB }, Found, 0x30B4, null);
            // Two images: no longer EXE-first. Their modules differ, and the module qualifier is preferred (3517fd15 #4).
            choose("two images", "ORD:ITEM", new[] { inA, inDll }, Amb, 0,
                   "ambiguous: filescope_a.clw!ORD:ITEM, orders.clw!ORD:ITEM - watch one of these");
            choose("image qualifier", "orders.dll!ORD:ITEM", new[] { inA, inDll }, Found, 0x9000, null);
            // One module, two records: named through each record, as a watch path.
            choose("one module", "BUFFER", new[] { outBuf, inBuf }, Amb, 0,
                   "ambiguous: CWUTIL.CLW!OUTFILE$OUTFILE@:RECORD.BUFFER, CWUTIL.CLW!INFILE$INFILE@:RECORD.BUFFER - watch one of these");
            // Unchanged: not two FILE records.
            choose("one FILE record", "ORD:ITEM", new[] { inA }, Found, 0x30B4, null);
            choose("an EXE static before a DLL file record", "ORD:ITEM", new[] { exeStatic, inDll }, Found, 0x2000, null);
            choose("a qualifier nothing matches", "nope.clw!ORD:ITEM", new[] { inA, inB }, None, 0, null);
            choose("nothing", "ORD:ITEM", new DebugEngine.DataCandidate[0], None, 0, null);

            // ---- the real watch handler, over a parsed image holding two ORDERS$ORD:RECORD symbols ----
            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildAttributionBlob(), 0, 0x0F00, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("ambiguous watch: the fixture blob did not parse - " + ex.Message); return; }
            Action<string, string> watch = (spec, want) =>
            {
                var eng = NewEngine();
                eng.EmitJson = true;
                string outp = CaptureConsole(() => eng.WatchWithImageForTest(dbg, "attr.exe", spec));
                // The wire: a watch event, found false, carrying the message as its error.
                string wire = "\"found\":false,\"error\":" + Json.Str(want);
                if (outp.IndexOf("  watch " + spec + ": " + want, StringComparison.Ordinal) < 0 || outp.IndexOf(wire, StringComparison.Ordinal) < 0)
                    failures.Add("ambiguous watch: " + spec + " did not answer \"" + want + "\"; it printed: " + outp.Trim());
                else if (outp.IndexOf("\"value\"", StringComparison.Ordinal) >= 0 || outp.IndexOf("\"addr\"", StringComparison.Ordinal) >= 0
                         || outp.IndexOf("\"editable\"", StringComparison.Ordinal) >= 0)
                    failures.Add("ambiguous watch: " + spec + " sent a value, an address or edit metadata: " + outp.Trim());
            };
            watch("ORDERS$ORD:RECORD", "ambiguous: A.CLW!ORDERS$ORD:RECORD, C.CLW!ORDERS$ORD:RECORD - watch one of these");
            watch("ORDERS$ORD:RECORD.ORD:ITEM", "ambiguous: A.CLW!ORDERS$ORD:RECORD.ORD:ITEM, C.CLW!ORDERS$ORD:RECORD.ORD:ITEM - watch one of these");

            // ---- the other three callers: `sym` gives no address, a condition reads it as unreadable (0), and a
            // thread scan records the message rather than a value ----
            {
                const string amb = "ambiguous: A.CLW!ORDERS$ORD:RECORD, C.CLW!ORDERS$ORD:RECORD - watch one of these";
                var eng = NewEngine();
                eng.EmitJson = true;
                string outp;
                try { outp = CaptureConsole(() => eng.DataCallersWithImageForTest(dbg, "attr.exe", "ORDERS$ORD:RECORD")); }
                catch (Exception ex) { failures.Add("ambiguous callers: threw " + ex.GetType().Name + " - " + ex.Message); outp = null; }
                if (outp != null)
                {
                    if (outp.IndexOf("  sym ORDERS$ORD:RECORD: " + amb, StringComparison.Ordinal) < 0
                        || outp.IndexOf(Json.Sym("ORDERS$ORD:RECORD", false, 0, 0, 0, null, 0, null), StringComparison.Ordinal) < 0)
                        failures.Add("ambiguous callers: sym did not answer not-found with the message: " + outp.Trim());
                    if (outp.IndexOf("condition: 0", StringComparison.Ordinal) < 0)
                        failures.Add("ambiguous callers: a condition did not read the name as unreadable (0): " + outp.Trim());
                    if (outp.IndexOf("probe: (" + amb + ")", StringComparison.Ordinal) < 0)
                        failures.Add("ambiguous callers: a thread scan did not record the message: " + outp.Trim());
                }
            }
        }
    }
}
