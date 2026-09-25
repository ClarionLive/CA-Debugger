using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The forms an ambiguity message suggests can be pasted back as a watch (3517fd15 item 4). A form is only
        /// useful if the host accepts it (IsValidWatchName: letters, digits and _:$.!@-) AND the engine resolves it
        /// to the candidate it was offered for, so every suggested form here is fed back through the real
        /// <see cref="DebugEngine.ChooseData"/>. Hand-built candidates, as in CheckAmbiguousFileRecordsFailClosed.
        /// </summary>
        private static void CheckSuggestedNamesArePasteable(List<string> failures, ClaimLog claims)
        {
            claims.Claim("an ambiguity message names each candidate by its module when the modules tell them apart, by "
                         + "its image when only that does, and by both otherwise; it never suggests a form holding a "
                         + "character outside [A-Za-z0-9_:$.!@-] without saying no such form exists, and every form it "
                         + "does suggest resolves back to the candidate it names; `sym` lists only forms that can be typed "
                         + "and name one candidate.");

            Func<string, string, string, uint, DebugEngine.DataCandidate> cand = (image, module, container, rva) =>
                new DebugEngine.DataCandidate
                {
                    Image = image, Module = module, FileRecord = true,
                    Loc = new TswdDebugInfo.DataLocation { Rva = rva, Container = container },
                };

            // What the message says for these candidates, and that each suggested form, when the message
            // claims them all usable, round-trips to its own candidate.
            Action<string, DebugEngine.DataCandidate[], string> expect = (what, cands, want) =>
            {
                DebugEngine.DataCandidate c; string msg;
                var r = DebugEngine.ChooseData("ORD:ITEM", null, null, cands, out c, out msg);
                if (r != DebugEngine.DataResolve.Ambiguous || msg != want)
                {
                    failures.Add("pasteable names: " + what + " gave " + r + " \"" + msg + "\", expected \"" + want + "\"");
                    return;
                }
                string note;
                var forms = DebugEngine.AmbiguityForms("ORD:ITEM", false, new List<DebugEngine.DataCandidate>(cands), out note);
                if (note != null) return;
                for (int i = 0; i < forms.Count; i++)
                {
                    if (!DebugEngine.IsPasteableWatchName(forms[i]))
                        failures.Add("pasteable names: " + what + " suggested " + forms[i] + " with no note, and it cannot be pasted");
                    string q1, q2, rest;
                    if (!DebugEngine.ParseQualified(forms[i], out q1, out q2, out rest))
                    { failures.Add("pasteable names: " + what + ": " + forms[i] + " does not parse"); continue; }
                    // No case below is named through its record (the CWUTIL case in CheckAmbiguousFileRecordsFailClosed
                    // is), so each form is a qualified leaf.
                    DebugEngine.DataCandidate back; string m;
                    var r2 = DebugEngine.ChooseData(rest, q1, q2, cands, out back, out m);
                    if (r2 != DebugEngine.DataResolve.Found || back != cands[i])
                        failures.Add("pasteable names: " + what + ": " + forms[i] + " does not resolve back to its own candidate (" + r2 + (m != null ? ", " + m : "") + ")");
                }
            };

            var exeA = cand("app.exe", "a.clw", "ORDERS$ORD:RECORD", 0x1000);
            var dllB = cand("orders.dll", "b.clw", "ORDERS$ORD:RECORD", 0x2000);
            var sameModA = cand("one.dll", "shared.clw", "ORDERS$ORD:RECORD", 0x3000);
            var sameModB = cand("two.dll", "shared.clw", "ORDERS$ORD:RECORD", 0x4000);
            var spacedA = cand("My App.exe", "shared.clw", "ORDERS$ORD:RECORD", 0x5000);
            var spacedB = cand("My Other.dll", "shared.clw", "ORDERS$ORD:RECORD", 0x6000);
            var hyphen = cand("app.exe", "order-entry.clw", "ORDERS$ORD:RECORD", 0x7000);
            var paren = cand("app.exe", "orders(1).clw", "ORDERS$ORD:RECORD", 0x8000);
            var parenDll = cand("orders.dll", "orders(1).clw", "ORDERS$ORD:RECORD", 0x9000);
            var spacedDllA = cand("My App.exe", "a.clw", "ORDERS$ORD:RECORD", 0xA000);

            expect("two images, two modules: the module alone", new[] { exeA, dllB },
                   "ambiguous: a.clw!ORD:ITEM, b.clw!ORD:ITEM - watch one of these");
            expect("two images, one module name: the image", new[] { sameModA, sameModB },
                   "ambiguous: one.dll!ORD:ITEM, two.dll!ORD:ITEM - watch one of these");
            expect("an image with a space, told apart by module: the module", new[] { spacedDllA, dllB },
                   "ambiguous: a.clw!ORD:ITEM, b.clw!ORD:ITEM - watch one of these");
            expect("a module with a hyphen is pasteable", new[] { hyphen, dllB },
                   "ambiguous: order-entry.clw!ORD:ITEM, b.clw!ORD:ITEM - watch one of these");
            expect("a module with a parenthesis: the image instead", new[] { paren, dllB },
                   "ambiguous: app.exe!ORD:ITEM, orders.dll!ORD:ITEM - watch one of these");
            expect("no pasteable form at all: said so", new[] { spacedA, spacedB },
                   "ambiguous: My App.exe!ORD:ITEM, My Other.dll!ORD:ITEM - watch one of these (some have no form a watch name can hold)");
            expect("one module name with a parenthesis, two images: the image", new[] { paren, parenDll },
                   "ambiguous: app.exe!ORD:ITEM, orders.dll!ORD:ITEM - watch one of these");

            // What `sym` lists: only forms that can be typed AND name one candidate.
            var listed = DebugEngine.PasteableForms(new List<string> { "a.clw!X", "My App.exe!X", "b.clw!R.X", "B.CLW!R.X", "c.clw!X" });
            if (string.Join(",", listed) != "a.clw!X,c.clw!X")
                failures.Add("pasteable names: sym's list kept [" + string.Join(",", listed) + "], expected [a.clw!X,c.clw!X]");

            foreach (var ok in new[] { "A.CLW!ORD:ITEM", "order-entry.clw!X", "OUTFILE$OUTFILE@:RECORD.BUFFER", "x_1" })
                if (!DebugEngine.IsPasteableWatchName(ok)) failures.Add("pasteable names: " + ok + " was refused");
            foreach (var bad in new[] { "My App.exe!X", "orders(1).clw!X", "a/b", "", "x\\y", "café" })
                if (DebugEngine.IsPasteableWatchName(bad)) failures.Add("pasteable names: '" + bad + "' was accepted");
        }
    }
}
