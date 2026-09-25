using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    // Contract C3, wave 7: run to cursor arms every image. See DebugEngine.Breakpoints.cs (AddBreakpoint,
    // ResolvePendingFor, RemoveBreakpoint), and ProtocolCheck.cs for the claim registry and NewEngine.
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// Run to cursor, as the host sends it from wave 7: `bp add module:line` with no |one=1, then `bp del
        /// module:line` at the stop. Two known images carry the compiland, so the add arms in both, with a bp-set
        /// echo naming each image; a third that maps later gets its own copy and echo; the del removes all three
        /// and echoes one bp-del per copy, each with that copy's ownerPath, which is what the host matches a
        /// removal on. |one=1 is still parsed: it arms one image and a later image gets no copy.
        ///
        /// The images are TSWD blobs protocolcheck builds (<see cref="BuildAttributionBlob"/>) at load base 0,
        /// i.e. known but not mapped, as a solution DLL is before launch: breakpoints BIND to them and nothing is
        /// written to any process. NOT COVERED: planting, and a stop in the second image, which need a live
        /// two-DLL debuggee.
        /// </summary>
        private static void CheckRunToCursorArmsEveryImage(List<string> failures, ClaimLog claims)
        {
            const string One = @"C:\App\one.dll", Two = @"C:\App\two.dll", Three = @"C:\App\three.dll", Four = @"C:\App\four.dll";
            Func<TswdDebugInfo> blob = () => new TswdDebugInfo(BuildAttributionBlob(), 0, 0x0F00, 0x2000, 0x10000);

            DebugEngine eng;
            try
            {
                eng = NewEngine();
                eng.EmitJson = true;
                eng.AddImageForTest(One, blob(), 0);
                eng.AddImageForTest(Two, blob(), 0);
            }
            catch (Exception ex) { failures.Add("run to cursor: the fixture images did not build - " + ex.Message); return; }

            Func<string, string, string[], string> echoes = (log, evt, paths) =>
            {
                // Each image's echo exactly once, and no echo of this kind for any other image.
                var bad = new List<string>();
                int total = 0;
                foreach (var line in log.Split('\n'))
                    if (line.StartsWith("@JSON ") && line.IndexOf("\"event\":\"" + evt + "\"", StringComparison.Ordinal) >= 0) total++;
                foreach (var p in paths)
                {
                    int n = 0;
                    foreach (var line in log.Split('\n'))
                        if (line.StartsWith("@JSON ") && line.IndexOf("\"event\":\"" + evt + "\"", StringComparison.Ordinal) >= 0
                            && line.IndexOf("\"ownerPath\":" + Json.Str(p), StringComparison.Ordinal) >= 0) n++;
                    if (n != 1) bad.Add(n + " " + evt + " echo(es) for " + p);
                }
                if (total != paths.Length) bad.Add(total + " " + evt + " echo(es) in all, expected " + paths.Length);
                return bad.Count == 0 ? null : string.Join("; ", bad);
            };
            Func<string[], string> bps = want =>
            {
                var got = eng.BpsForTest();
                got.Sort(StringComparer.Ordinal);
                var w = new List<string>(want);
                w.Sort(StringComparer.Ordinal);
                return string.Join(" ", got) == string.Join(" ", w) ? null
                     : "[" + string.Join(" ", got) + "], expected [" + string.Join(" ", w) + "]";
            };

            // The add: every known image carrying A.CLW.
            string log = CaptureConsole(() => eng.BpCommandForTest("bp add A.CLW:5"));
            string e = bps(new[] { "A.CLW:5@" + One, "A.CLW:5@" + Two });
            if (e != null) failures.Add("run to cursor: an unqualified add bound " + e);
            e = echoes(log, "bp-set", new[] { One, Two });
            if (e != null) failures.Add("run to cursor: the add echoed " + e);

            // A third image maps after the add: it gets a copy of its own.
            var three = eng.AddImageForTest(Three, blob(), 0);
            log = CaptureConsole(() => eng.ImageMappedForTest(three));
            e = bps(new[] { "A.CLW:5@" + One, "A.CLW:5@" + Two, "A.CLW:5@" + Three });
            if (e != null) failures.Add("run to cursor: after a late image mapped the breakpoints are " + e);
            e = echoes(log, "bp-set", new[] { Three });
            if (e != null) failures.Add("run to cursor: the late image's copy echoed " + e);

            // The del at the stop: every copy, the late one included, one matchable echo each.
            log = CaptureConsole(() => eng.BpCommandForTest("bp del A.CLW:5"));
            e = bps(new string[0]);
            if (e != null) failures.Add("run to cursor: after the del the breakpoints are " + e);
            e = echoes(log, "bp-del", new[] { One, Two, Three });
            if (e != null) failures.Add("run to cursor: the del echoed " + e);

            // |one=1 is still parsed, and still means one image, with no copy for a later one.
            log = CaptureConsole(() => eng.BpCommandForTest("bp add A.CLW:5|one=1"));
            if (eng.BpsForTest().Count != 1)
                failures.Add("run to cursor: `bp add A.CLW:5|one=1` bound " + eng.BpsForTest().Count + " breakpoint(s), expected 1");
            var four = eng.AddImageForTest(Four, blob(), 0);
            CaptureConsole(() => eng.ImageMappedForTest(four));
            if (eng.BpsForTest().Count != 1)
                failures.Add("run to cursor: a single-target breakpoint was copied into a later image ("
                             + string.Join(" ", eng.BpsForTest()) + ")");
            CaptureConsole(() => eng.BpCommandForTest("bp del A.CLW:5"));
            if (eng.BpsForTest().Count != 0)
                failures.Add("run to cursor: the del left " + string.Join(" ", eng.BpsForTest()));

            claims.Claim("run to cursor as sent from wave 7 (`bp add module:line`, no |one=1) binds in every known image "
                         + "carrying the compiland and in one that maps later, echoing bp-set per image; `bp del module:line` "
                         + "removes every copy, the late one included, with one bp-del per copy naming its ownerPath; |one=1 "
                         + "still binds one image and is not copied into a later one.");
        }
    }
}
