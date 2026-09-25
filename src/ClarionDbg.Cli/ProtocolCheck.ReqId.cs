using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// Watch and module-data replies name the request they answer (C1, wave 7, 3517fd15 #1). The host mints an
        /// edit grant only from a reply to an id it still holds, so every reply shape must carry the id, and one
        /// without a request id must be the reply it always was. Drives the REAL handlers through their seams on
        /// the attribution blob (no process): a found watch, a miss, an ambiguous name (the watch error shape),
        /// and the empty moduledata reply; then the shared trailing-id parser's refusals, which `stack` uses too.
        ///
        /// NOT COVERED here: the out-of-scope miss and the path-walk failures, which need a stack to reach. They
        /// emit through the same EmitWatchEvent, and tools/test-engine-reqid-sites.ps1 asserts that no watch
        /// event in DebugEngine.Watch.cs is emitted any other way.
        /// </summary>
        private static void CheckWatchAndModuleDataReqId(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a watch carrying reqid=N answers with \"reqId\":\"N\" as the last member whether it is found, "
                         + "missed or ambiguous, and so do `moduledata reqid=N` and `moddata reqid=N`; without an id none "
                         + "of them carries a reqId member and each is the same reply less the id; a non-numeric, empty, "
                         + "signed or 11-digit id, or one that is not the last token, is an error naming the grammar and "
                         + "no watch or moduledata reply is sent; an id never carries into the next watch.");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildAttributionBlob(), 0, 0x0F00, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("reqid: the fixture blob did not parse - " + ex.Message); return; }

            Func<string, string> watch = rest =>
            {
                var eng = NewEngine();
                eng.EmitJson = true;
                return CaptureConsole(() => eng.WatchWithImageForTest(dbg, "attr.exe", rest));
            };
            Func<string, string> moddata = line =>
            {
                var eng = NewEngine();
                eng.EmitJson = true;
                return CaptureConsole(() => eng.ModuleDataForTest(line, 4812));
            };
            Func<string, string, string> eventLine = (outp, evt) =>
            {
                foreach (var l in outp.Split('\n'))
                    if (l.StartsWith("@JSON ", StringComparison.Ordinal) && l.Contains("\"event\":\"" + evt + "\"")) return l.Trim();
                return null;
            };
            Func<string, string, string> plusId = (plain, id) => plain.Substring(0, plain.Length - 1) + ",\"reqId\":\"" + id + "\"}";

            // name -> what the reply must say besides the id
            var shapes = new[]
            {
                new[] { "A.CLW!ORDERS$ORD:RECORD", "\"found\":true" },
                new[] { "NO_SUCH_NAME", "\"found\":false" },
                new[] { "ORDERS$ORD:RECORD", "\"error\":\"ambiguous: " },
            };
            foreach (var sh in shapes)
            {
                string with = eventLine(watch(sh[0] + " reqid=7"), "watch");
                string plain = eventLine(watch(sh[0]), "watch");
                if (plain == null || !plain.Contains(sh[1]) || plain.Contains("reqId"))
                    failures.Add("reqid: a plain `watch " + sh[0] + "` must answer (" + sh[1] + ") with no reqId member: " + (plain ?? "no watch reply"));
                else if (with == null || with != plusId(plain, "7"))
                    failures.Add("reqid: `watch " + sh[0] + " reqid=7` must be the plain reply with \"reqId\":\"7\" last: "
                                 + (with ?? "no watch reply") + " vs " + plain);
            }

            foreach (var verb in new[] { "moduledata", "moddata" })
            {
                string with = eventLine(moddata(verb + " reqid=4294967295"), "moduledata");
                string plain = eventLine(moddata(verb), "moduledata");
                if (plain == null || plain.Contains("reqId"))
                    failures.Add("reqid: a plain `" + verb + "` must answer with no reqId member: " + (plain ?? "no moduledata reply"));
                else if (with == null || with != plusId(plain, "4294967295"))
                    failures.Add("reqid: `" + verb + " reqid=4294967295` must be the plain reply with the id last: "
                                 + (with ?? "no moduledata reply") + " vs " + plain);
            }

            foreach (var bad in new[] { "reqid=x7", "reqid=", "reqid=12345678901", "reqid=-1" })
            {
                string o = watch("A.CLW!ORDERS$ORD:RECORD " + bad);
                string err = eventLine(o, "error");
                if (eventLine(o, "watch") != null || err == null || !err.Contains("watch: expected watch NAME [reqid=N]"))
                    failures.Add("reqid: `watch A.CLW!ORDERS$ORD:RECORD " + bad + "` must be refused naming the grammar, with no watch reply: " + o.Trim());
                o = moddata("moduledata " + bad);
                err = eventLine(o, "error");
                if (eventLine(o, "moduledata") != null || err == null || !err.Contains("moduledata: expected moduledata [reqid=N]"))
                    failures.Add("reqid: `moduledata " + bad + "` must be refused naming the grammar, with no reply: " + o.Trim());
            }
            string misplaced = watch("reqid=7 A.CLW!ORDERS$ORD:RECORD");
            if (eventLine(misplaced, "watch") != null || eventLine(misplaced, "error") == null)
                failures.Add("reqid: `watch reqid=7 NAME` (the id not last) must be refused: " + misplaced.Trim());
            misplaced = moddata("moduledata reqid=7 extra");
            if (eventLine(misplaced, "moduledata") != null || eventLine(misplaced, "error") == null)
                failures.Add("reqid: `moduledata reqid=7 extra` (the id not last) must be refused: " + misplaced.Trim());
            // One engine, two requests: an id is the answer to ITS request only, never carried into the next.
            {
                var eng = NewEngine();
                eng.EmitJson = true;
                CaptureConsole(() => eng.WatchWithImageForTest(dbg, "attr.exe", "NO_SUCH_NAME reqid=9"));
                string next = eventLine(CaptureConsole(() => eng.WatchWithImageForTest(dbg, "attr.exe", "NO_SUCH_NAME")), "watch");
                if (next == null || next.Contains("reqId"))
                    failures.Add("reqid: a plain watch after `watch ... reqid=9` on the same engine carried an id: " + (next ?? "no watch reply"));
            }
            string noName = watch("reqid=7");
            if (eventLine(noName, "watch") != null || eventLine(noName, "error") == null)
                failures.Add("reqid: `watch reqid=7` (no name) must be refused: " + noName.Trim());
        }
    }
}
