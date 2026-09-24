using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The stack reply names the request it answers (49538b78 wave 5 run 3, codex security + adversary).
        /// The host proves a stack reply fresh by its id, not by counting: a stale reply for the SAME thread
        /// carries the same tid, and only the id it echoes tells it apart. Drives the REAL HandleStackCommand
        /// through its seam (no target, so the walk is frame 0 alone) and the argument parser behind it.
        ///
        /// NOT COVERED: the host side (tools/test-addin-json.ps1 drives the id set).
        /// </summary>
        private static void CheckStackReqIdEcho(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a stack request carrying reqid=N is answered with \"reqId\":\"N\", and one without carries no "
                         + "reqId member; `stack`, `stack 20`, `stack reqid=7` and `stack 20 reqid=7` parse, while a "
                         + "non-numeric, empty or 11-digit id, an id before the count, or a trailing token is refused. "
                         + "Not covered: the host's id set.");

            Func<string, string> reply = line =>
            {
                var eng = NewEngine();
                eng.EmitJson = true;
                string outp = CaptureConsole(() => eng.HandleStackCommandForTest(line, 4812));
                foreach (var l in outp.Split('\n'))
                    if (l.StartsWith("@JSON ", StringComparison.Ordinal) && l.Contains("\"event\":\"stack\"")) return l.Trim();
                return null;
            };
            string withId = reply("stack reqid=7");
            if (withId == null || !withId.Contains("\"event\":\"stack\",\"reqId\":\"7\",\"frames\":["))
                failures.Add("stack reqid: `stack reqid=7` must answer with \"reqId\":\"7\" ahead of the frames: " + (withId ?? "no stack reply"));
            string withCount = reply("bt 5 reqid=12");
            if (withCount == null || !withCount.Contains("\"reqId\":\"12\""))
                failures.Add("stack reqid: `bt 5 reqid=12` must echo \"reqId\":\"12\": " + (withCount ?? "no stack reply"));
            string plain = reply("stack");
            if (plain == null || plain.Contains("reqId"))
                failures.Add("stack reqid: a plain `stack` must answer with no reqId member: " + (plain ?? "no stack reply"));

            Action<string, bool, int, string> parse = (line, ok, wantMax, wantId) =>
            {
                int max; string id, err;
                bool got = DebugEngine.TryParseStackArgs(line.Split(' '), out max, out id, out err);
                if (got != ok || (ok && (max != wantMax || id != wantId)))
                    failures.Add("stack args: `" + line + "`: got ok=" + got + " max=" + max + " reqId=" + (id ?? "null")
                                 + (err != null ? " (" + err + ")" : "") + ", expected ok=" + ok
                                 + (ok ? " max=" + wantMax + " reqId=" + (wantId ?? "null") : ""));
            };
            parse("stack", true, 32, null);
            parse("stack 20", true, 20, null);
            parse("stack reqid=7", true, 32, "7");
            parse("where 20 reqid=4294967295", true, 20, "4294967295");
            parse("stack reqid=x7", false, 0, null);
            parse("stack reqid=", false, 0, null);
            parse("stack reqid=12345678901", false, 0, null);
            parse("stack reqid=7 20", false, 0, null);
            parse("stack 20 reqid=7 junk", false, 0, null);
            parse("stack 0", false, 0, null);
        }
    }
}
