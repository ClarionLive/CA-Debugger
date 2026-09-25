using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The host names the frame count on every stack request (97f23f5d): `stack 32 reqid=N`, so an engine
        /// from before wave 5, which reads the first argument as the count and ignores a trailing token, still
        /// answers. The count it names is the host's ClarionDebuggerService.StackFrameCount, meant to equal this
        /// engine's default so that naming it changes nothing here. This check pins the ENGINE half of that
        /// pair; tools/test-addin-json.ps1 pins the host's constant at the same 32. Change one, change both.
        ///
        /// NOT COVERED: the host constant itself (tools/test-addin-json.ps1), and a pre-wave-5 engine binary.
        /// </summary>
        private static void CheckStackFrameCountSkew(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the engine's default stack frame count is 32, the count the host names on every stack "
                         + "request, and `stack 32 reqid=N` parses to that count and id and is answered with the id. "
                         + "Not covered: the host constant, and an older engine binary.");

            const int HostStackFrameCount = 32;   // ClarionDebuggerService.StackFrameCount
            int max; string id, err;
            if (!DebugEngine.TryParseStackArgs("stack".Split(' '), out max, out id, out err) || max != HostStackFrameCount)
                failures.Add("stack frame count: a bare `stack` must walk " + HostStackFrameCount
                             + " frames, the count the host names, but walks " + max + (err != null ? " (" + err + ")" : ""));

            string line = "stack " + HostStackFrameCount + " reqid=7";
            if (!DebugEngine.TryParseStackArgs(line.Split(' '), out max, out id, out err) || max != HostStackFrameCount || id != "7")
                failures.Add("stack frame count: `" + line + "` must parse to max=" + HostStackFrameCount + " reqId=7, got max="
                             + max + " reqId=" + (id ?? "null") + (err != null ? " (" + err + ")" : ""));

            var eng = NewEngine();
            eng.EmitJson = true;
            string outp = CaptureConsole(() => eng.HandleStackCommandForTest(line, 4812));
            string reply = null;
            foreach (var l in outp.Split('\n'))
                if (l.StartsWith("@JSON ", StringComparison.Ordinal) && l.Contains("\"event\":\"stack\"")) { reply = l.Trim(); break; }
            if (reply == null || !reply.Contains("\"reqId\":\"7\""))
                failures.Add("stack frame count: `" + line + "` must be answered with \"reqId\":\"7\": " + (reply ?? "no stack reply"));
        }
    }
}
