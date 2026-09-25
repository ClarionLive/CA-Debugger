using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// A breakpoint condition over an ambiguous name says it is ambiguous (3517fd15 item 4), and a qualified
        /// watch never asks the stack for a local (item 7). Through the REAL condition gate and watch handler on
        /// the attribution blob, whose A.CLW and C.CLW each hold an ORDERS$ORD:RECORD.
        ///
        /// NOT COVERED: an ambiguous name on the RIGHT of the operator, which is read only after the left side
        /// reads, and nothing reads without a process; it goes through the same ReadVarValue overload.
        /// Nor a qualified watch on a live stack: the seam has no thread context, so the lookup it counts is the
        /// call, which is what the qualifier must prevent; what a stack would have answered is not asked.
        /// </summary>
        private static void CheckConditionAmbiguityAndQualifiedWatch(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a breakpoint condition naming a record two FILE records answer to pauses and prints the "
                         + "ambiguity message, while an unknown name still prints the "
                         + "plain could-not-be-evaluated line; a watch qualified with image! or module! makes no local "
                         + "lookup, and an unqualified one makes exactly one.");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildAttributionBlob(), 0, 0x0F00, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("condition ambiguity: the fixture blob did not parse - " + ex.Message); return; }

            const string amb = "ambiguous: A.CLW!ORDERS$ORD:RECORD, C.CLW!ORDERS$ORD:RECORD - watch one of these";
            Func<string, string> gate = cond =>
            {
                var eng = NewEngine();
                return CaptureConsole(() => eng.ConditionWithImageForTest(dbg, "attr.exe", cond));
            };
            foreach (var cond in new[] { "ORDERS$ORD:RECORD = 1", "ORDERS$ORD:RECORD <> 'x'" })
            {
                string o = gate(cond);
                if (o.IndexOf("condition '" + cond + "' could not be evaluated (" + amb + ")", StringComparison.Ordinal) < 0
                    || o.IndexOf("pause: True", StringComparison.Ordinal) < 0)
                    failures.Add("condition ambiguity: `" + cond + "` did not pause with the ambiguity message: " + o.Trim());
            }
            string unknown = gate("NO_SUCH_NAME = 1");
            if (unknown.IndexOf("condition 'NO_SUCH_NAME = 1' could not be evaluated — pausing", StringComparison.Ordinal) < 0)
                failures.Add("condition ambiguity: an unknown name must print the plain line, with no reason: " + unknown.Trim());

            Action<string, int> lookups = (name, want) =>
            {
                var eng = NewEngine();
                eng.EmitJson = true;
                CaptureConsole(() => eng.WatchWithImageForTest(dbg, "attr.exe", name));
                if (eng.LocalLookupsForTest != want)
                    failures.Add("qualified watch: `watch " + name + "` asked the stack for a local " + eng.LocalLookupsForTest
                                 + " time(s), expected " + want);
            };
            lookups("A.CLW!ORDERS$ORD:RECORD", 0);
            lookups("attr.exe!NO_SUCH_NAME", 0);
            lookups("attr.exe!A.CLW!NO_SUCH_NAME", 0);
            lookups("NO_SUCH_NAME", 1);       // control: the counter counts
        }
    }
}
