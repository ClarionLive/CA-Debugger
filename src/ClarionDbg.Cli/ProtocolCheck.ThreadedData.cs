using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The shared template-overlap rule over a SPAN, and the straddling discriminator derived from it
        /// (tickets 3c031cdc, ef0a941d). Drives the shipped TouchesThreadedTemplate and ClassifyTemplateSpan
        /// through their seams, over the same LoadedModule fields RegisterThreadedModuleForTest sets.
        ///
        /// WHAT THIS DOES NOT GUARD, stated here so a green run is not read as more than it is:
        ///  • that the module-data panel, Watch, the thread scan and breakpoint conditions CALL this rule.
        ///    A caller reverted to its own inline point test would still pass every line below.
        ///    tools/test-threaded-template-rule.ps1 guards that at SOURCE level only.
        ///  • what each caller DOES with a straddling answer — the panel's and Watch's "partly in the shared
        ///    ... template" note with editable=false, the scan's label, a condition answering indeterminate.
        ///    Reaching those arms needs a paused thread's CONTEXT, a real EIP in a mapped image, parsed TSWD
        ///    debug info and a DataSymbol whose Rva+Size crosses CwtlsLo; RegisterThreadedModuleForTest builds
        ///    a module with no m.Dbg at all. They belong on the live-target list, and this check does not
        ///    close them.
        /// </summary>
        private static void CheckTemplateSpanDiscriminator(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the shared template test works over a SPAN: a range starting below the .cwtls template "
                         + "and reaching in is TOUCHING it, at the template's first byte, and classifies as "
                         + "STRADDLING; one starting inside classifies as STARTS-INSIDE at its own start; one "
                         + "ending exactly at the template does not touch it. Not covered: that the four "
                         + "callers use this rule, or what each renders from the answer.");

            // An image mapped at 0x400000 whose .cwtls template block is RVA 0xC8000..0xCC000 — the same
            // shape CheckThreadedWriteGuard registers.
            var m = new LoadedModule { Name = "app.exe", LoadBase = 0x400000, Size = 0x200000, CwtlsLo = 0xC8000, CwtlsHi = 0xCC000 };
            const uint tmplLo = 0x4C8000, tmplLast = 0x4CBFFF;
            uint hit;

            // STRADDLING: 16 bytes below the template, 32 long, so the last 16 land in it. The discriminator
            // is hitVa != va — the first byte IN the template is the template's own first byte.
            const uint straddle = tmplLo - 0x10;
            if (!DebugEngine.TouchesThreadedTemplateForTest(m, straddle, 0x20, out hit))
                failures.Add("template-span: a range starting 0x10 below the template and 0x20 long was not "
                             + "seen to touch it — the start-only defect");
            else if (hit != tmplLo)
                failures.Add("template-span: a straddling range reported its first template byte as 0x" + hit.ToString("X")
                             + ", expected the template's first byte 0x" + tmplLo.ToString("X"));
            else if (hit == straddle)
                failures.Add("template-span: a straddling range's hit equals its start — the discriminator cannot tell it from a contained one");
            var s = DebugEngine.ClassifyTemplateSpanForTest(m, straddle, 0x20);
            if (s != DebugEngine.TemplateSpan.Straddling)
                failures.Add("template-span: a symbol starting below the template and reaching in classified as " + s + ", expected Straddling");

            // CONTAINED: starts inside, so the hit is the start itself.
            const uint inside = tmplLo + 0x10;
            if (!DebugEngine.TouchesThreadedTemplateForTest(m, inside, 4, out hit))
                failures.Add("template-span: a range starting inside the template was not seen to touch it");
            else if (hit != inside)
                failures.Add("template-span: a contained range reported its hit as 0x" + hit.ToString("X") + ", expected its own start 0x" + inside.ToString("X"));
            s = DebugEngine.ClassifyTemplateSpanForTest(m, inside, 4);
            if (s != DebugEngine.TemplateSpan.StartsInside)
                failures.Add("template-span: a symbol starting inside the template classified as " + s + ", expected StartsInside");
            // Starting on the last byte and running PAST the template is still a start inside it — the case
            // the old point test also answered as threaded, and which must not move.
            s = DebugEngine.ClassifyTemplateSpanForTest(m, tmplLast, 0x100);
            if (s != DebugEngine.TemplateSpan.StartsInside)
                failures.Add("template-span: a symbol starting on the template's last byte classified as " + s + ", expected StartsInside");
            // A zero size is one byte, as the write guard treats it: a point inside is still inside.
            s = DebugEngine.ClassifyTemplateSpanForTest(m, inside, 0);
            if (s != DebugEngine.TemplateSpan.StartsInside)
                failures.Add("template-span: a zero-size symbol inside the template classified as " + s + ", expected StartsInside");

            // CONTROLS: a range ending exactly at the template's first byte touches nothing, and neither does
            // one starting just past its end. Without these, a rule that answered "touching" for everything
            // would pass the lines above.
            if (DebugEngine.TouchesThreadedTemplateForTest(m, straddle, 0x10, out hit))
                failures.Add("template-span control: a range ENDING exactly at the template's first byte was seen to touch it (hit 0x" + hit.ToString("X") + ")");
            s = DebugEngine.ClassifyTemplateSpanForTest(m, straddle, 0x10);
            if (s != DebugEngine.TemplateSpan.Outside)
                failures.Add("template-span control: a symbol ending exactly at the template classified as " + s + ", expected Outside");
            s = DebugEngine.ClassifyTemplateSpanForTest(m, tmplLast + 1, 0x20);
            if (s != DebugEngine.TemplateSpan.Outside)
                failures.Add("template-span control: a symbol starting just past the template classified as " + s + ", expected Outside");
            // An image with no .cwtls section has no template to touch.
            var plain = new LoadedModule { Name = "plain.dll", LoadBase = 0x400000, Size = 0x200000 };
            s = DebugEngine.ClassifyTemplateSpanForTest(plain, inside, 4);
            if (s != DebugEngine.TemplateSpan.Outside)
                failures.Add("template-span control: an image with no .cwtls section classified a symbol as " + s + ", expected Outside");
        }

        /// <summary>
        /// The THR$GetInstance branches that only run when something has gone wrong (38b75897). 337b3222 made
        /// a debuggee write during emulation a QUESTION rather than a verdict: a write inside the block being
        /// returned is the allocate-on-first-touch path, a write elsewhere is reported and the result kept, and
        /// an emulation that throws after writing is reported instead of swallowed. No live run ever fired
        /// them: in clbrws the fast path never writes.
        ///
        /// HOW THE FAULT IS INJECTED: through what the harness hands in, not a switch. RtlEmulator already
        /// reads code and memory through delegates, so each case runs a few hand-assembled x86 bytes as
        /// "THR$GetInstance" over the harness's own memory, then asks the engine's REAL verdict
        /// (ClassifyEmulatedInstanceForTest). A throw is an instruction the emulator refuses (CPUID); a write
        /// lands wherever the bytes say.
        ///
        /// NOT COVERED: that real ClaRUN code takes these paths, or the probe-and-cache step the live caller
        /// runs after an Ok verdict (it reads the target).
        /// </summary>
        private static void CheckEmulationFaultBranches(List<string> failures, ClaimLog claims)
        {
            claims.Claim("THR$GetInstance's failure branches run on injected emulations: a write INSIDE the block "
                         + "being returned (to its last byte) reads as not-yet-allocated, the same result with the "
                         + "write just OUTSIDE it is kept and reported, a run that throws after writing is reported "
                         + "rather than swallowed, and one that throws without writing fails. Not covered: real "
                         + "ClaRUN code, or the live probe-and-cache step.");

            // app.exe at 0x400000, template block RVA 0xC8000..0xCC000; this name sits 0x10 into it. The
            // thread's instance block is at 0x02000000, so its instance of this name is 0x02000010.
            var owner = new LoadedModule { Name = "app.exe", LoadBase = 0x400000, Size = 0x200000, CwtlsLo = 0xC8000, CwtlsHi = 0xCC000 };
            const uint templateVa = 0x4C8010, block = 0x02000000, instance = 0x02000010, blockLen = 0x4000;
            const uint helper = 0x00600000;

            // One case = a fresh engine (the notes dedup per engine) and a fresh emulator over `code` at `helper`.
            Func<byte[], EmulationCase> run = code =>
            {
                var eng = NewEngine();
                var emu = new RtlEmulator(
                    readMem: (addr, n) =>
                    {
                        var buf = new byte[n];   // everything outside the code reads as zeros
                        for (int i = 0; i < n; i++)
                        {
                            long off = (long)addr + i - helper;
                            if (off >= 0 && off < code.Length) buf[i] = code[off];
                        }
                        return buf;
                    },
                    tlsGetValue: idx => 0, curThreadId: 4812, teb: 0,
                    importAtSlot: slot => null,
                    isCode: va => va >= helper && va < helper + 0x1000,
                    stackBase: 0x20000000);
                var r = new EmulationCase();
                r.Console = CaptureConsole(() =>
                {
                    r.Verdict = eng.ClassifyEmulatedInstanceForTest(owner, templateVa, emu, helper, out r.Result, out r.Reason);
                });
                return r;
            };
            Func<uint, byte[]> movEax = v => new byte[] { 0xB8, (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) };
            Func<uint, byte[]> storeDword = a => new byte[] { 0xC7, 0x05, (byte)a, (byte)(a >> 8), (byte)(a >> 16), (byte)(a >> 24), 1, 0, 0, 0 };
            Func<uint, byte[]> storeByte = a => new byte[] { 0xC6, 0x05, (byte)a, (byte)(a >> 8), (byte)(a >> 16), (byte)(a >> 24), 1 };
            byte[] ret = { 0xC3 }, cpuid = { 0x0F, 0xA2 };
            Func<byte[][], byte[]> asm = parts => { var l = new List<byte>(); foreach (var q in parts) l.AddRange(q); return l.ToArray(); };

            // CONTROL: a clean read-only run is an Ok candidate with no report. Without this, a verdict that
            // reported or refused everything would satisfy the fault cases below.
            var c = run(asm(new[] { movEax(instance), ret }));
            if (c.Verdict != DebugEngine.ThreadedResolve.Ok || c.Result != instance)
                failures.Add("emulation faults control: a clean run returning 0x" + instance.ToString("X") + " was " + c.Verdict
                             + " (0x" + c.Result.ToString("X") + "), expected an Ok candidate");
            else if (c.Console.Length != 0)
                failures.Add("emulation faults control: a clean run printed a report: " + c.Console.Trim());

            // ITEM 2, BOTH DIRECTIONS. Same result each time; only the write's address differs, so WroteWithin
            // is the deciding test.
            var inside = run(asm(new[] { storeDword(block), movEax(instance), ret }));
            if (inside.Verdict != DebugEngine.ThreadedResolve.Unallocated)
                failures.Add("emulation faults: a write INSIDE the returned block was " + inside.Verdict
                             + ", expected Unallocated (the allocate-on-first-touch path)");
            var lastByte = run(asm(new[] { storeByte(block + blockLen - 1), movEax(instance), ret }));
            if (lastByte.Verdict != DebugEngine.ThreadedResolve.Unallocated)
                failures.Add("emulation faults: a write on the block's LAST byte was " + lastByte.Verdict + ", expected Unallocated");
            var outside = run(asm(new[] { storeByte(block + blockLen), movEax(instance), ret }));
            if (outside.Verdict != DebugEngine.ThreadedResolve.Ok || outside.Result != instance)
                failures.Add("emulation faults: a write one byte PAST the returned block was " + outside.Verdict
                             + ", expected the instance kept (Ok) - a write elsewhere is not the allocate path");
            else if (outside.Console.IndexOf("outside its block", StringComparison.Ordinal) < 0)
                failures.Add("emulation faults: the instance was kept despite a write outside its block, SILENTLY - console: "
                             + outside.Console.Trim());
            else if (outside.Console.IndexOf("wrote 0x" + (block + blockLen).ToString("X"), StringComparison.Ordinal) < 0)
                failures.Add("emulation faults: the outside-write report did not carry the emulator's trace of WHERE it wrote");

            // ITEM 1: a broken emulation that happens to write first. It may still read as Unallocated (there is
            // no result to test the write against), but never silently: that is the original defect, a template
            // value shown as "not yet used on this thread" with nothing to doubt.
            var broken = run(asm(new[] { storeDword(0x03000000), cpuid }));
            if (broken.Verdict != DebugEngine.ThreadedResolve.Unallocated)
                failures.Add("emulation faults: a run that wrote then threw was " + broken.Verdict + ", expected Unallocated-with-report");
            else if (broken.Console.IndexOf("failed emulation", StringComparison.Ordinal) < 0
                     || broken.Console.IndexOf("NotSupported", StringComparison.Ordinal) < 0)
                failures.Add("emulation faults: a run that wrote then THREW was reported as not-yet-allocated WITHOUT "
                             + "saying the emulation failed - console: " + broken.Console.Trim());
            // ...and the same throw with NO write is a plain failure, not "unallocated".
            var failed = run(cpuid);
            if (failed.Verdict != DebugEngine.ThreadedResolve.Failed)
                failures.Add("emulation faults: a run that threw without writing was " + failed.Verdict + ", expected Failed");
            else if (failed.Reason == null || failed.Reason.IndexOf("not emulatable", StringComparison.Ordinal) < 0)
                failures.Add("emulation faults: a refused emulation failed without saying why: " + (failed.Reason ?? "(no reason)"));
        }

        /// <summary>One injected emulation's outcome, for <see cref="CheckEmulationFaultBranches"/>.</summary>
        private sealed class EmulationCase
        {
            internal DebugEngine.ThreadedResolve Verdict;
            internal uint Result;
            internal string Reason;
            internal string Console;
        }
    }
}
