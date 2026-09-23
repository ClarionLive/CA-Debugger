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
    }
}
