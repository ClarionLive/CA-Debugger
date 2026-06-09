using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length < 1) { Usage(); return 1; }
            try
            {
                switch (args[0].ToLowerInvariant())
                {
                    case "dump": return Dump(args);
                    case "resolve": return Resolve(args);
                    case "modules": return Modules(args);
                    case "runs": return Runs(args);
                    case "lines": return Lines(args);
                    case "break": return Break(args);
                    default: Usage(); return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: " + ex.Message);
                return 2;
            }
        }

        private static void Usage()
        {
            Console.WriteLine("ClarionDbg — Clarion TSWD debug-info tool");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg dump <exe>");
            Console.WriteLine("      Parse the EXE and report PE info, TSWD TOC, modules, and line-table validation.");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg modules <exe>");
            Console.WriteLine("      List per-module line sub-tables (slice, phase, record count, line range).");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg lines <exe> --module NAME [--json]");
            Console.WriteLine("      List the breakable source lines for a module (lines that carry a code record).");
            Console.WriteLine("      These are the only lines a breakpoint binds to exactly; others get snapped.");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg resolve <exe> --addr 0xRVA");
            Console.WriteLine("      Map a code RVA (or VA) to its module + source line (address -> line).");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg resolve <exe> --line N [--module NAME]");
            Console.WriteLine("      Map a source line to code RVAs (line -> address); --module to scope it.");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg break <exe> [--rva 0xX ...] [--line N --module M] [--entry] [--once] [--timeout ms]");
            Console.WriteLine("      Launch under the debugger, plant INT3 breakpoint(s), and on a hit report");
            Console.WriteLine("      the module + source line and register state. --once kills the target after first hit.");
        }

        private static (PeImage pe, TswdDebugInfo dbg) LoadDebug(string exe)
        {
            var pe = PeImage.Load(exe);
            var dbg = TswdDebugInfo.FromPe(pe);
            return (pe, dbg);
        }

        private static int Dump(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            var entry = pe.ReadFirstDebugEntry();
            var text = pe.Text;

            Console.WriteLine("== PE ==");
            Console.WriteLine($"  machine        : 0x{pe.Machine:X4} ({(pe.IsX86 ? "x86" : "?")})");
            Console.WriteLine($"  imageBase      : 0x{pe.ImageBase:X}");
            Console.WriteLine($"  .text          : RVA 0x{text.VirtualAddress:X}..0x{text.VirtualAddress + text.VirtualSize:X}");
            Console.WriteLine($"  debug entry    : type=0x{entry.Type:X8} ('{Tag(entry.Type)}') size={entry.SizeOfData} ptr=0x{entry.PointerToRawData:X}");
            Console.WriteLine();

            Console.WriteLine("== TSWD TOC ==");
            Console.WriteLine($"  headerSize     : {dbg.HeaderSize}");
            Console.WriteLine($"  moduleNameArr  : 0x{dbg.OffModuleNameArray:X}");
            Console.WriteLine($"  moduleNamePool : 0x{dbg.OffModuleNamePool:X}");
            Console.WriteLine($"  lineTableA     : 0x{dbg.OffLineTableA:X}");
            Console.WriteLine($"  lineTableB     : 0x{dbg.OffLineTableB:X}");
            Console.WriteLine($"  tableAfterB    : 0x{dbg.OffTableAfterB:X}");
            Console.WriteLine($"  symbolPool     : 0x{dbg.OffSymbolPool:X}");
            Console.WriteLine($"  symbolNameArr  : 0x{dbg.OffSymbolNameArray:X}");
            Console.WriteLine($"  moduleCount    : {dbg.ModuleCount} (derived); TOC +0x24 field = {dbg.ModuleCountField}");
            Console.WriteLine();

            Console.WriteLine("== Modules ==");
            Console.WriteLine($"  count={dbg.ModuleNames.Count}; first 12:");
            foreach (var m in dbg.ModuleNames.Take(12)) Console.WriteLine("    " + m);
            Console.WriteLine();

            Console.WriteLine("== Line tables (validation) ==");
            ReportTable("Table A {line,rva}", dbg.ByLine, pe);
            ReportTable("Table B {rva,line}", dbg.ByAddr, pe);
            Console.WriteLine();
            Console.WriteLine("  Table A first 5:");
            foreach (var r in dbg.ByLine.Take(5))
                Console.WriteLine($"    line {r.Line,5} -> RVA 0x{r.Rva:X}  (VA 0x{pe.ImageBase + r.Rva:X})");
            Console.WriteLine();

            Console.WriteLine("== Module line sub-tables (authoritative) ==");
            int withCode = dbg.Modules.Count(m => m.HasCode);
            int totalRecs = dbg.Modules.Sum(m => m.Records.Count);
            Console.WriteLine($"  {dbg.Modules.Count} modules, {withCode} with code, {totalRecs} total line records");
            foreach (var m in dbg.Modules.Where(m => m.HasCode).Take(4))
                Console.WriteLine($"    {m.Name,-16} phase {m.Phase} recs {m.Records.Count,4}  e.g. line {m.Records[0].Line} -> RVA 0x{m.Records[0].Rva:X}");
            Console.WriteLine();

            Console.WriteLine("== Symbol pool (best-effort) ==");
            Console.WriteLine($"  strings={dbg.SymbolPool.Count}; sample:");
            foreach (var s in dbg.SymbolPool.Where(s => s.Length >= 4).Take(12)) Console.WriteLine("    " + s);

            return 0;
        }

        private static void ReportTable(string name, List<LineRec> recs, PeImage pe)
        {
            int inText = recs.Count(r => pe.RvaInText(r.Rva));
            double pct = recs.Count == 0 ? 0 : 100.0 * inText / recs.Count;
            int minL = recs.Count == 0 ? 0 : recs.Min(r => r.Line);
            int maxL = recs.Count == 0 ? 0 : recs.Max(r => r.Line);
            Console.WriteLine($"  {name}: {recs.Count} records, {inText} in .text ({pct:F1}%), line {minL}..{maxL}");
        }

        private static int Resolve(string[] args)
        {
            if (args.Length < 4) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            string opt = args[2].ToLowerInvariant();
            string val = args[3];
            string module = GetOpt(args, "--module");

            if (opt == "--addr")
            {
                uint rva = ParseNum(val);
                if (rva >= pe.ImageBase) rva -= pe.ImageBase; // accept VA or RVA
                // v2 primary: the +0x1C address table (clean, RVA-ascending, carries moduleIdx).
                if (dbg.ResolveAddr(rva, out int l2, out int mi2, out uint rr2))
                    Console.WriteLine($"RVA 0x{rva:X} (VA 0x{pe.ImageBase + rva:X}) -> moduleIdx {mi2} line {l2}  (+0x1C, record RVA 0x{rr2:X})");
                else
                    Console.WriteLine($"RVA 0x{rva:X} -> no +0x1C record at or before this address");
                // legacy module-sliced path, for comparison
                if (dbg.TryResolve(rva, out var m, out int line, out uint recRva))
                    Console.WriteLine($"  [legacy +0x10] -> {m.Name} line {line}  (record RVA 0x{recRva:X})");
                return 0;
            }
            if (opt == "--line")
            {
                int line = (int)ParseNum(val);
                // v2 primary: resolve within a compiland by moduleIdx via the +0x1C table.
                string modIdxOpt = GetOpt(args, "--modidx");
                if (modIdxOpt != null)
                {
                    int mi = (int)ParseNum(modIdxOpt);
                    var rvas2 = dbg.LineToRvasInModuleIdx(mi, line);
                    if (rvas2.Count == 0) { Console.WriteLine($"moduleIdx {mi} line {line} -> no record (+0x1C)"); return 0; }
                    Console.WriteLine($"moduleIdx {mi} line {line} -> {rvas2.Count} address(es) (+0x1C):");
                    foreach (var rva in rvas2) Console.WriteLine($"    RVA 0x{rva:X}  (VA 0x{pe.ImageBase + rva:X})");
                    return 0;
                }
                if (module != null)
                {
                    int planted = line;
                    var rvas = dbg.LineToRvasInModule(module, line);
                    if (rvas.Count == 0)
                    {
                        int snapped = dbg.NearestLineWithCode(module, line);
                        if (snapped > 0) { planted = snapped; rvas = dbg.LineToRvasInModule(module, snapped); }
                    }
                    if (rvas.Count == 0) { Console.WriteLine($"{module} line {line} -> no code (module has no line records)"); return 0; }
                    if (planted != line)
                        Console.WriteLine($"{module} line {line} has no record; nearest breakable line is {planted}:");
                    Console.WriteLine($"{module} line {planted} -> {rvas.Count} address(es):");
                    foreach (var rva in rvas) Console.WriteLine($"    RVA 0x{rva:X}  (VA 0x{pe.ImageBase + rva:X})");
                }
                else
                {
                    var hits = dbg.LineToRvasAll(line);
                    if (hits.Count == 0) { Console.WriteLine($"line {line} -> no code in any module"); return 0; }
                    Console.WriteLine($"line {line} -> {hits.Count} hit(s) across modules (use --module to disambiguate):");
                    foreach (var h in hits) Console.WriteLine($"    {h.Key.Name,-16} RVA 0x{h.Value:X}  (VA 0x{pe.ImageBase + h.Value:X})");
                }
                return 0;
            }
            Usage();
            return 1;
        }

        private static int Modules(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            var withCode = dbg.Modules.Where(m => m.HasCode).ToList();
            Console.WriteLine($"{dbg.Modules.Count} modules, {withCode.Count} with code:");
            foreach (var m in withCode)
            {
                int lo = m.Records.Count > 0 ? m.Records.Min(r => r.Line) : 0;
                int hi = m.Records.Count > 0 ? m.Records.Max(r => r.Line) : 0;
                Console.WriteLine($"  {m.Name,-16} slice 0x{m.SliceStart:X5}..0x{m.SliceEnd:X5} phase {m.Phase} recs {m.Records.Count,4}  lines {lo}..{hi}");
            }
            return 0;
        }

        private static int Runs(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            Console.WriteLine($"Table A: {dbg.Runs.Count} line-major runs (continuous grid, segmented by line-resets)");
            Console.WriteLine($"{"run",3} {"startByte",9} {"startRec",8} {"ph",2} {"lMin",6} {"lMax",6} {"rvaMin",9} {"rvaMax",9} {"nrec",5}  owner(+0x10)");
            for (int i = 0; i < dbg.Runs.Count; i++)
            {
                var r = dbg.Runs[i];
                Console.WriteLine($"{i,3} 0x{r.StartByteOffset:X6} {r.StartRecordIndex,8} {r.Phase,2} {r.LineMin,6} {r.LineMax,6} 0x{r.RvaMin:X6} 0x{r.RvaMax:X6} {r.Records.Count,5}  {r.OwnerHint}");
            }
            return 0;
        }

        private static int Lines(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            string module = GetOpt(args, "--module");
            if (module == null) { Console.Error.WriteLine("specify --module NAME"); return 1; }

            var lines = dbg.BreakableLines(module);
            if (HasFlag(args, "--json"))
            {
                Console.WriteLine("@LINES " + Json.Lines(module, lines));
                return lines.Count > 0 ? 0 : 3;
            }
            if (lines.Count == 0) { Console.WriteLine($"{module}: no breakable lines (unknown module or no code records)"); return 3; }
            Console.WriteLine($"{module}: {lines.Count} breakable lines: {CompactRanges(lines)}");
            return 0;
        }

        /// <summary>Render a sorted line list as compact ranges, e.g. "17,19-30,171-216".</summary>
        private static string CompactRanges(List<int> xs)
        {
            if (xs.Count == 0) return "(none)";
            var sb = new System.Text.StringBuilder();
            int start = xs[0], prev = xs[0];
            for (int i = 1; i <= xs.Count; i++)
            {
                if (i < xs.Count && xs[i] == prev + 1) { prev = xs[i]; continue; }
                if (sb.Length > 0) sb.Append(',');
                sb.Append(start == prev ? start.ToString() : start + "-" + prev);
                if (i < xs.Count) { start = xs[i]; prev = xs[i]; }
            }
            return sb.ToString();
        }

        private static int Break(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);

            var rvas = new List<uint>();
            // --rva may appear multiple times
            for (int i = 2; i < args.Length - 1; i++)
                if (string.Equals(args[i], "--rva", StringComparison.OrdinalIgnoreCase))
                    rvas.Add(ToRva(ParseNum(args[i + 1]), pe));

            string lineStr = GetOpt(args, "--line");
            if (lineStr != null)
            {
                string module = GetOpt(args, "--module");
                int line = (int)ParseNum(lineStr);
                var hits = new List<uint>();
                if (module != null)
                {
                    int planted = line;
                    hits = dbg.LineToRvasInModule(module, line);
                    if (hits.Count == 0)
                    {
                        // Clarion's line table is sparse — snap to the nearest line that has a record.
                        int snapped = dbg.NearestLineWithCode(module, line);
                        if (snapped > 0) { planted = snapped; hits = dbg.LineToRvasInModule(module, snapped); }
                    }
                    if (hits.Count > 0 && planted != line)
                        Console.WriteLine($"line {line} has no code record in {module}; breakpoint moved to nearest line {planted}");
                }
                else
                {
                    var all = dbg.LineToRvasAll(line);
                    foreach (var h in all) hits.Add(h.Value);
                }
                if (hits.Count == 0) { Console.Error.WriteLine($"no code for line {line}{(module != null ? " in " + module : "")} (and no nearby breakable line)"); return 2; }
                rvas.AddRange(hits);
            }

            if (HasFlag(args, "--entry"))
            {
                rvas.Add(pe.EntryPointRva);
                Console.WriteLine($"adding PE entry point RVA 0x{pe.EntryPointRva:X}");
            }

            if (HasFlag(args, "--all-entries"))
            {
                // discovery: breakpoint at the lowest-RVA record of every parsed module
                int added = 0;
                foreach (var m in dbg.Modules)
                {
                    if (m.Records.Count == 0) continue;
                    uint min = uint.MaxValue;
                    foreach (var r in m.Records) if (r.Rva < min) min = r.Rva;
                    rvas.Add(min); added++;
                }
                Console.WriteLine($"adding {added} module-entry breakpoints (discovery mode)");
            }

            if (rvas.Count == 0)
            {
                Console.Error.WriteLine("nothing to break on — specify --rva 0xX, --line N [--module M], or --entry");
                return 1;
            }

            bool once = HasFlag(args, "--once");
            int waitMs = 15000;
            string to = GetOpt(args, "--timeout");
            if (to != null) waitMs = (int)ParseNum(to);

            var engine = new DebugEngine(args[1], dbg, pe.ImageBase, rvas, once, waitMs);
            engine.EmitJson = HasFlag(args, "--json");
            int hits2 = engine.Run();
            Console.WriteLine($"\ndone — {hits2} breakpoint hit(s).");
            return hits2 > 0 ? 0 : 3;
        }

        private static uint ToRva(uint v, PeImage pe) { return v >= pe.ImageBase ? v - pe.ImageBase : v; }
        private static bool HasFlag(string[] args, string name)
        {
            foreach (var a in args) if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string GetOpt(string[] args, string name)
        {
            for (int i = 0; i < args.Length - 1; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                    return args[i + 1];
            return null;
        }

        private static uint ParseNum(string s)
        {
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return uint.Parse(s.Substring(2), NumberStyles.HexNumber);
            return uint.Parse(s, CultureInfo.InvariantCulture);
        }

        private static string Tag(uint t)
        {
            var b = BitConverter.GetBytes(t);
            var c = new char[4];
            for (int i = 0; i < 4; i++) c[i] = (b[i] >= 32 && b[i] < 127) ? (char)b[i] : '.';
            return new string(c);
        }
    }
}
