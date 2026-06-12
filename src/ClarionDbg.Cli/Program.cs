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
                    case "symbols": return Symbols(args);
                    case "globals": return Globals(args);
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
            Console.WriteLine("  ClarionDbg symbols <exe> [--module NAME] [--kind proc|method|routine|other] [--json]");
            Console.WriteLine("      List decoded symbol definitions (procedures, class methods, routines) with");
            Console.WriteLine("      entry RVA + owning module. Default text view groups top-level procs by module.");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg globals <exe> [--module NAME] [--name SUBSTR]");
            Console.WriteLine("      List static data symbols (globals + file record buffers with their fields,");
            Console.WriteLine("      offsets, type codes, and sizes). RVAs are link-time template addresses.");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg resolve <exe> --addr 0xRVA");
            Console.WriteLine("      Map a code RVA (or VA) to its module + source line (address -> line).");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg resolve <exe> --line N [--module NAME]");
            Console.WriteLine("      Map a source line to code RVAs (line -> address); --module to scope it.");
            Console.WriteLine();
            Console.WriteLine("  ClarionDbg break <exe> [--bp MODULE:LINE ...] [--rva 0xX ...] [--line N --module M]");
            Console.WriteLine("                         [--entry] [--once] [--interactive] [--json] [--timeout ms]");
            Console.WriteLine("      Launch under the debugger, plant INT3 breakpoint(s), and on a hit report");
            Console.WriteLine("      the module + source line and register state. --once kills the target after first hit.");
            Console.WriteLine("      --bp may repeat; breakpoints persist (re-armed after each hit).");
            Console.WriteLine("      --interactive: pause at each hit and read stdin commands —");
            Console.WriteLine("        continue | step | stepover | stepout | bp add M:L | bp del M:L | bp list");
            Console.WriteLine("        | mem 0xADDR LEN | regs | stack [maxFrames] | sym NAME | watch NAME | quit");
            Console.WriteLine("        (while running: pause, bp add/del/list, sym, quit)");
            Console.WriteLine("      watch resolves THREADed (.cwtls) data to the paused thread's live");
            Console.WriteLine("      instance via a THR$GetInstance func-eval, then dumps the value.");
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

        /// <summary>Nearest breakable line to a request: smallest &gt;= line (forward snap), else
        /// largest &lt; line. Returns -1 if the list is empty. (Sorted-list scan; lists are small.)</summary>
        private static int NearestIn(System.Collections.Generic.List<int> sorted, int line)
        {
            if (sorted == null || sorted.Count == 0) return -1;
            int fwd = int.MaxValue, back = -1;
            foreach (int v in sorted)
            {
                if (v == line) return line;
                if (v > line && v < fwd) fwd = v;
                if (v < line && v > back) back = v;
            }
            return fwd != int.MaxValue ? fwd : back;
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
                {
                    string nm = dbg.ModuleNameForIdx(mi2) ?? "?";
                    // symbol bind, cross-checked against the +0x1C moduleIdx (cold/init code below a
                    // module's named entry binds to the previous module's last symbol — say unknown)
                    string proc = dbg.ResolveSymbol(rva, out ProcSymbol sym) && sym.ModuleIdx == mi2
                        ? $"{sym.Name} [{sym.Kind.ToString().ToLowerInvariant()}]" : null;
                    Console.WriteLine($"RVA 0x{rva:X} (VA 0x{pe.ImageBase + rva:X}) -> {nm} (moduleIdx {mi2}) line {l2}{(proc != null ? " in " + proc : "")}  (+0x1C, record RVA 0x{rr2:X})");
                }
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
                    // v2: resolve the module NAME to a +0x1C moduleIdx (name-array index == moduleIdx),
                    // then line->addr via the clean +0x1C table, snapping to the nearest breakable line.
                    int mi = dbg.FindModuleIdx(module);
                    if (mi < 0) { Console.WriteLine($"{module} -> unknown module"); return 0; }
                    int planted = line;
                    var rvas = dbg.LineToRvasInModuleIdx(mi, line);
                    if (rvas.Count == 0)
                    {
                        var breakable = dbg.BreakableLinesInModuleIdx(mi);
                        int snapped = NearestIn(breakable, line);
                        if (snapped > 0) { planted = snapped; rvas = dbg.LineToRvasInModuleIdx(mi, snapped); }
                    }
                    if (rvas.Count == 0) { Console.WriteLine($"{module} (moduleIdx {mi}) line {line} -> no code records"); return 0; }
                    if (planted != line)
                        Console.WriteLine($"{module} line {line} has no record; nearest breakable line is {planted}:");
                    Console.WriteLine($"{module} (moduleIdx {mi}) line {planted} -> {rvas.Count} address(es):");
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

            // v2: name -> moduleIdx -> breakable lines from the +0x1C table.
            int mi = dbg.FindModuleIdx(module);
            var lines = mi >= 0 ? dbg.BreakableLinesInModuleIdx(mi) : new List<int>();
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

        private static int Symbols(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            var syms = dbg.Symbols ?? new List<ProcSymbol>();

            string module = GetOpt(args, "--module");
            if (module != null)
            {
                int mi = dbg.FindModuleIdx(module);
                if (mi < 0) { Console.Error.WriteLine($"{module} -> unknown module"); return 3; }
                syms = syms.Where(s => s.ModuleIdx == mi).ToList();
            }
            string kind = GetOpt(args, "--kind");
            if (kind != null)
            {
                SymbolKind k;
                switch (kind.ToLowerInvariant())
                {
                    case "proc": case "procedure": k = SymbolKind.Procedure; break;
                    case "method": k = SymbolKind.Method; break;
                    case "routine": k = SymbolKind.Routine; break;
                    case "other": k = SymbolKind.Other; break;
                    default: Console.Error.WriteLine($"unknown --kind '{kind}'"); return 1;
                }
                syms = syms.Where(s => s.Kind == k).ToList();
            }

            if (HasFlag(args, "--json"))
            {
                Console.WriteLine("@SYMBOLS " + Json.Symbols(syms, dbg));
                return syms.Count > 0 ? 0 : 3;
            }

            int nProc = syms.Count(s => s.Kind == SymbolKind.Procedure);
            int nMeth = syms.Count(s => s.Kind == SymbolKind.Method);
            int nRtn = syms.Count(s => s.Kind == SymbolKind.Routine);
            int nOther = syms.Count(s => s.Kind == SymbolKind.Other);
            Console.WriteLine($"{syms.Count} symbol definitions (TOC +0x30 count field = {dbg.SymbolCountField}):");
            Console.WriteLine($"  {nProc} procedures, {nMeth} methods, {nRtn} routines, {nOther} other");
            Console.WriteLine();

            // group top-level procs per module (matches spikes/tswd-symbols.txt for validation)
            Console.WriteLine($"{"modIdx",6}  {"module",-20} {"procs",5}  procName(entryRVA)");
            var byMod = syms.Where(s => s.Kind == SymbolKind.Procedure)
                            .GroupBy(s => s.ModuleIdx).OrderBy(g => g.Key);
            foreach (var g in byMod)
            {
                string nm = dbg.ModuleNameForIdx(g.Key) ?? "?";
                string lst = string.Join(", ", g.OrderBy(s => s.EntryRva)
                                               .Select(s => $"{s.Name}(0x{s.EntryRva:X})"));
                Console.WriteLine($"{g.Key,6}  {nm,-20} {g.Count(),5}  {lst}");
            }

            if (module != null)
            {
                // single-module view: show everything (methods/routines too), address-ordered
                Console.WriteLine();
                foreach (var s in syms.OrderBy(s => s.EntryRva))
                    Console.WriteLine($"  0x{s.EntryRva:X6}  {s.Kind,-9}  {s.Name}  [{s.RawName}]");
            }
            return 0;
        }

        private static int Globals(string[] args)
        {
            if (args.Length < 2) { Usage(); return 1; }
            var (pe, dbg) = LoadDebug(args[1]);
            var syms = dbg.DataSymbols ?? new List<DataSymbol>();

            string module = GetOpt(args, "--module");
            if (module != null)
            {
                int mi = dbg.FindModuleIdx(module);
                if (mi < 0) { Console.Error.WriteLine($"{module} -> unknown module"); return 3; }
                syms = syms.Where(s => s.ModuleIdx == mi).ToList();
            }
            string filter = GetOpt(args, "--name");
            if (filter != null)
                syms = syms.Where(s => s.Name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0
                                    || (s.Fields != null && s.Fields.Any(f => f.Name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)))
                           .ToList();

            if (HasFlag(args, "--json"))
            {
                Console.WriteLine("@GLOBALS " + Json.Globals(syms, dbg));
                return syms.Count > 0 ? 0 : 3;
            }

            int groups = syms.Count(s => s.Fields != null);
            Console.WriteLine($"{syms.Count} data symbol(s), {groups} with fields:");
            foreach (var s in syms)
            {
                string ty = TswdDebugInfo.TypeCodeName(s.TypeCode) ?? (s.TypeCode != 0 ? $"type 0x{s.TypeCode:X2}" : "?");
                string mod = dbg.ModuleNameForIdx(s.ModuleIdx) ?? "?";
                Console.WriteLine($"  0x{s.Rva:X6}  {s.Name,-32} {ty,-10} size {s.Size,-6} {mod}");
                if (s.Fields == null) continue;
                foreach (var f in s.Fields)
                {
                    string fty = TswdDebugInfo.TypeCodeName(f.TypeCode) ?? $"type 0x{f.TypeCode:X2}";
                    Console.WriteLine($"            +{f.Offset,-4} {f.Name,-30} {fty,-10} size {f.Size}");
                }
            }
            return syms.Count > 0 ? 0 : 3;
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

            // --bp MODULE:LINE may appear multiple times; the engine resolves + snaps each one
            var specs = new List<BpSpec>();
            for (int i = 2; i < args.Length - 1; i++)
            {
                if (!string.Equals(args[i], "--bp", StringComparison.OrdinalIgnoreCase)) continue;
                string v = args[i + 1];
                int colon = v.LastIndexOf(':');
                if (colon <= 0) { Console.Error.WriteLine($"--bp expects MODULE:LINE, got '{v}'"); return 1; }
                specs.Add(new BpSpec(v.Substring(0, colon), (int)ParseNum(v.Substring(colon + 1))));
            }

            string lineStr = GetOpt(args, "--line");
            if (lineStr != null)
            {
                string module = GetOpt(args, "--module");
                int line = (int)ParseNum(lineStr);
                if (module != null)
                {
                    // legacy single-breakpoint form — equivalent to one --bp module:line
                    specs.Add(new BpSpec(module, line));
                }
                else
                {
                    // No module: match the line across all compilands via +0x1C (ambiguous — prefer --module).
                    var hits = new List<uint>();
                    if (dbg.AddrTable != null)
                        foreach (var r in dbg.AddrTable) if (r.Line == line) hits.Add(r.Rva);
                    if (hits.Count == 0) { Console.Error.WriteLine($"no code for line {line} in any module"); return 2; }
                    rvas.AddRange(hits);
                }
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

            bool interactive = HasFlag(args, "--interactive");
            if (rvas.Count == 0 && specs.Count == 0 && !interactive)
            {
                // interactive sessions may start empty — breakpoints arrive via 'bp add' (gutter clicks)
                Console.Error.WriteLine("nothing to break on — specify --bp M:L, --rva 0xX, --line N [--module M], or --entry");
                return 1;
            }

            bool once = HasFlag(args, "--once");
            int waitMs = 15000;
            string to = GetOpt(args, "--timeout");
            if (to != null) waitMs = (int)ParseNum(to);

            var engine = new DebugEngine(args[1], dbg, pe.ImageBase, rvas, specs, once, waitMs, interactive);
            engine.EmitJson = HasFlag(args, "--json");

            // threaded-data resolution (watch NAME on THREADed vars) needs the .cwtls range and
            // the live THR$GetInstance address (read via its IAT slot at runtime)
            var cwtls = pe.FindSection(".cwtls");
            uint thrIat = pe.FindImportIatSlotRva("ClaRUN.dll", "THR$GetInstance");
            if (cwtls != null && thrIat != 0)
                engine.SetThreadEvalInfo(cwtls.VirtualAddress, cwtls.VirtualAddress + cwtls.Span, thrIat);
            int hits2 = engine.Run();
            if (hits2 < 0) { Console.Error.WriteLine("no breakpoint could be resolved"); return 2; }
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
