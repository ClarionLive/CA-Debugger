using System;
using System.Collections.Generic;
using System.Text;

namespace ClarionDbg.Core
{
    /// <summary>One line-number table record: a source line mapped to a code RVA.</summary>
    public struct LineRec
    {
        public int Line;
        public uint Rva;
        public LineRec(int line, uint rva) { Line = line; Rva = rva; }
    }

    /// <summary>
    /// One record of the TOC +0x1C address table — the CLEAN line table: 8-byte
    /// {u32 codeRVA, u16 line, u16 moduleIdx}, strictly RVA-ascending with NO line resets.
    /// moduleIdx partitions all code into compilands (one per code .clw), in .text LINK order
    /// (NOT module-name-array order — bind to a name by content/symbol, never by index rank).
    /// This is the primary address-&gt;line path (binary-search by RVA) and the per-proc tag source.
    /// </summary>
    public struct AddrRec
    {
        public uint Rva;
        public int Line;
        public int ModuleIdx;
        public AddrRec(uint rva, int line, int moduleIdx) { Rva = rva; Line = line; ModuleIdx = moduleIdx; }
    }

    /// <summary>Per-compiland summary derived from the +0x1C table's moduleIdx partition.</summary>
    public sealed class CompilandInfo
    {
        public int ModuleIdx;
        public uint EntryRva;     // lowest RVA for this moduleIdx (proc prologue, for these binaries)
        public uint HiRva;        // highest RVA
        public int RecordCount;
    }

    /// <summary>Kind of a code symbol, derived from Clarion's name mangling.</summary>
    public enum SymbolKind
    {
        Procedure,   // NAME@F or NAME@F<digits>          (top-level PROCEDURE)
        Method,      // NAME@F<len><CLASSNAME>...          (class method)
        Routine,     // R$PROC::ROUTINE                    (ROUTINE inside a proc)
        Other        // _main, clbrws$$$__attach_process … (runtime / compiler symbols)
    }

    /// <summary>
    /// One symbol DEFINITION from the TSWD blob: 12-byte little-endian
    /// {u32 nameRef, u32 entryRVA, u32 moduleBackref}, byte-granular (NOT aligned), scattered
    /// after the +0x28 backref array. The {nameRef, entryRVA} pair also appears at CALL SITES,
    /// so definitions are selected by requiring the 3rd field to be a valid +0x28 backref value
    /// (whose array index IS the moduleIdx) and skipping __thunk.* names (a thunk lives in the
    /// caller's module). See docs/TSWD-format.md and spikes/tswd-procsym-decode.ps1.
    /// </summary>
    public sealed class ProcSymbol
    {
        public string RawName;    // mangled, e.g. SELECTJOBS@F, R$BRW1::SELECTSORT, UPDATE@F8INICLASS
        public string Name;       // demangled, e.g. SELECTJOBS, BRW1::SELECTSORT, INICLASS.UPDATE
        public SymbolKind Kind;
        public uint EntryRva;     // canonical proc start (may sit ABOVE the module's +0x1C floor)
        public int ModuleIdx;     // == +0x08 name-array index == +0x1C moduleIdx
    }

    /// <summary>
    /// A contiguous ascending line-major RUN within Table A. Table A is ONE continuous 6-byte
    /// {u16 line, u32 rva} grid from blob+OffLineTableA; runs are delimited by line RESETS (the line
    /// number dropping back to ~9-17 at a compiland-group boundary), NOT by the +0x10 byte map (which
    /// is byte-chopped and decoupled from runs — see docs + spikes/tswd-runs.txt). Each run holds one
    /// compiland group; line numbers are CUMULATIVE across the procedures in the group (the first proc
    /// is base-0: table-line == .clw physical line; subsequent procs are appended and need a per-proc
    /// base derived from the proc's entry RVA — the symbol table). RVAs are ascending within a run.
    /// </summary>
    public sealed class LineRun
    {
        public int StartRecordIndex;   // index into the continuous grid (counts every 6-byte slot)
        public int StartByteOffset;    // blob-relative byte offset of the run's first record
        public int Phase;              // (StartByteOffset - OffLineTableA) % 6 — informational only
        public int LineMin, LineMax;
        public uint RvaMin, RvaMax;
        public List<LineRec> Records = new List<LineRec>();
        /// <summary>The +0x10 module whose byte-chunk contains this run's start. UNRELIABLE for
        /// content (orientation only) — trust RVA range + symbol-table proc entries instead.</summary>
        public string OwnerHint;

        public bool ContainsRva(uint rva) { return rva >= RvaMin && rva <= RvaMax; }
    }

    /// <summary>
    /// Parser for the Clarion "TSWD" embedded debug blob (TopSpeed Watcom Debug).
    /// Decodes the TOC header, module-name table, and both line-number tables.
    /// Layout reference: docs/TSWD-format.md.
    /// </summary>
    public sealed class TswdDebugInfo
    {
        public const uint TswdMagic = 0x44575354; // 'TSWD'

        private readonly byte[] _b;
        private readonly int _base; // file offset of the blob

        public int HeaderSize { get; private set; }
        /// <summary>Module count derived from the name-offset array geometry (authoritative).</summary>
        public int ModuleCount { get { return ModuleNames.Count; } }
        /// <summary>Raw value of the TOC +0x24 field (NOT the array length — keep for diagnostics).</summary>
        public int ModuleCountField { get; private set; }
        public List<string> ModuleNames { get; private set; }

        /// <summary>Line-major table (Table A): use for source-line -&gt; address (set breakpoint).</summary>
        public List<LineRec> ByLine { get; private set; }

        /// <summary>Address-major table (Table B): use for address -&gt; source-line (resolve a hit).</summary>
        public List<LineRec> ByAddr { get; private set; }

        /// <summary>Best-effort list of symbol names from the symbol string pool (not yet structured).</summary>
        public List<string> SymbolPool { get; private set; }

        /// <summary>Structured code-symbol definitions (procs/methods/routines/runtime), sorted by
        /// EntryRva. Built from the 12-byte definition records — see <see cref="ProcSymbol"/>.</summary>
        public List<ProcSymbol> Symbols { get; private set; }

        /// <summary>Per-module line sub-tables (LEGACY: sliced by the +0x10 byte map — mis-buckets
        /// records because the map cuts mid-run. Kept for diagnostics/compat; prefer <see cref="Runs"/>).</summary>
        public List<ModuleSlice> Modules { get; private set; }

        /// <summary>Table A decoded correctly: one continuous grid segmented into line-major runs
        /// (compiland groups). Cross-check / fallback for line&lt;-&gt;address (the +0x1C table is primary).</summary>
        public List<LineRun> Runs { get; private set; }

        /// <summary>The TOC +0x1C address table (clean, RVA-ascending {rva,line,moduleIdx}). PRIMARY
        /// path for address-&gt;line and the per-proc (moduleIdx) partition. See <see cref="AddrRec"/>.</summary>
        public List<AddrRec> AddrTable { get; private set; }

        /// <summary>Per-moduleIdx summary (entry/hi RVA, record count) from the +0x1C partition.</summary>
        public Dictionary<int, CompilandInfo> Compilands { get; private set; }

        // Raw TOC offsets (relative to blob base), exposed for diagnostics.
        public int OffModuleNameArray { get; private set; }
        public int OffModuleNamePool { get; private set; }
        public int OffModuleRange { get; private set; }
        public int OffLineTableA { get; private set; }
        public int OffLineTableB { get; private set; }
        public int OffTableAfterB { get; private set; }
        public int OffSymbolPool { get; private set; }
        public int OffSymbolNameArray { get; private set; }
        /// <summary>TOC +0x2C table offset (purpose not yet decoded — Phase 3 data-symbol candidate).</summary>
        public int OffTable2C { get; private set; }
        /// <summary>TOC +0x30 symbol count field — validates the definition-record scan.</summary>
        public int SymbolCountField { get; private set; }
        /// <summary>TOC +0x34 near-end table offset (purpose not yet decoded — Phase 3 candidate).</summary>
        public int OffTable34 { get; private set; }

        // .text bounds (RVA) used to validate record framing; 0..uint.Max disables the check.
        private readonly uint _textLo;
        private readonly uint _textHi;

        // Lazily-built global address index over all modules' records, sorted by RVA.
        private List<KeyValuePair<uint, ModuleSlice>> _addrIndex;

        private uint U32(int rel) { return BitConverter.ToUInt32(_b, _base + rel); }
        private ushort U16(int rel) { return BitConverter.ToUInt16(_b, _base + rel); }

        public static TswdDebugInfo FromPe(PeImage pe)
        {
            var e = pe.ReadFirstDebugEntry();
            if (e.Type != TswdMagic)
                throw new InvalidOperationException(
                    string.Format("Debug entry type 0x{0:X8} is not TSWD — was the EXE built with Full debug info?", e.Type));
            var t = pe.Text;
            uint lo = t != null ? t.VirtualAddress : 0;
            uint hi = t != null ? t.VirtualAddress + t.VirtualSize : uint.MaxValue;
            return new TswdDebugInfo(pe.Bytes, (int)e.PointerToRawData, lo, hi);
        }

        public TswdDebugInfo(byte[] bytes, int blobOffset)
            : this(bytes, blobOffset, 0, uint.MaxValue) { }

        public TswdDebugInfo(byte[] bytes, int blobOffset, uint textLo, uint textHi)
        {
            _b = bytes;
            _base = blobOffset;
            _textLo = textLo;
            _textHi = textHi;
            ModuleNames = new List<string>();
            Modules = new List<ModuleSlice>();
            ByLine = new List<LineRec>();
            ByAddr = new List<LineRec>();
            SymbolPool = new List<string>();

            if (U32(0) != TswdMagic)
                throw new InvalidOperationException("Bad TSWD magic at blob offset.");

            HeaderSize         = (int)U32(0x04);
            OffModuleNameArray = (int)U32(0x08);
            OffModuleNamePool  = (int)U32(0x0C);
            OffModuleRange     = (int)U32(0x10);
            OffLineTableA      = (int)U32(0x14);
            OffLineTableB      = (int)U32(0x18);
            OffTableAfterB     = (int)U32(0x1C);
            OffSymbolPool      = (int)U32(0x20);
            ModuleCountField   = (int)U32(0x24);
            OffSymbolNameArray = (int)U32(0x28);
            OffTable2C         = (int)U32(0x2C);
            SymbolCountField   = (int)U32(0x30);
            OffTable34         = (int)U32(0x34);

            // --- module names: iterate the u32 offset array up to the start of the string pool.
            // (The +0x24 count field is NOT the array length, so derive count from geometry.)
            for (int o = OffModuleNameArray; o + 4 <= OffModuleNamePool; o += 4)
            {
                uint nameOff = U32(o);
                ModuleNames.Add(ReadCString(OffModuleNamePool + (int)nameOff));
            }

            // --- per-module line sub-tables (authoritative). The +0x10 map gives each
            //     module's blob-relative byte slice into the [LineTableA, LineTableB) region. ---
            BuildModules();

            // --- v2: decode Table A as ONE continuous grid, segment into line-major runs by resets.
            //     This is the correct model (the +0x10 byte slices above cut mid-run). ---
            BuildRuns();

            // --- v2 primary: the TOC +0x1C address table — clean {u32 rva,u16 line,u16 moduleIdx},
            //     RVA-ascending, moduleIdx partitions code per-compiland. ---
            BuildAddrTable();

            // --- DIAGNOSTIC ONLY: flat parse of the same region. This drifts out of phase at
            //     module boundaries (slices are not 6-byte multiples) and is unreliable — kept
            //     only for comparison. Use Modules for real resolution. ---
            for (int o = OffLineTableA; o + 6 <= OffLineTableB; o += 6)
                ByLine.Add(new LineRec(U16(o), U32(o + 2)));
            for (int o = OffLineTableB; o + 6 <= OffTableAfterB; o += 6)
                ByAddr.Add(new LineRec(U16(o + 4), U32(o)));

            // --- symbol pool: scan null-terminated strings in [SymbolPool, SymbolNameArray) ---
            int i2 = OffSymbolPool;
            while (i2 < OffSymbolNameArray && _base + i2 < _b.Length)
            {
                int start = i2;
                while (i2 < OffSymbolNameArray && _b[_base + i2] != 0) i2++;
                if (i2 > start) SymbolPool.Add(ReadCStringRange(start, i2));
                i2++; // skip the NUL
            }

            // --- structured symbol definitions: 12-byte {nameRef, entryRVA, moduleBackref} ---
            BuildSymbols();
        }

        // ----- module-scoped line table -----

        private bool RecordValid(int line, uint rva)
        {
            return rva >= _textLo && rva < _textHi && line >= 1 && line < 20000;
        }

        private void BuildModules()
        {
            int n = ModuleNames.Count;
            for (int i = 0; i < n; i++)
            {
                int o = OffModuleRange + i * 8;
                uint s = U32(o);
                uint e = U32(o + 4);
                var ms = new ModuleSlice { Index = i, Name = ModuleNames[i], SliceStart = s, SliceEnd = e };
                // Only parse slices that point INTO the line-table region. A few app modules
                // (e.g. the MEMBER/data modules) carry small offsets below the region and would
                // otherwise yield garbage records that pollute the address index.
                ms.InRegion = ms.HasCode && s >= (uint)OffLineTableA && e <= (uint)OffLineTableB;
                if (ms.InRegion)
                {
                    ms.Phase = DetectPhase((int)s, (int)e);
                    for (int p = (int)s + ms.Phase; p + 6 <= (int)e; p += 6)
                    {
                        int line = U16(p);
                        uint rva = U32(p + 2);
                        if (RecordValid(line, rva))
                            ms.Records.Add(new LineRec(line, rva));
                    }
                }
                Modules.Add(ms);
            }
        }

        /// <summary>
        /// Decode Table A as a single continuous 6-byte {u16 line, u32 rva} grid from OffLineTableA and
        /// segment it into ascending line-major RUNS. A run ends at a line RESET (line drops below the
        /// run's running max by more than a small tolerance — a compiland-group boundary) or at an
        /// invalid record. Runs shorter than 3 records are dropped (stray noise). Mirrors the verified
        /// walker in spikes/tswd-run-walker.ps1 (reproduces spikes/tswd-runs.txt: 10 runs).
        /// </summary>
        private void BuildRuns()
        {
            Runs = new List<LineRun>();
            LineRun cur = null;
            int recIdx = 0;
            for (int p = OffLineTableA; p + 6 <= OffLineTableB; p += 6, recIdx++)
            {
                int line = U16(p);
                uint rva = U32(p + 2);
                if (!RecordValid(line, rva)) { CloseRun(ref cur); continue; }
                // Reset: a drop below the running max (>2 tolerates tiny non-monotonic noise within a run).
                if (cur != null && line < cur.LineMax - 2) CloseRun(ref cur);
                if (cur == null)
                {
                    cur = new LineRun
                    {
                        StartRecordIndex = recIdx,
                        StartByteOffset = p,
                        Phase = (p - OffLineTableA) % 6,
                        LineMin = line, LineMax = line,
                        RvaMin = rva, RvaMax = rva,
                        OwnerHint = OwnerNameAtByte(p)
                    };
                }
                if (line < cur.LineMin) cur.LineMin = line;
                if (line > cur.LineMax) cur.LineMax = line;
                if (rva < cur.RvaMin) cur.RvaMin = rva;
                if (rva > cur.RvaMax) cur.RvaMax = rva;
                cur.Records.Add(new LineRec(line, rva));
            }
            CloseRun(ref cur);
        }

        /// <summary>
        /// Parse the TOC +0x1C address table: 8-byte {u32 codeRVA, u16 line, u16 moduleIdx} records over
        /// [OffTableAfterB, OffSymbolPool). It is strictly RVA-ascending with no line resets — the clean
        /// address-&gt;line path. Also builds the per-moduleIdx compiland summary (entry/hi RVA, count).
        /// </summary>
        private void BuildAddrTable()
        {
            AddrTable = new List<AddrRec>();
            Compilands = new Dictionary<int, CompilandInfo>();
            for (int o = OffTableAfterB; o + 8 <= OffSymbolPool; o += 8)
            {
                uint rva = U32(o);
                int line = U16(o + 4);
                int modIdx = U16(o + 6);
                if (rva < _textLo || rva >= _textHi) continue;   // skip stray non-.text records
                AddrTable.Add(new AddrRec(rva, line, modIdx));

                CompilandInfo ci;
                if (!Compilands.TryGetValue(modIdx, out ci))
                {
                    ci = new CompilandInfo { ModuleIdx = modIdx, EntryRva = rva, HiRva = rva };
                    Compilands[modIdx] = ci;
                }
                if (rva < ci.EntryRva) ci.EntryRva = rva;
                if (rva > ci.HiRva) ci.HiRva = rva;
                ci.RecordCount++;
            }
            // The table is documented RVA-ascending; sort defensively so the binary search is safe
            // even if a future build reorders it.
            AddrTable.Sort((a, b) => a.Rva.CompareTo(b.Rva));
        }

        /// <summary>
        /// PRIMARY address-&gt;line: binary-search the +0x1C table for the greatest record RVA &lt;= target,
        /// returning its source line and moduleIdx. moduleIdx maps to a .clw via a content/symbol bind
        /// (done by the caller — it is link order, not name-array order). Returns false if no record precedes.
        /// </summary>
        public bool ResolveAddr(uint rva, out int line, out int moduleIdx, out uint recordRva)
        {
            line = 0; moduleIdx = -1; recordRva = 0;
            if (AddrTable == null || AddrTable.Count == 0) return false;
            int lo = 0, hi = AddrTable.Count - 1, ans = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (AddrTable[mid].Rva <= rva) { ans = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (ans < 0) return false;
            var r = AddrTable[ans];
            line = r.Line; moduleIdx = r.ModuleIdx; recordRva = r.Rva;
            return true;
        }

        /// <summary>line-&gt;RVAs within a compiland (moduleIdx) using the +0x1C table. Gate user
        /// breakpoints to lines within the file (the table carries cumulative-tail values past EOF).</summary>
        public List<uint> LineToRvasInModuleIdx(int moduleIdx, int line)
        {
            var list = new List<uint>();
            if (AddrTable != null)
                foreach (var r in AddrTable)
                    if (r.ModuleIdx == moduleIdx && r.Line == line) list.Add(r.Rva);
            return list;
        }

        // ----- structured symbol table (Phase 3) -----

        /// <summary>
        /// Scan [OffSymbolNameArray, blob end) byte-granularly for 12-byte symbol DEFINITION
        /// records (see <see cref="ProcSymbol"/>). Filters: nameRef must land on a NUL-preceded
        /// printable string inside the +0x20 pool, entryRVA must be in .text, and the 3rd field
        /// must be one of the +0x28 backref values (its index = moduleIdx). __thunk.* names are
        /// call-site artifacts, not definitions — skipped. Mirrors spikes/tswd-procsym-decode.ps1.
        /// </summary>
        private void BuildSymbols()
        {
            Symbols = new List<ProcSymbol>();
            int poolLen = OffSymbolNameArray - OffSymbolPool;
            if (poolLen <= 0) return;

            // +0x28 backref array: value -> module index. Length = the +0x24 count field (61 for
            // the reference build; one more than the 60-entry name array — the extra is a
            // runtime/error module with no name entry).
            var backrefs = new Dictionary<uint, int>();
            int nBack = ModuleCountField;
            for (int i = 0; i < nBack; i++)
            {
                int o = OffSymbolNameArray + i * 4;
                if (_base + o + 4 > _b.Length) break;
                uint v = U32(o);
                if (!backrefs.ContainsKey(v)) backrefs[v] = i;
            }

            var seen = new HashSet<string>();
            int end = _b.Length - _base - 12;
            for (int o = OffSymbolNameArray; o <= end; o++)
            {
                uint nameRef = U32(o);
                if (nameRef < 1 || nameRef >= (uint)poolLen) continue;
                uint rva = U32(o + 4);
                if (rva < _textLo || rva >= _textHi) continue;
                uint backref = U32(o + 8);
                int modIdx;
                if (!backrefs.TryGetValue(backref, out modIdx)) continue;
                string raw = SymbolNameAt((int)nameRef, poolLen);
                if (raw == null) continue;
                if (raw.StartsWith("__thunk.", StringComparison.Ordinal)) continue;
                if (!seen.Add(raw + "|" + rva)) continue;

                var sym = new ProcSymbol { RawName = raw, EntryRva = rva, ModuleIdx = modIdx };
                Demangle(raw, sym);
                Symbols.Add(sym);
            }
            Symbols.Sort((a, b) => a.EntryRva.CompareTo(b.EntryRva));
        }

        /// <summary>Validated name read for a pool-relative ref: must be NUL-preceded (a real
        /// string start), begin with a printable non-space char, and run printable to a NUL.</summary>
        private string SymbolNameAt(int rel, int poolLen)
        {
            int s = _base + OffSymbolPool + rel;
            if (s <= 0 || s >= _b.Length) return null;
            if (_b[s - 1] != 0) return null;
            if (_b[s] < 0x21 || _b[s] >= 0x7F) return null;
            int e = s;
            while (e < _b.Length && _b[e] >= 0x20 && _b[e] < 0x7F) e++;
            if (e >= _b.Length || _b[e] != 0) return null;
            return Encoding.ASCII.GetString(_b, s, e - s);
        }

        /// <summary>
        /// Derive Kind + display name from Clarion's mangling:
        ///   R$PROC::RTN / R$NAME   -> Routine   "PROC::RTN" / "NAME"
        ///   NAME@F / NAME@F123     -> Procedure "NAME"
        ///   NAME@F8CLASSNAME...    -> Method    "CLASSNAME.NAME" (len-prefixed class name)
        ///   anything else          -> Other     (raw, e.g. _main)
        /// </summary>
        private static void Demangle(string raw, ProcSymbol sym)
        {
            if (raw.StartsWith("R$", StringComparison.Ordinal) && raw.Length > 2)
            {
                sym.Kind = SymbolKind.Routine;
                sym.Name = raw.Substring(2);
                return;
            }
            int at = raw.IndexOf("@F", StringComparison.Ordinal);
            if (at > 0)
            {
                string head = raw.Substring(0, at);
                string tail = raw.Substring(at + 2);
                int d = 0;
                while (d < tail.Length && char.IsDigit(tail[d])) d++;
                if (d == tail.Length)
                {
                    sym.Kind = SymbolKind.Procedure;   // NAME@F or NAME@F<digits>
                    sym.Name = head;
                    return;
                }
                sym.Kind = SymbolKind.Method;
                int len;
                if (d > 0 && int.TryParse(tail.Substring(0, d), out len) && d + len <= tail.Length)
                    sym.Name = tail.Substring(d, len) + "." + head;
                else
                    sym.Name = head;                   // unparsed method mangling — keep the proc part
                return;
            }
            sym.Kind = SymbolKind.Other;
            sym.Name = raw;
        }

        /// <summary>
        /// Bind a code RVA to the symbol whose entry it falls under: the greatest EntryRva &lt;=
        /// the target (binary search over the sorted table). Because routines/methods are symbols
        /// too, this names stack frames at sub-procedure granularity. Returns false if no symbol
        /// precedes the address. NOTE: a proc can emit code BELOW its named entry (init/cold), so
        /// the floor of a module's +0x1C region may bind to the previous module's last symbol —
        /// callers that have a moduleIdx should cross-check it against <see cref="ProcSymbol.ModuleIdx"/>.
        /// </summary>
        public bool ResolveSymbol(uint rva, out ProcSymbol sym)
        {
            sym = null;
            if (Symbols == null || Symbols.Count == 0) return false;
            int lo = 0, hi = Symbols.Count - 1, ans = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (Symbols[mid].EntryRva <= rva) { ans = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (ans < 0) return false;
            sym = Symbols[ans];
            return true;
        }

        /// <summary>Commit a run if it carries enough records to be real (drops stray fragments).</summary>
        private void CloseRun(ref LineRun r)
        {
            if (r != null && r.Records.Count >= 3) Runs.Add(r);
            r = null;
        }

        /// <summary>The +0x10 module whose byte-chunk contains a blob-relative byte offset (orientation
        /// hint only — the +0x10 chunks are byte-chopped and do NOT bound runs).</summary>
        private string OwnerNameAtByte(int blobByteOffset)
        {
            uint b = (uint)blobByteOffset;
            foreach (var m in Modules)
                if (m.SliceEnd > m.SliceStart && b >= m.SliceStart && b < m.SliceEnd)
                    return m.Name;
            return "?";
        }

        /// <summary>Pick the 6-byte phase (0..5) that yields the most valid records in [start,end).</summary>
        private int DetectPhase(int start, int end)
        {
            int bestPhase = 0, bestGood = -1;
            for (int ph = 0; ph < 6; ph++)
            {
                int good = 0;
                for (int p = start + ph; p + 6 <= end; p += 6)
                    if (RecordValid(U16(p), U32(p + 2))) good++;
                if (good > bestGood) { bestGood = good; bestPhase = ph; }
            }
            return bestPhase;
        }

        private void EnsureAddrIndex()
        {
            if (_addrIndex != null) return;
            var list = new List<KeyValuePair<uint, ModuleSlice>>();
            foreach (var m in Modules)
                foreach (var r in m.Records)
                    list.Add(new KeyValuePair<uint, ModuleSlice>(r.Rva, m));
            list.Sort((a, b) => a.Key.CompareTo(b.Key));
            _addrIndex = list;
        }

        /// <summary>
        /// The +0x1C moduleIdx for a .clw module name. The +0x08 module-name-array index IS the
        /// moduleIdx (== the symbol moduleBackref index) — verified deterministically — so this is a
        /// direct index match against <see cref="ModuleNames"/>, NOT a content bind. Accepts the name
        /// with or without extension, case-insensitive. Returns -1 if not found.
        /// </summary>
        public int FindModuleIdx(string name)
        {
            if (string.IsNullOrEmpty(name)) return -1;
            for (int i = 0; i < ModuleNames.Count; i++)
            {
                string mn = ModuleNames[i];
                if (string.Equals(mn, name, StringComparison.OrdinalIgnoreCase)) return i;
                int dot = mn.LastIndexOf('.');
                string stem = dot > 0 ? mn.Substring(0, dot) : mn;
                if (string.Equals(stem, name, StringComparison.OrdinalIgnoreCase)) return i;
            }
            return -1;
        }

        /// <summary>The .clw module name for a moduleIdx (== ModuleNames[idx]); null if out of range.</summary>
        public string ModuleNameForIdx(int idx)
        {
            return (idx >= 0 && idx < ModuleNames.Count) ? ModuleNames[idx] : null;
        }

        /// <summary>The distinct source lines that carry a +0x1C code record for a compiland (moduleIdx) —
        /// the lines a breakpoint binds to exactly. Sorted ascending. Gate user picks to line &lt;= file
        /// length (the +0x1C table can carry cumulative-tail values past EOF).</summary>
        public List<int> BreakableLinesInModuleIdx(int moduleIdx)
        {
            var set = new SortedSet<int>();
            if (AddrTable != null)
                foreach (var r in AddrTable)
                    if (r.ModuleIdx == moduleIdx) set.Add(r.Line);
            return new List<int>(set);
        }

        public ModuleSlice FindModule(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            // match with or without extension, case-insensitive
            foreach (var m in Modules)
            {
                if (string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase)) return m;
                int dot = m.Name.LastIndexOf('.');
                string stem = dot > 0 ? m.Name.Substring(0, dot) : m.Name;
                if (string.Equals(stem, name, StringComparison.OrdinalIgnoreCase)) return m;
            }
            return null;
        }

        /// <summary>Source line -&gt; code RVAs within a specific module.</summary>
        public List<uint> LineToRvasInModule(string moduleName, int line)
        {
            var list = new List<uint>();
            var m = FindModule(moduleName);
            if (m != null)
                foreach (var r in m.Records) if (r.Line == line) list.Add(r.Rva);
            return list;
        }

        /// <summary>
        /// Find the nearest source line in a module that actually carries a code record. Clarion's
        /// TSWD line table is sparse and coarsely attributed (many source lines have no record), so a
        /// user-picked line frequently has no exact entry. Mirrors what VS/gdb do: prefer the smallest
        /// recorded line &gt;= the request (forward snap), else fall back to the largest recorded line
        /// &lt; the request. Returns the requested line if it has a record, or -1 if the module has none.
        /// </summary>
        public int NearestLineWithCode(string moduleName, int line)
        {
            var m = FindModule(moduleName);
            if (m == null || m.Records.Count == 0) return -1;
            int fwd = int.MaxValue, back = -1;
            foreach (var r in m.Records)
            {
                if (r.Line == line) return line;            // exact hit
                if (r.Line > line && r.Line < fwd) fwd = r.Line;
                if (r.Line < line && r.Line > back) back = r.Line;
            }
            return fwd != int.MaxValue ? fwd : back;        // records>0 guarantees one side is set
        }

        /// <summary>
        /// The distinct source lines in a module that carry a code record — i.e. the lines a
        /// breakpoint can actually bind to. Sorted ascending; empty if the module is unknown or has
        /// no records. The IDE gutter should offer breakpoints only on these lines (a pick on any
        /// other line gets snapped — see <see cref="NearestLineWithCode"/>).
        /// </summary>
        public List<int> BreakableLines(string moduleName)
        {
            var set = new SortedSet<int>();
            var m = FindModule(moduleName);
            if (m != null) foreach (var r in m.Records) set.Add(r.Line);
            return new List<int>(set);
        }

        /// <summary>Source line -&gt; (module, RVA) across all modules (line may exist in several).</summary>
        public List<KeyValuePair<ModuleSlice, uint>> LineToRvasAll(int line)
        {
            var list = new List<KeyValuePair<ModuleSlice, uint>>();
            foreach (var m in Modules)
                foreach (var r in m.Records)
                    if (r.Line == line) list.Add(new KeyValuePair<ModuleSlice, uint>(m, r.Rva));
            return list;
        }

        /// <summary>
        /// Resolve a code RVA to (module, line): the record with the greatest RVA &lt;= target
        /// across all modules' correctly-framed records. This is the engine's address-&gt;line path.
        /// </summary>
        public bool TryResolve(uint rva, out ModuleSlice module, out int line, out uint recordRva)
        {
            module = null; line = 0; recordRva = 0;
            EnsureAddrIndex();
            if (_addrIndex.Count == 0) return false;

            // binary search for greatest key <= rva
            int lo = 0, hi = _addrIndex.Count - 1, ans = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (_addrIndex[mid].Key <= rva) { ans = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (ans < 0) return false;
            recordRva = _addrIndex[ans].Key;
            module = _addrIndex[ans].Value;
            // find the line for this (rva, module) record
            foreach (var r in module.Records)
                if (r.Rva == recordRva) { line = r.Line; break; }
            return true;
        }

        private string ReadCString(int rel)
        {
            int start = _base + rel;
            int end = start;
            while (end < _b.Length && _b[end] != 0) end++;
            return Encoding.ASCII.GetString(_b, start, end - start);
        }

        private string ReadCStringRange(int relStart, int relEnd)
        {
            return Encoding.ASCII.GetString(_b, _base + relStart, relEnd - relStart);
        }

        /// <summary>All code RVAs generated for a given source line (across modules — may be ambiguous).</summary>
        public List<uint> RvasForLine(int line)
        {
            var list = new List<uint>();
            foreach (var r in ByLine) if (r.Line == line) list.Add(r.Rva);
            return list;
        }

        /// <summary>
        /// Resolve a code RVA (e.g. a breakpoint hit) to its source line: the record with the
        /// greatest Rva &lt;= the target. Returns false if no record precedes the address.
        /// </summary>
        public bool TryAddrToLine(uint rva, out int line, out uint recordRva)
        {
            line = 0; recordRva = 0; bool found = false;
            foreach (var r in ByAddr)
            {
                if (r.Rva <= rva && (!found || r.Rva > recordRva))
                {
                    recordRva = r.Rva; line = r.Line; found = true;
                }
            }
            return found;
        }
    }
}
