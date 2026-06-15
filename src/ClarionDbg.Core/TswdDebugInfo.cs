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

    /// <summary>One field of a GROUP/RECORD data symbol (a tag-0C member record).</summary>
    public sealed class DataField
    {
        public string Name;      // pool name, e.g. JOB:JOBID
        public uint Offset;      // byte offset within the parent record buffer
        public byte TypeCode;    // raw TSWD type code (0x11 SHORT, 0x12 BYTE, 0x18 STRING, ...)
        public uint Size;        // bytes; derived from the next field's offset when the type tail is complex
    }

    /// <summary>
    /// A static data symbol (tag-04 definition with its RVA outside .text): a plain global or a
    /// FILE record buffer (GROUP, with fields). The RVA is the link-time TEMPLATE address — for
    /// THREADed data (.cwtls) the per-thread instance may differ at runtime (see TSWD-format.md).
    /// </summary>
    public sealed class DataSymbol
    {
        public string Name;      // pool name, e.g. SAVEPATH or JOBS$JOB:RECORD
        public uint Rva;
        public int ModuleIdx;
        public byte TypeCode;    // 0x08 = GROUP/RECORD; 0 = unknown
        public uint Size;        // 0 = unknown
        public List<DataField> Fields;   // non-null when TypeCode is GROUP/RECORD
        public uint TypeRef;     // the record's typeRef (u32 at tag+1) — pointer to its TYPE record
        public ClarionType Type; // resolved aggregate layout (non-null when typeRef resolves); byte-exact members
    }

    /// <summary>Kind of a resolved TSWD type record (see <see cref="ClarionType"/>).</summary>
    public enum TypeKind { Unknown, Group, Array, String, Int, Uint, Float, Char, Decimal, PDecimal, Reference, Opaque }

    /// <summary>One member of a resolved GROUP type: name + byte offset within the group + its own type.</summary>
    public sealed class TypeMember
    {
        public string Name;
        public int Offset;
        public ClarionType Type;
    }

    /// <summary>
    /// A resolved TSWD TYPE record — followed from a 0x04/0x0C record's <c>typeRef</c> pointer (the u32 at
    /// tag+1). This is the byte-exact aggregate layout (GROUP member offsets, array descriptors, DECIMAL
    /// places) that lives in the TSWD blob itself — no .obj required. Decoded by
    /// <see cref="TswdDebugInfo.ResolveType"/>; ported from clarion-pdb typeref_probe.parse_type.
    /// </summary>
    public sealed class ClarionType
    {
        public uint TypeRef;      // this record's typeRef key (relative to OffTable2C) — for lazy re-resolution
        public byte Tag;          // raw type-record tag: 0x08 group, 0x18 array/string desc, 0x23/0x24 decimal, 0x11-0x14 scalar
        public TypeKind Kind;
        public uint Size;         // total byte size of the type
        public int Places;        // DECIMAL/PDECIMAL scale (digits after the point)
        public byte ElemTag;      // array element type tag (0x18 descriptor)
        public uint ElemSize;     // array element byte size (stride between elements)
        public int Length;        // array element count / STRING character count
        public int LoBound;       // array lower bound (Kind == Array); Clarion DIM is 1-based
        public ClarionType ElemType;      // Kind == Array: the element's resolved type (may be a GROUP -> tree)
        public List<TypeMember> Members;  // GROUP members (non-null only when Kind == Group)
        public ClarionType Referent;      // Kind == Reference: the pointed-at type (e.g. a by-ref GROUP/QUEUE)

        /// <summary>Map this resolved type to the flat (code,size,places) triple the shared engine value
        /// renderer understands, so a leaf member renders identically to a top-level scalar of that type.</summary>
        public void RenderHint(out byte code, out uint size, out int places)
        {
            code = 0; size = Size; places = 0;
            switch (Kind)
            {
                case TypeKind.Int:      code = 0x11; break;
                case TypeKind.Uint:     code = 0x12; break;
                case TypeKind.Float:    code = 0x13; break;
                case TypeKind.Char:     code = 0x18; break;                 // a bare CHAR -> STRING(size)
                case TypeKind.String:   code = 0x18; size = (uint)Length; break;
                case TypeKind.Decimal:  code = 0x23; places = Places; break;
                case TypeKind.PDecimal: code = 0x24; places = Places; break;
                case TypeKind.Group:    code = 0x08; break;
                case TypeKind.Opaque:   code = 0x10; size = 4; break;       // opaque stub (window / forward class) — no members
                case TypeKind.Reference: code = 0x16; size = 4; break;      // a pointer (by-ref)
                default:                code = 0x00; break;                 // array / unknown — composite
            }
        }
    }

    /// <summary>
    /// A local variable or parameter of a procedure (a tag-04 record in the +0x2C tree whose 2nd
    /// field is a NEGATIVE frame-pointer-relative offset, scoped to the most recent preceding proc
    /// record). The live value lives at [frame-pointer + FrameOff] on the paused thread.
    /// Ported from clarion-pdb read_locals (DiscoverClarion); coverage is partial — by-ref params
    /// (positive offsets above the frame ptr) are not yet captured.
    /// </summary>
    public sealed class LocalSym
    {
        public string Name;       // pool name, e.g. LOC:COUNTER
        public int FrameOff;      // frame-pointer-relative byte offset (negative = below the frame ptr)
        public byte TypeCode;     // Clarion type code (0x11 LONG, 0x18 STRING, 0x16 ref, 0x23 DECIMAL, ...)
        public byte Target;       // for a reference (0x16): the referent's type code (0x18 STRING, 0x08 group)
        public uint Size;         // char count (STRING) / byte width (scalar, DECIMAL); 0 = unknown
        public int Places;        // DECIMAL/PDECIMAL scale (digits after the point)
        public uint TypeRef;      // the record's typeRef (u32 at tag+1) — pointer to its TYPE record
        public ClarionType Type;  // resolved aggregate layout (non-null when typeRef resolves to a GROUP)
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

        /// <summary>Static data symbols (globals + file record buffers with fields), sorted by Rva.
        /// Same definition records as <see cref="Symbols"/> but with the RVA in a data section.</summary>
        public List<DataSymbol> DataSymbols { get; private set; }

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
        // end of the highest section (RVA) — bounds data-symbol RVA validation.
        private readonly uint _imageHi;

        // Lazily-built global address index over all modules' records, sorted by RVA.
        private List<KeyValuePair<uint, ModuleSlice>> _addrIndex;

        private uint U32(int rel) { return BitConverter.ToUInt32(_b, _base + rel); }
        private ushort U16(int rel) { return BitConverter.ToUInt16(_b, _base + rel); }

        // Bounds-checked blob reads (return 0 when out of range) — used by the type-record walk, which
        // chases pointers to arbitrary offsets and must never throw on a malformed/short blob.
        private uint SU32(int rel) { int i = _base + rel; return (i >= 0 && i + 4 <= _b.Length) ? BitConverter.ToUInt32(_b, i) : 0; }
        private int SI32(int rel) { int i = _base + rel; return (i >= 0 && i + 4 <= _b.Length) ? BitConverter.ToInt32(_b, i) : 0; }
        private byte SB(int rel) { int i = _base + rel; return (i >= 0 && i < _b.Length) ? _b[i] : (byte)0; }

        public static TswdDebugInfo FromPe(PeImage pe)
        {
            var e = pe.ReadFirstDebugEntry();
            if (e.Type != TswdMagic)
                throw new InvalidOperationException(
                    string.Format("Debug entry type 0x{0:X8} is not TSWD — was the EXE built with Full debug info?", e.Type));
            return Build(pe, e.PointerToRawData);
        }

        /// <summary>Non-throwing variant: returns null when the image carries no TSWD debug info
        /// (no debug directory, or a debug entry of a different type). Used to tier loaded modules
        /// — a DLL with TSWD becomes debuggable; one without is registered base+size only.</summary>
        public static TswdDebugInfo TryFromPe(PeImage pe)
        {
            PeImage.DebugEntry e;
            if (!pe.TryReadFirstDebugEntry(out e) || e.Type != TswdMagic) return null;
            try { return Build(pe, e.PointerToRawData); }
            catch { return null; }
        }

        private static TswdDebugInfo Build(PeImage pe, uint blobFileOffset)
        {
            var t = pe.Text;
            uint lo = t != null ? t.VirtualAddress : 0;
            uint hi = t != null ? t.VirtualAddress + t.VirtualSize : uint.MaxValue;
            uint imageHi = 0;
            foreach (var s in pe.Sections)
                if (s.VirtualAddress + s.Span > imageHi) imageHi = s.VirtualAddress + s.Span;
            return new TswdDebugInfo(pe.Bytes, (int)blobFileOffset, lo, hi, imageHi);
        }

        public TswdDebugInfo(byte[] bytes, int blobOffset)
            : this(bytes, blobOffset, 0, uint.MaxValue, uint.MaxValue) { }

        public TswdDebugInfo(byte[] bytes, int blobOffset, uint textLo, uint textHi)
            : this(bytes, blobOffset, textLo, textHi, uint.MaxValue) { }

        public TswdDebugInfo(byte[] bytes, int blobOffset, uint textLo, uint textHi, uint imageHi)
        {
            _b = bytes;
            _base = blobOffset;
            _textLo = textLo;
            _textHi = textHi;
            _imageHi = imageHi;
            ModuleNames = new List<string>();
            Modules = new List<ModuleSlice>();
            ByLine = new List<LineRec>();
            ByAddr = new List<LineRec>();
            SymbolPool = new List<string>();
            DataSymbols = new List<DataSymbol>();

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
            // Reject addresses outside this image's code section. All line records live in .text, so an
            // address beyond it (a thread paused inside a system call, or broken in the OS such as
            // ntdll!DbgBreakPoint after a DebugBreak) would otherwise falsely bind to the last record
            // with an absurd gap.
            if (_textHi != uint.MaxValue && (rva < _textLo || rva >= _textHi)) return false;
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

        // Lazily-built indexes for fast, correct definition-line lookup (built once; this object is
        // per-image and immutable after load): per-module AddrTable slices (each ascending by Rva), and
        // the sorted set of symbol entry RVAs (for the next-symbol upper bound).
        private Dictionary<int, List<AddrRec>> _addrByModule;
        private uint[] _sortedEntries;
        private void EnsureDefIndexes()
        {
            if (_addrByModule != null) return;
            var map = new Dictionary<int, List<AddrRec>>();
            if (AddrTable != null)
                foreach (var r in AddrTable)   // AddrTable is sorted by Rva → each per-module slice stays sorted
                {
                    List<AddrRec> lst;
                    if (!map.TryGetValue(r.ModuleIdx, out lst)) { lst = new List<AddrRec>(); map[r.ModuleIdx] = lst; }
                    lst.Add(r);
                }
            int n = Symbols != null ? Symbols.Count : 0;
            var entries = new uint[n];
            for (int i = 0; i < n; i++) entries[i] = Symbols[i].EntryRva;
            Array.Sort(entries);
            _sortedEntries = entries;
            _addrByModule = map;   // set last: makes EnsureDefIndexes idempotent under concurrent reads
        }

        /// <summary>Definition line for a procedure/method symbol. The proc OWNS [EntryRva, nextEntry);
        /// its definition line is the FIRST same-module +0x1C record in that range. Bounding to the proc's
        /// OWN range is what makes this correct in multi-method modules (library .clw files carry many
        /// methods): records BELOW the entry belong to the previous proc, and records at/above the next
        /// symbol's entry belong to the next proc. Returns 0 when the proc has no own line record (no
        /// source / not navigable) so callers can drop it rather than misnavigate. O(log n) via the
        /// per-module slices + sorted entry index.</summary>
        public int DefinitionLine(ProcSymbol s)
        {
            if (s == null) return 0;
            EnsureDefIndexes();
            uint entry = s.EntryRva;
            // upper bound = smallest symbol entry strictly greater than this one (binary upper_bound)
            uint upper = uint.MaxValue;
            { int lo = 0, hi = _sortedEntries.Length - 1;
              while (lo <= hi) { int mid = (lo + hi) >> 1; if (_sortedEntries[mid] > entry) { upper = _sortedEntries[mid]; hi = mid - 1; } else lo = mid + 1; } }
            List<AddrRec> slice;
            if (!_addrByModule.TryGetValue(s.ModuleIdx, out slice) || slice.Count == 0) return 0;
            // first same-module record with Rva >= entry (binary lower_bound), valid only if within [entry, upper)
            int a = 0, b = slice.Count - 1, ans = -1;
            while (a <= b) { int mid = (a + b) >> 1; if (slice[mid].Rva >= entry) { ans = mid; b = mid - 1; } else a = mid + 1; }
            if (ans < 0) return 0;
            var rec = slice[ans];
            return rec.Rva < upper ? rec.Line : 0;
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
                bool inText = rva >= _textLo && rva < _textHi;
                bool inData = !inText && rva >= 0x1000 && rva < _imageHi;
                if (!inText && !inData) continue;
                uint backref = U32(o + 8);
                int modIdx;
                if (!backrefs.TryGetValue(backref, out modIdx)) continue;
                string raw = SymbolNameAt((int)nameRef, poolLen);
                if (raw == null) continue;
                if (raw.StartsWith("__thunk.", StringComparison.Ordinal)) continue;
                if (!seen.Add(raw + "|" + rva)) continue;

                if (inText)
                {
                    var sym = new ProcSymbol { RawName = raw, EntryRva = rva, ModuleIdx = modIdx };
                    Demangle(raw, sym);
                    Symbols.Add(sym);
                }
                else
                {
                    DataSymbols.Add(BuildDataSymbol(o, raw, rva, modIdx, poolLen));
                }
            }
            Symbols.Sort((a, b) => a.EntryRva.CompareTo(b.EntryRva));
            DataSymbols.Sort((a, b) => a.Rva.CompareTo(b.Rva));
            BuildDataNameIndex();
        }

        /// <summary>
        /// Complete a data symbol from its definition record. The record is
        /// `04 link nameRef rva backref` with type info following the 12-byte triple (which starts
        /// at o): flags @o+12, type code @o+13, u32 size @o+14. GROUP/RECORD (0x08) additionally
        /// carries u32 fieldCount @o+18, a child-pointer array, and the field member records
        /// (tag 0x0C) FOLLOWING it in the stream, each holding parentRef == this record's link
        /// value @o-4 — that exact-match key is how fields are bound (see TSWD-format.md).
        /// </summary>
        private DataSymbol BuildDataSymbol(int o, string name, uint rva, int modIdx, int poolLen)
        {
            var ds = new DataSymbol { Name = name, Rva = rva, ModuleIdx = modIdx };
            if (_base + o + 22 > _b.Length) return ds;

            // The u32 at tag+1 (here o-4 — the "link" the legacy field-scan below only used as a match key)
            // is the record's typeRef. Follow it for the byte-exact aggregate layout; when it resolves to a
            // GROUP, take its members + size verbatim and skip the heuristic forward-scan. (The scan stays as
            // a fallback for records whose typeRef doesn't resolve to a group.)
            ds.TypeRef = U32(o - 4);
            ds.Type = ResolveType(ds.TypeRef);
            if (ds.Type != null && ds.Type.Kind == TypeKind.Group && ds.Type.Members != null && ds.Type.Members.Count > 0)
            {
                ds.TypeCode = 0x08;
                if (ds.Type.Size > 0 && ds.Type.Size <= 0x100000) ds.Size = ds.Type.Size;
                ds.Fields = BuildFieldsFromType(ds.Type);
                return ds;
            }

            // Type tail uses a discriminator byte @o+12 (matches clarion-pdb read_globals, the proven
            // typed-globals decoder):
            //   disc == 0x00  -> aggregate form:      kind @o+13, u32 size @o+14
            //   disc != 0x00  -> scalar/string form:  kind == disc @o+12, u32 size @o+13
            // The old code only read the aggregate offsets and bailed on disc != 0, so it dropped (or
            // mis-sized) every scalar/string global.
            byte disc = _b[_base + o + 12];
            byte code; uint size;
            if (disc == 0x00) { code = _b[_base + o + 13]; size = U32(o + 14); }
            else              { code = disc;               size = U32(o + 13); }
            // A STRING/CSTRING/PSTRING's real character count lives in the string leaf at o+36 (== tag+41,
            // the SAME leaf read_locals uses for inline strings) — NOT the o+14/o+13 field, which holds a
            // type descriptor (e.g. STRING(20) reads 8289 there). Take the leaf count when present.
            if (code == 0x18 && _base + o + 40 <= _b.Length) size = U32(o + 36);
            if (size == 0 || size > 0x100000) return ds;  // implausible
            ds.TypeCode = code;
            ds.Size = size;

            if (!(disc == 0x00 && code == 0x08)) return ds;   // only true aggregates carry member records

            // GROUP/RECORD: field count + child-ptr array, then the tag-0C field records.
            uint count = U32(o + 18);
            if (count == 0 || count > 512) return ds;
            ds.Fields = new List<DataField>();
            uint parentKey = U32(o - 4);                  // this record's link value
            int p = o + 22 + (int)count * 4;              // just past the child-pointer array
            int window = p + 0x8000;                      // generous scan window for big records
            while (p + 22 <= _b.Length - _base && p < window && ds.Fields.Count < (int)count)
            {
                if (_b[_base + p] == 0x0C && U32(p + 13) == parentKey)
                {
                    uint fNameRef = U32(p + 5);
                    uint fOff = U32(p + 9);
                    string fName = fNameRef >= 1 && fNameRef < (uint)poolLen
                        ? SymbolNameAt((int)fNameRef, poolLen) : null;
                    if (fName != null && fOff < ds.Size)
                    {
                        byte fType = _b[_base + p + 17];
                        uint fSize = U32(p + 18);
                        if (fSize == 0 || fSize > ds.Size) fSize = 0;   // complex tail — derive later
                        ds.Fields.Add(new DataField { Name = fName, Offset = fOff, TypeCode = fType, Size = fSize });
                        p += 17;                          // past the fixed head; tails vary
                        continue;
                    }
                }
                p++;
            }

            // derive sizes the simple {type,u32 size} parse couldn't give (e.g. STRING tails):
            // a field runs to the next field's offset (last field runs to the record's end).
            ds.Fields.Sort((a, b) => a.Offset.CompareTo(b.Offset));
            for (int i = 0; i < ds.Fields.Count; i++)
            {
                uint limit = i + 1 < ds.Fields.Count ? ds.Fields[i + 1].Offset : ds.Size;
                uint span = limit > ds.Fields[i].Offset ? limit - ds.Fields[i].Offset : 0;
                if (ds.Fields[i].Size == 0 || ds.Fields[i].Size > span) ds.Fields[i].Size = span;
            }
            return ds;
        }

        /// <summary>Flatten a resolved GROUP's TOP-LEVEL members into the legacy <see cref="DataField"/> list
        /// (name + offset + render code + size). The full nested tree lives in <see cref="DataSymbol.Type"/>;
        /// this keeps the CLI text dump and the watch name-index working unchanged.</summary>
        private static List<DataField> BuildFieldsFromType(ClarionType g)
        {
            var fields = new List<DataField>();
            if (g == null || g.Members == null) return fields;
            foreach (var mb in g.Members)
            {
                if (mb.Type == null) continue;
                mb.Type.RenderHint(out byte code, out uint size, out int places);
                fields.Add(new DataField { Name = mb.Name ?? "?", Offset = (uint)mb.Offset, TypeCode = code, Size = size });
            }
            return fields;
        }

        // local variables / parameters per procedure (entry RVA -> locals), from the +0x2C tree.
        private Dictionary<uint, List<LocalSym>> _locals;

        /// <summary>Local variables + parameters for each procedure, keyed by proc ENTRY RVA. A local is a
        /// tag-04/05 record whose 2nd field is a NEGATIVE frame offset (vs a proc's .text entry RVA or a
        /// global's data RVA), scoped lexically to the most recent preceding proc record. Lazily built and
        /// cached. Ported from clarion-pdb read_locals (the proven PDB-generation spec); see <see cref="LocalSym"/>.</summary>
        public Dictionary<uint, List<LocalSym>> ReadLocals()
        {
            if (_locals != null) return _locals;
            var outMap = new Dictionary<uint, List<LocalSym>>();
            int poolLen = OffSymbolNameArray - OffSymbolPool;
            int end = OffTable34;
            if (_base + end > _b.Length) end = _b.Length - _base;   // clamp to the blob so reads stay in range
            uint cur = 0; bool haveCur = false;                     // current proc entry RVA (lexical scope)
            for (int p = OffTable2C; p >= 0 && p + 19 <= end; p++)
            {
                byte tag = _b[_base + p];
                if (tag != 0x04 && tag != 0x05) continue;
                uint nameRef = U32(p + 5);
                if (nameRef < 1 || nameRef >= (uint)poolLen) continue;
                string nm = SymbolNameAt((int)nameRef, poolLen);
                if (nm == null) continue;

                uint f3 = U32(p + 9);
                if (f3 >= _textLo && f3 < _textHi)                  // proc: 2nd field is an entry RVA in .text
                {
                    cur = f3; haveCur = true;
                    if (!outMap.ContainsKey(cur)) outMap[cur] = new List<LocalSym>();
                }
                else if ((f3 & 0x80000000) != 0 && haveCur)         // negative 2nd field -> a local of `cur`
                {
                    // Skip compiler-synthesized references to GLOBAL entities (threaded globals like
                    // GlobalResponse, file RELATE/ACCESS managers, record buffers). They live on the stack
                    // as pointers but are NOT user locals; their mangled names are decorated $NAME' / NAME'
                    // (leading '$' / trailing apostrophe) — neither is legal in a Clarion identifier.
                    if (nm[0] == '$' || nm[nm.Length - 1] == '\'') continue;

                    int frameOff = BitConverter.ToInt32(_b, _base + p + 9);
                    byte code = _b[_base + p + 18];                 // typecode (after the storage byte @+17)
                    // reject corrupt / false-positive records: a real local has a type and sits within a
                    // sane distance below the frame pointer (the naive byte-scan can match junk, e.g. a
                    // HASCHILDREN record decoded with code 0x00 at frame offset -1.35e9).
                    if (code == 0x00 || frameOff >= 0 || frameOff < -0x100000) continue;
                    byte target = 0; uint size = 0; int places = 0;
                    if (code == 0x16)                              // reference
                    {
                        if (p + 23 < end) target = _b[_base + p + 23];
                        if (target == 0x18 && p + 50 <= end) size = U32(p + 46);   // &STRING char count
                    }
                    else if (code == 0x18 && p + 45 <= end) size = U32(p + 41);    // inline STRING/CSTRING/PSTRING
                    else if ((code == 0x11 || code == 0x12 || code == 0x13 || code == 0x25) && p + 23 <= end)
                        size = U32(p + 19);                                        // scalar byte width
                    else if ((code == 0x23 || code == 0x24) && p + 24 <= end)      // DECIMAL / PDECIMAL
                    {
                        size = U32(p + 19);
                        places = _b[_base + p + 23];
                    }
                    if (size > 0xFFFF) size = 0;   // implausible — a misread tail; treat as unknown
                    // The u32 at tag+1 is the record's typeRef: follow it for the byte-exact aggregate
                    // layout (GROUP members, array/DECIMAL geometry) the inline scalar decode can't give.
                    uint typeRef = U32(p + 1);
                    // Resolve aggregates: a direct GROUP/QUEUE (0x08), a class-instance-by-value (0x04, e.g.
                    // `Toolbar ToolbarClass` — its typeRef also points straight at a 0x08 group), or any
                    // reference (0x16) — the latter may point at a by-ref GROUP/QUEUE/CLASS/WINDOW (resolved
                    // transparently via the type record's referent).
                    ClarionType aggr = (code == 0x04 || code == 0x08 || code == 0x16) ? ResolveType(typeRef) : null;
                    outMap[cur].Add(new LocalSym { Name = nm, FrameOff = frameOff, TypeCode = code,
                                                   Target = target, Size = size, Places = places,
                                                   TypeRef = typeRef, Type = aggr });
                }
            }
            _locals = outMap;
            return _locals;
        }

        // ----- typeRef aggregate layout (GROUP/array/DECIMAL member offsets, from the blob alone) -----

        // typeRef -> decoded type record (shared cache; also breaks reference cycles between records).
        private Dictionary<uint, ClarionType> _typeCache;

        /// <summary>
        /// Follow a record's <c>typeRef</c> (the u32 at tag+1 of a 0x04/0x0C record) to its separate TYPE
        /// record and decode the byte-exact aggregate layout: GROUP size/count/members, array/string
        /// descriptors, DECIMAL places, scalar widths. Faithful port of clarion-pdb typeref_probe.parse_type.
        ///
        /// THE BASE (the bit everyone got wrong): every ref — typeRef, memberRef — is relative to the
        /// record-stream START, which is dir[9] == <see cref="OffTable2C"/> (TOC +0x2C), and the ref points
        /// DIRECTLY at the type record's tag byte (no +4). dir[8] (<see cref="OffSymbolNameArray"/>, TOC +0x28)
        /// is a per-module base ARRAY that precedes the stream; using it is the module_count==1 degenerate
        /// (dir[9] == dir[8] + 4*moduleCount) — it works on single-module test binaries and lands in
        /// neighbouring records on multi-module apps. Returns null when the ref is out of range. Cached.
        /// </summary>
        public ClarionType ResolveType(uint typeRef)
        {
            if (_typeCache == null) _typeCache = new Dictionary<uint, ClarionType>();
            return ParseType(typeRef, 0);
        }

        // A ref is valid if OffTable2C + ref lands inside the record stream [OffTable2C, OffTable34).
        private bool ValidRef(uint refv)
        {
            long o = (long)OffTable2C + refv;
            return o >= OffTable2C && o + 1 <= OffTable34 && _base + o + 1 <= _b.Length;
        }

        private ClarionType ParseType(uint typeRef, int depth)
        {
            if (_typeCache.TryGetValue(typeRef, out ClarionType cached)) return cached;
            if (!ValidRef(typeRef) || depth > 16) return null;

            var t = new ClarionType { TypeRef = typeRef };
            _typeCache[typeRef] = t;                 // seed BEFORE recursing so cyclic refs terminate
            int o = OffTable2C + (int)typeRef;        // the type record's tag byte (blob-relative)
            byte tag = SB(o);
            t.Tag = tag;
            switch (tag)
            {
                case 0x11: t.Kind = TypeKind.Int;   t.Size = SU32(o + 1); break;
                case 0x12: t.Kind = TypeKind.Uint;  t.Size = SU32(o + 1); break;
                case 0x13: t.Kind = TypeKind.Float; t.Size = SU32(o + 1); break;
                case 0x14: t.Kind = TypeKind.Char;  t.Size = SU32(o + 1); break;
                case 0x23: t.Kind = TypeKind.Decimal;  t.Size = SU32(o + 1); t.Places = SB(o + 5); break;
                case 0x24: t.Kind = TypeKind.PDecimal; t.Size = SU32(o + 1); t.Places = SB(o + 5); break;
                case 0x08:
                {
                    t.Kind = TypeKind.Group;
                    t.Size = SU32(o + 1);
                    uint count = SU32(o + 5);
                    t.Members = new List<TypeMember>();
                    int poolLen = OffSymbolNameArray - OffSymbolPool;
                    int max = (int)Math.Min(count, 1024u);
                    for (int i = 0; i < max; i++)
                    {
                        uint mref = SU32(o + 9 + 4 * i);
                        if (!ValidRef(mref)) continue;
                        int mb = OffTable2C + (int)mref;        // member record's tag byte
                        byte mtag = SB(mb);
                        if (mtag != 0x04 && mtag != 0x0C) continue;
                        uint mType = SU32(mb + 1);
                        uint mNameRef = SU32(mb + 5);
                        int mOff = SI32(mb + 9);
                        string mName = mNameRef >= 1 && poolLen > 0 && mNameRef < (uint)poolLen
                            ? SymbolNameAt((int)mNameRef, poolLen) : null;
                        t.Members.Add(new TypeMember { Name = mName, Offset = mOff, Type = ParseType(mType, depth + 1) });
                    }
                    break;
                }
                case 0x16:
                    // A reference type record: the u32 at +1 (innerRef) points at the referent's type record.
                    // This is the extra hop a by-ref GROUP/QUEUE/CLASS needs (e.g. a browse QUEUE:BROWSE:n is a
                    // 0x16 ref -> the 0x08 queue group). The variable itself holds a pointer; the caller derefs
                    // it before reading members. Verified byte-exact on school.exe + TestDashboard.exe.
                    t.Kind = TypeKind.Reference;
                    t.Size = 4;
                    t.Referent = ParseType(SU32(o + 1), depth + 1);
                    break;
                case 0x10:
                    // OPAQUE type: a stub with NO member layout (the record is just `10 00 00 00 00`).
                    // Used INDISTINGUISHABLY for a WINDOW (which has no member layout) AND for by-ref
                    // class members the compiler emitted only a stub for (e.g. BrowseClass via a
                    // BROWSEMANAGER ref). Byte-identical to a real window, so we must NOT claim "WINDOW".
                    // Marked opaque so the renderer shows a non-expandable leaf rather than a bad tree.
                    t.Kind = TypeKind.Opaque;
                    t.Size = 4;
                    break;
                case 0x18:
                {
                    // array/string descriptor: 18 <elemTypeRef@+1> <descRef@+5> followed by the INLINED element
                    // type record and the INLINED 0x0f dimension descriptor. The element TYPE is the typeRef at
                    // +1 (resolve it — may be a GROUP, which gives an array-of-group its member tree); the BOUNDS
                    // are in the 0x0f descriptor referenced at +5: lobound@+5, count@+9. (The old decode read the
                    // count at a fixed +23, which only lands right when the element is a 5-byte CHAR — i.e. a
                    // STRING; for a group element it read garbage, so arrays never expanded.)
                    uint elemRef = SU32(o + 1);
                    ClarionType elem = ParseType(elemRef, depth + 1);
                    int lo = 1, count = 0;
                    uint descRef = SU32(o + 5);
                    if (ValidRef(descRef))
                    {
                        int d = OffTable2C + (int)descRef;
                        if (SB(d) == 0x0f) { lo = SI32(d + 5); count = (int)SU32(d + 9); }
                    }
                    if (count < 0 || count > 0xFFFFFF) count = 0;
                    byte elemTag = elem != null ? elem.Tag : SB(o + 9);
                    uint elemSize = elem != null && elem.Size > 0 ? elem.Size : SU32(o + 10);
                    if (elemTag == 0x14 && (elem == null || elem.Kind == TypeKind.Char))
                    {
                        // an array of CHAR is, to the user, a STRING(count)
                        t.Kind = TypeKind.String; t.Length = count; t.Size = (uint)count;
                    }
                    else
                    {
                        t.Kind = TypeKind.Array; t.ElemTag = elemTag; t.ElemSize = elemSize;
                        t.ElemType = elem; t.Length = count; t.LoBound = lo;
                        t.Size = elemSize * (uint)count;
                    }
                    break;
                }
                default:
                    t.Kind = TypeKind.Unknown;
                    break;
            }
            return t;
        }

        // name -> resolved location for watch-by-name (statics + record fields, case-insensitive)
        private Dictionary<string, DataLocation> _dataNames;

        /// <summary>A resolved data name: absolute (image-relative) RVA + type/size + container.</summary>
        public struct DataLocation
        {
            public uint Rva;
            public byte TypeCode;
            public uint Size;
            public string Container;   // the record-buffer symbol a field belongs to; null for statics
            public int ModuleIdx;
        }

        private void BuildDataNameIndex()
        {
            _dataNames = new Dictionary<string, DataLocation>(StringComparer.OrdinalIgnoreCase);
            foreach (var ds in DataSymbols)
            {
                if (!_dataNames.ContainsKey(ds.Name))
                    _dataNames[ds.Name] = new DataLocation { Rva = ds.Rva, TypeCode = ds.TypeCode, Size = ds.Size, Container = null, ModuleIdx = ds.ModuleIdx };
                if (ds.Type != null && ds.Type.Members != null)
                    RegisterTypeLeaves(ds.Name, ds.Rva, ds.Type, ds.ModuleIdx);   // byte-exact, recurses nested groups
                else if (ds.Fields != null)
                    foreach (var f in ds.Fields)
                        if (!_dataNames.ContainsKey(f.Name))
                            _dataNames[f.Name] = new DataLocation { Rva = ds.Rva + f.Offset, TypeCode = f.TypeCode, Size = f.Size, Container = ds.Name, ModuleIdx = ds.ModuleIdx };
            }
        }

        // Register every leaf member of a resolved GROUP by name -> absolute RVA, so watch-by-name resolves
        // nested group fields too. Groups are recursed into; only leaves get a watchable location.
        private void RegisterTypeLeaves(string container, uint groupRva, ClarionType g, int moduleIdx)
        {
            if (g == null || g.Members == null) return;
            foreach (var mb in g.Members)
            {
                if (mb.Type == null || string.IsNullOrEmpty(mb.Name)) continue;
                uint rva = (uint)(groupRva + mb.Offset);
                if (mb.Type.Kind == TypeKind.Group)
                    RegisterTypeLeaves(container, rva, mb.Type, moduleIdx);
                else if (!_dataNames.ContainsKey(mb.Name))
                {
                    mb.Type.RenderHint(out byte code, out uint size, out int places);
                    _dataNames[mb.Name] = new DataLocation { Rva = rva, TypeCode = code, Size = size, Container = container, ModuleIdx = moduleIdx };
                }
            }
        }

        /// <summary>
        /// Resolve a data name (global static, record-buffer symbol, or record field like
        /// JOB:JOBID) to its template RVA + type/size. Case-insensitive exact match. NOTE:
        /// THREADed (.cwtls) data resolves to the link-time template instance — the active
        /// thread's instance may live elsewhere (runtime resolution is a later phase).
        /// </summary>
        public bool ResolveDataName(string name, out DataLocation loc)
        {
            loc = default(DataLocation);
            if (string.IsNullOrEmpty(name) || _dataNames == null) return false;
            return _dataNames.TryGetValue(name, out loc);
        }

        /// <summary>Clarion type name for a TSWD type code — PROVEN codes only (validated against
        /// the clbrws dictionary); null for codes not yet confirmed. Render unknowns as hex.</summary>
        public static string TypeCodeName(byte code)
        {
            switch (code)
            {
                case 0x08: return "GROUP";
                case 0x11: return "SHORT";
                case 0x12: return "BYTE";
                case 0x18: return "STRING";
                default: return null;
            }
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
            // Reject addresses outside this image's code (e.g. a paused thread in a system call, or one
            // broken in the OS) — they would otherwise bind to the last symbol and mislabel an external
            // frame as Clarion code.
            if (_textHi != uint.MaxValue && (rva < _textLo || rva >= _textHi)) return false;
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
