# TSWD Debug Format (decoded)

Clarion's embedded debug information. Tag `TSWD` (almost certainly "TopSpeed Watcom
Debug" — Clarion's toolchain descends from TopSpeed/JPI). **Custom format, NOT
CodeView/PDB** — no off-the-shelf parser (DIA/dbghelp) will read it.

All offsets/values below decoded from
`...\HowToClarion\Browses\clbrws.exe` (Clarion 11, 32-bit, Full debug), cross-checked
against the on-disk generated sources (`..\v8Source\clbrwsNNN.clw`, resolved via the .red
redirection file). ImageBase `0x400000`.

> **Status (2026-06):** line resolution is fully decoded and verified. The primary
> address↔line path is the **`+0x1C` table** (clean, module-tagged — see below), NOT the
> Table-A/Table-B model the earlier drafts chased. Proc/module symbol names are decoded.
> Variable *types* (for watch/value support) are still open. Repro scripts:
> `spikes/tswd-*.ps1` and `spikes/tswd-*.txt`.

## Locating the blob

1. Read the PE optional header → Data Directory **index 6** (Debug Directory).
2. That points at a 28-byte `IMAGE_DEBUG_DIRECTORY` (it lives in the `.cwdebug`
   section, which is *only* those 28 bytes).
3. The entry's `Type` field = `0x44575354` = ASCII **`TSWD`** (a custom type code).
4. `SizeOfData` = size of the debug blob; `PointerToRawData` = its **file offset**.
   The blob is an **overlay appended after the last PE section**.

For this build of clbrws.exe the blob is at file offset `0x16CC00`. Always read it from the
debug directory — it is build-specific (an earlier draft recorded `0x16CA00` from a prior
build). Everything below is **blob-relative**.

## Header (TOC) — at blob+0x00, little-endian u32

| Offset | Value (this build) | Meaning |
|--------|--------------------|---------|
| +0x00 | `0x44575354` | magic `TSWD` |
| +0x04 | `0x3C` | header size (60 bytes) |
| +0x08 | `0x38` | → **module-name offset array** (u32 offsets into name pool; one per module) |
| +0x0C | `0x128` | → **module-name string pool** (null-term plaintext: `ABBROWSE.CLW`, `clbrws001.clw`, …) |
| +0x10 | `0x444` | → per-module **byte-slice** table into Table A (see "the +0x10 trap" below — NOT run boundaries) |
| +0x14 | `0x624` | → **Table A** — line-major line records (continuous 6-byte grid) |
| +0x18 | `0x889C` | → **Table B** — flat 6-byte parse is unreliable; superseded by +0x1C |
| +0x1C | `0x3282C` | → **ADDRESS→LINE table (the one to use)** — 8-byte `{rva, line, moduleIdx}` |
| +0x20 | `0x76D0C` | → **symbol-name string pool** (plaintext) |
| +0x24 | `0x3D` = 61 | module count field |
| +0x28 | `0x87AC4` | → **module backref array** (61 u32; each is a "module block" key — its index = module index) |
| +0x2C | `0x87BB8` | → table |
| +0x30 | `0x8B9` = 2233 | symbol count |
| +0x34 | `0x126E88` | → near-end table |

Module-name offset array (at +0x08): byte offsets into the pool at +0x0C. **Module index 0 =
`ABBROWSE.CLW`**, and the array is the canonical module ordering — see "the module index is
one number" below. The current build has 60 name entries; 56 of them carry code.

Symbol pool sample (at +0x20): `_main`, `clbrws$$$__attach_process`, `SELECTJOBS@F`,
`BROWSEAUTHORSEIP@F`, `R$BRW1::SELECTSORT`, `R$BRW1::INITIALIZEBROWSE`, `JOB:JOBID`,
`BRW1::LASTSORTORDER`, …

---

## ★ The +0x1C table — the primary address→line index

This is the table to build the resolver on. The earlier drafts mislabeled it
"symbol/addr record table"; it is in fact a clean, global, **address-major line table with
module tags baked in**.

```
struct AddrLineRec {           // 8 bytes, little-endian
    uint32 codeRVA;
    uint16 line;               // source line within the owning module (see caveats)
    uint16 moduleIdx;          // == module-name-array index (see below)
};
```

Verified properties (this build): **34,972 records, 100% within `.text`, strictly
RVA-ascending, ZERO resets.**

**Resolution:**
- **address → line** (resolve a breakpoint hit / current line): binary-search by `codeRVA`
  for the greatest record `≤ target`; return `{line, moduleIdx}`. No segmentation, no phase,
  no per-module bookkeeping.
- **line → address** (set a breakpoint at `file:line`): filter records by `moduleIdx`
  (for the file) then by `line`. (Table A also works but +0x1C is simpler and already tagged.)
- **moduleIdx → .clw name**: `names[moduleIdx]` — trivial (see next section).

`moduleIdx` partitions all code into 56 compilands; each module's `[min RVA, max RVA]` is its
contiguous `.text` region.

## The module index is *one* number

The `moduleIdx` in the +0x1C table **equals** the `+0x08` module-name-array index **equals**
the symbol records' `moduleBackref` index. They are the same module ordering. Therefore:

```
moduleIdx  ->  .clw name   ==   names[moduleIdx]
```

No content-matching, no heuristics. Verified end-to-end, e.g.
`SELECTJOBS@F → entryRVA 0x48D5C → moduleIdx 37 → names[37] = "clbrws011.clw"` and
`BROWSEAUTHORSEIP@F → 0x32D64 → moduleIdx 29 → names[29] = "clbrws003.clw"`.

`moduleIdx` is **not contiguous** — the no-code modules (their `+0x10` slice is `{0,0}`)
occupy their name-array index but produce no +0x1C records, so those indices are simply
absent. Don't assume `0..55`; iterate the indices that appear.

## Symbol table — proc/method/routine name → entry RVA

The symbol-name pool is at `+0x20` (plaintext). Symbol **definition** records (scattered
after the name pool; **byte-granular, not 4-aligned** to any table) are 12 bytes:

```
struct SymDefRec {             // 12 bytes, little-endian
    uint32 nameRef;            // offset into the +0x20 name pool; the name is NUL-preceded
    uint32 entryRVA;           // symbol entry (image-relative)
    uint32 moduleBackref;      // == one of the 61 values in the +0x28 array;
                               //    that value's INDEX is the module index
};
```

The `{nameRef, entryRVA}` pair also appears at **call sites**, so to select *definitions*
require the 3rd field to be a valid `+0x28` value (and skip `__thunk.*` names — a thunk lives
in the caller's module, not the definee's). That filter yields ~2233 defs (= the `+0x30`
count).

Name conventions in the pool:
- **Top-level procedures**: `NAME@F` or `NAME@F<digits>` (e.g. `SELECTJOBS@F`, `MAIN@F`).
- **Class methods**: `NAME@F<nn>CLASSNAME...` (e.g. `UPDATE@F8INICLASS`).
- **Routines**: `R$PROC::ROUTINENAME` (e.g. `R$BRW1::SELECTSORT`).
- **Thunks**: `__thunk.NAME@F` (skip for definitions).

**Semantic (proc count per module):** of the 32 modules carrying top-level proc defs, **31
have exactly one proc (1:1)** — every generated `clbrwsNNN.clw` procedure module is one proc.
One module (a runtime/error module) holds 3. Library modules (`ABBROWSE`, `RTFCTL`,
`CWUTIL`, …) carry **class methods, not top-level procs** (0 `NAME@F` defs).

**Caveat — entry vs region floor:** a proc's `entryRVA` (from its symbol) can sit *above* its
module's lowest +0x1C RVA. Clarion emits some proc code (ROUTINEs / init / embed / cold) at
lower addresses than the named entry. So use `entryRVA` as the proc's canonical "start"
address, but use **+0x1C records filtered by moduleIdx** for line↔address (authoritative for
the whole module region).

See `spikes/tswd-symbols.txt` for the full 32-row module→proc fixture and
`spikes/tswd-procsym-decode.ps1` for the decoder.

---

## Table A (+0x14) — line-major records (cross-check / fallback)

`[+0x14, +0x18)` is a **single continuous 6-byte grid** (no per-module realignment):

```
struct LineRec { uint16 line; uint32 codeRVA; };   // 6 bytes
```

Read it straight from `+0x14`; do **not** phase-detect per `+0x10` chunk (the "0–5 byte
phase per module" model in earlier drafts was an artifact of measuring from arbitrary chunk
starts — a chunk's apparent phase is just `(chunkStart − OffTableA) mod 6`).

The grid is a sequence of **per-compiland line-major runs** delimited by **line resets**
(line drops back to the file's first code line). Within a run the records ascend by line; the
RVAs scatter (line-major). Line numbers run **cumulatively** across a compiland group, so a
run's max line can exceed any single `.clw`'s length (the tail is compiler/include-internal).

Because +0x1C gives the same line data already address-sorted and module-tagged, Table A is
now only a **cross-check / fallback**. If you parse it, segment by resets, not by +0x10.

### The +0x10 trap (why earlier resolvers drifted)

`+0x10` (`[0x444, 0x624)`, 2× u32 per module = `{ uint32 sliceStart; uint32 sliceEnd; }`,
absolute blob offsets into Table A, `{0,0}` for no-code modules) was read as if each slice
were one module's records. **It is not.** The byte slices tile Table A contiguously but their
boundaries fall *mid-run*: a single compiland's run is chopped across several slices, and one
slice can hold the tail of one run plus the head of the next. Treating slices as module
record boundaries causes the classic symptoms (wrong line labels at slice edges, truncated
modules, line numbers attributed to the wrong file). Use +0x1C's `moduleIdx` instead; if you
must use Table A, segment by line resets and attach names via `names[moduleIdx]`.

## Table B (+0x18) — not needed

`[+0x18, +0x1C)` parses *flat* as 6-byte `{u32 rva, u16 line}` but that parse is unreliable
(its start decodes to out-of-`.text` RVAs), and it is **not required** — +0x1C is the clean
global address→line index. Leave Table B unparsed unless a future need appears.

---

## Gotchas (learned the hard way)

- **Template-similarity trap.** Clarion browse/form procedures are generated from shared
  templates, so different `.clw` files are *line-for-line identical* over long stretches
  (e.g. `BRW1::SelectSort` at the same line in many browses). Content-matching a `(line →
  source text)` pair against candidate `.clw` files therefore mis-binds, and so does
  comparing line numbers across files. **Bind module identity by `moduleIdx` (= name index),
  never by source-line content.** This bit twice during decode; the symbol/+0x1C indices are
  the template-proof source of truth.
- **Cumulative line tail.** A module's records can carry `line` values beyond the `.clw`'s
  physical length (cumulative numbering). Gate user breakpoints to `line ≤ fileLen`; treat
  larger values as compiler/include-internal.
- **moduleIdx gaps.** No-code modules have no records; their indices are absent. Don't assume
  a contiguous range.
- **entryRVA ≥ region floor is false.** See the symbol-table caveat above.

## Ground-truth confirmation

Source verified against `..\v8Source\` (regenerated before compile, so on-disk == compiled):

```
clbrws011.clw : SelectJobs, line 317 = "BRW1::LastSortOrder = BRW1::SortOrder"
clbrws003.clw : BrowseAuthorsEIP (line 317 = "DO RefreshWindow" — different proc, same line!)
```

Regression anchors for the resolver (template-proof; key on address → moduleIdx → name):

```
resolve(addr 0x48D5C) -> { moduleIdx 37, clbrws011.clw, proc SELECTJOBS }
resolve(addr 0x32D64) -> { moduleIdx 29, clbrws003.clw, proc BROWSEAUTHORSEIP }
names[37] == "clbrws011.clw" ;  names[29] == "clbrws003.clw"
```

> Do **not** assert `line 317 → 0x31F68 == clbrws011` — `0x31F68` is `clbrws003`'s line 317
> (the template-similarity trap). Resolve via address → moduleIdx → `names[]`.

## Implementation notes (ClarionDbg.Core)

- Parse `+0x1C` as `List<AddrLineRec>{ rva, line, moduleIdx }`; build a `moduleIdx →
  { entryRVA = min rva, hiRVA = max rva, recordCount }` map and a sorted-by-rva index.
- `address → line`: binary search the rva index. `line → address`: filter by `moduleIdx`.
- `moduleIdx → .clw`: `names[moduleIdx]` (module-name array, +0x08).
- The old flat `TswdDebugInfo.TryAddrToLine` / `RvasForLine` / `BuildModules`
  (Table-A-by-+0x10) are superseded — replace with the +0x1C path. `OffTableAfterB`
  (`U32(0x1C)`) is the +0x1C base; the previous `ByAddr` parse read the wrong region/width.

## Open items (Phase 3 — watch/value support)

- **Symbol → storage**: tie each name (via the `+0x28` / symbol records) to its
  `{address or stack-frame offset, type code}` for data symbols.
- **Clarion type-code enumeration** — map type codes → STRING / CSTRING / PSTRING / BYTE /
  SHORT / LONG / DECIMAL / REAL / GROUP / QUEUE / `&FILE:RECORD` etc., with picture/size, so
  raw memory can be rendered. Reuse the dictionary/FileSchema type model.
- **Threaded variables** — instances allocated at runtime; resolved via a runtime library
  call (same `DEBUGHOOK` caveat the native debugger has). Not a regression.
