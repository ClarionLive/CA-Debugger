# TSWD GROUP members with `mNameRef == 0` — recovered names for 99.5% of real cases

## Summary

While debugging why `ST.Value` (a `StringTheory` instance) never showed up under a
`GROUP`/class-instance local in the Variables panel, we found that the Clarion compiler
sometimes emits a **GROUP member record with no name-pool reference at all**
(`mNameRef == 0`) — even though the member's identifier string is still written to the
TSWD symbol pool correctly. This is not a bug in `ParseType`'s scanning: the byte layout
of the affected record is identical in every other respect to a working neighbor's
record; only the 4-byte name-pool offset field itself is zero.

We built a general recovery heuristic (not specific to `StringTheory`) that fills in the
missing name by reading backward in the symbol pool from a known-good neighboring
member's name. Surveyed across the whole application (`ML2apiDev799.exe`, ~3,600
procedures, ~16,850 locals), this recovers **191 of 192 confirmed cases (99.5%)**.

## Reproduction

Any `GROUP`/class member whose identifier happens to trigger this compiler behavior will
show up in the debugger's Variables tree as `(unnamed+N)` (N = byte offset within the
group) instead of its real name — readable and dereferenceable (type, value, size), just
unlabeled.

Minimal repro, confirmed independently of any class/library code:

```clarion
NotificationGrptype GROUP, TYPE
InfoStr               STRING(260)
Value                 LONG
                    END
```

`InfoStr` resolves correctly; `Value` does not — regardless of declaration order,
resulting memory offset, or whether the group lives standalone or as a `ProgressG`
property of another class. This rules out:
- Field position (first/middle/last member all reproduce it — see "The `VALUE`
  experiment" below)
- Field type (StringTheory's `Value` is `&STRING`; this repro's `Value` is a plain `LONG`)
- Any `NAME(...)` attribute (this repro has none)
- Being a class vs. a plain `GROUP,TYPE`

## Root cause (confirmed, not fully explained)

Byte-for-byte comparison of the broken record against a working neighbor's (StringTheory's
`value` vs. `streamFileName`, both declared `&string,PRIVATE,name('... | &string')`) shows
**identical record shape** — same tag (`0x0C`), same type-ref field, same offset field —
except the name-pool reference itself:

```
streamFileName (works):  mNameRef = 06 00 00 00   (= 6, valid pool offset)
value          (broken):  mNameRef = 00 00 00 00   (= 0)
```

The identifier string ("VALUE") *is* present in the pool — found via a plain linear scan
— so this is the compiler failing to **link** the member record to its own name, not
failing to emit the name at all.

### The `VALUE` experiment

Independent, decisive testing (renaming fields in the minimal repro above, one change at
a time) showed:

| Declaration order | Result |
|---|---|
| `InfoStr, Value, xxxTestxxx` | `Value` unnamed (offset 260) |
| `InfoStr, xxxTestxxx, Value` | `Value` still unnamed (now offset 264) |
| `aaaTestaaa, InfoStr, Value` | `Value` still unnamed (offset 264) |
| `Value, InfoStr, aaaTestaaa` | `Value` still unnamed (now offset **0**) |
| `InfoStr, xxxTestxxx, TheValue` *(renamed `Value` → `TheValue`)* | **`TheValue` resolves correctly** |

Every other identifier tested (`InfoStr`, `xxxTestxxx`, `aaaTestaaa`, `TheValue`) resolves
fine in every position. Only the exact identifier **`VALUE`** (case-insensitive) fails,
independent of position, offset, or type. This strongly suggests `VALUE` collides with
something the compiler treats specially/internally (a reserved or auto-generated symbol
of the same name), though we have not identified what.

**Important:** `VALUE` is the single most common trigger in the surveyed application (76
of 192 cases) but **not the only one** — `INPUTDATA` (40), `INFOQ` (25),
`LOWERATTRIBUTES` (15), `REFLECTION` (12), `FILES` (10), `FAULTDATA` (6), `TABLEQUEUE`
(4), and several others each account for the remaining cases. The `VALUE`-collision
theory is not confirmed to explain those; the broader pattern behind all ~15 distinct
affected identifiers is still open.

One side observation worth recording: the `ClarionDbg`/`ClarionDebugger` addin's own
compiled EXE does not contain the literal text "VALUE" anywhere, i.e. it doesn't use any
field/property named `Value` itself — consistent with (but not proof of) the collision
theory, since the addin never triggers whatever internal symbol collides with it.

## Fix implemented

All logic lives in `ClarionDbg.Core/TswdDebugInfo.cs`, `ParseType()`'s `case 0x08`
(GROUP) branch — the single place `TypeMember.Name` is populated, so every consumer
(Variables panel, Watch, module data, CLI diagnostics) benefits uniformly.

1. **Detect**: a member is only considered for recovery if its raw `mNameRef` is
   *exactly* `0`. A different out-of-range sentinel (`0xFFFFFFFF`) means something else
   entirely — confirmed on an `ML_RestErrorClass` `GROUP` overlay where two members
   legitimately share one offset and both carry `0xFFFFFFFF`; that's the compiler saying
   "no single field name applies here" (an anonymous overlay slot), not "the name was
   lost". Treating it the same as `mNameRef == 0` produced a false "duplicate name"
   rejection.

2. **Anchor selection**: the symbol pool interleaves many unrelated identifiers (queue
   element field names, other structs' fields, even mangled procedure names) — it is
   **not** grouped by class, and a group's own member array is **not** reliably in pool
   order either (confirmed: `_DATAEND` is *alphabetically* far from `VALUEPTR` but sits
   immediately before it *in the pool*). Anchoring on an arbitrary neighbor is unsafe
   (`_DATAEND`'s own immediate predecessor in the pool is `QUOTED`, from some unrelated
   struct). The one anchor that is trustworthy: **the group's own member with the
   smallest known `mNameRef`** — a missing member's true pool position can only be even
   earlier, so it's the only gap where "whatever sits immediately before" is still
   plausibly one of *this* group's own fields.

3. **Recover**: read backward from that anchor's pool position to the previous NUL
   terminator (`SymbolNameEndingBefore`, the mirror of the existing `SymbolNameAt`).
   Strict: any non-printable byte before a clean NUL boundary aborts with `null` rather
   than guessing.

4. **Validate before accepting**:
   - Reject a candidate that duplicates an *already-named* member in the same group
     (that string belongs to a different, already-resolved member).
   - Reject a candidate containing `@` or `$` — these only ever appear in the compiler's
     own mangled PROCEDURE/ROUTINE names (`NAME@F`, `R$NAME`), never in a real Clarion
     field identifier. Confirmed false-positive without this filter:
     `TEST_XCEEDZIPPING@F`, a plain `PROCEDURE` in `ML2apiDev799_Functions` with no
     relation to the group it was matched against.

A diagnostic (`MissingMemberLog`, surfaced via the CLI's `surveymissingnames` command)
records every recovery attempt — including outcome and rejection reason — for auditing.

## Results

Full survey of `ML2apiDev799.exe` (triggered by resolving every local's aggregate type
via `ReadLocals()`, so only *real*, reachable groups are counted — no raw-byte-scan false
positives):

- **192** distinct group `typeRef`s (deduplicated — the same class compiled into
  multiple modules gets its own `typeRef` per module, so e.g. `StringTheory` accounts for
  76 of these) had a member with confirmed `mNameRef == 0`.
- **191 recovered** correctly (verified: no incorrect/duplicate names introduced anywhere
  else in the same survey run).
- **1 unrecovered**, left honestly labeled `(unnamed+N)`: `ML_UtilityBaseClass.ScanPath`'s
  `ProgressG` (`NotificationGrptype`), offset `+260`. Root cause understood — this group
  has only two members (`InfoStr`, and the broken `Value`), and `InfoStr`'s own pool
  neighbor happens not to be a clean printable string this time, so there's no anchor to
  recover from. Not fixable without another data source (see below).

## Known limitations / not pursued further

- **Not exhaustive**: relies on the missing member's true name still sitting
  immediately before *some* resolvable neighbor's name in the pool. When it doesn't (as
  in the one residual case above), there is nothing left to recover from with this
  technique.
- **Two other, unrelated compiler-generated data tables were found during this
  investigation and are NOT used by the fix** (out of scope for now, noted here in case
  they're useful later):
  1. A `NAME(...)`-attribute reflection table (found via searching the EXE for a
     temporarily-renamed `NAME('xxxvaluexxx | &string')` override): repeating
     `1F <b1> <b2> IDENTIFIER\0 OVERRIDE\0` records, physically located *before* the TSWD
     debug blob (i.e. in ordinary program data, not debug-only info — plausibly present
     even in release builds). Declaration-order, not alphabetical.
  2. A `GROUP,TYPE` field-name reflection table (found via searching for `INFOSTR`):
     repeating records pairing a group's field names together (e.g.
     `INFOSTR\0 06 02 VALUE\0`) followed by group-level metadata, also located before the
     TSWD blob. This one groups a type's fields together explicitly regardless of pool
     proximity, and could in principle resolve the one residual case above — but we have
     not found a link from a `ParseType` typeRef to an entry in this table, and elected
     not to pursue it now.
- The broader "which identifiers trigger this" question (beyond `VALUE`) remains open —
  we have examples (`INPUTDATA`, `INFOQ`, `LOWERATTRIBUTES`, `REFLECTION`, `FILES`,
  `FAULTDATA`, `TABLEQUEUE`, and others) but no unifying theory.

## Files changed

- `ClarionDbg.Core/TswdDebugInfo.cs`
  - `ParseType()` `case 0x08`: the detect/anchor/recover/validate logic above.
  - `SymbolNameEndingBefore(int relStart, int poolLen)`: new — mirror of `SymbolNameAt`.
  - `MissingMemberLog`, `TestSymbolNameEndingBefore`, `DumpTypeRaw`, `DumpTypeChain`,
    `DumpGroupMembersRaw`, `ScanForMissingMemberNames`: diagnostics added during this
    investigation (raw-byte-scan version superseded by the `ReadLocals()`-driven survey;
    kept for future spot-checks).
- `ClarionDbg.Cli/Program.cs`
  - Diagnostic CLI commands added: `typemembers`, `typechain`, `poolback`,
    `scanmissingnames`, `surveymissingnames`.

## Suggested labels

`bug`, `tswd-parser`, `investigated`, `low-priority` (99.5% resolved; residual case is
cosmetic — the value is still fully inspectable, just unlabeled)
