# By-ref `STRING`/`CHAR` GROUP members rendered as raw pointers instead of text

## Summary

A `GROUP`/class member that is itself a reference to a `STRING`/`CHAR` (e.g.
StringTheory's `LASTERROR`, or its own `Value` property) rendered in the Variables panel
as a bare pointer (`&0x08019BF0`) instead of its actual text content — even though the
exact same *top-level local* pattern (a `&STRING` local variable, not a group member)
already dereferenced and displayed correctly. Fixed by extending `CodeForType()` (the
GROUP-member equivalent of the top-level-local logic in `ReadLocals()`) to recognize and
dereference by-ref `STRING`/`CHAR` members the same way.

A related, separate problem surfaced during testing: a dynamically-allocated `&STRING`
has **no reliable length signal anywhere** — neither in its own static type record nor
via any single, general mechanism — so the fix also had to decide how to render a
preview without one.

## Root cause #1 — `CodeForType` didn't propagate a STRING referent

`ReadLocals()` (top-level locals) already special-cases a `&STRING` local: when a
record's type code is `0x16` (reference) and its target byte is `0x18` (STRING), it reads
the target's size directly out of the record (`p+46`) and passes it through, so
`FormatValueAt` dereferences and shows the text.

`CodeForType()` — the equivalent mapping used for **GROUP members** (`GroupChildrenJson`)
— only handled the by-ref-to-GROUP case (for lazy tree expansion); everything else
(including a by-ref STRING) fell through to a bare pointer:

```csharp
// before
target = (t.Referent != null && t.Referent.Kind == TypeKind.Group) ? (byte)0x08 : (byte)0;
```

Fix: also recognize `t.Referent.Kind == TypeKind.String || TypeKind.Char` and set
`target = 0x18` (plus the referent's own size via `RenderHint`), matching what
`FormatValueAt`'s existing `0x16`/`target==0x18` branch already expects.

## Root cause #2 — `ParseType` doesn't decode tag `0x29`/`0x26` at all

Testing against `StringTheory.LASTERROR` showed root cause #1 alone wasn't enough: its
referent isn't a plain `String`/`Char`-kind type record — `DumpTypeChain` showed:

```
depth=0  tag=0x16  kind=Reference
depth=1  tag=0x29  kind=Unknown   size=0
```

`ParseType`'s tag switch has no `case 0x29` (or `0x26`) at all, so any referent with that
tag comes back `Kind=Unknown, Size=0` no matter what. `0x29`/`0x26` are exactly the tags
`CodeForType`'s *outer* check already treats as "a reference/class-ref, same as `0x16`"
(pre-existing code, likely added for ABC control string-properties like `NAME`/
`MENUTEXT`/`BASENAME`) — so they're a known-but-never-fully-decoded shape. Extended
`CodeForType` to also treat a `0x29`/`0x26` **referent** as string-like — a best-effort
classification, not a real decode of that tag's own structure, but the only workable
option without reverse-engineering `0x29`'s full layout.

**Bug found and fixed while wiring this up:** the outer reference case initializes
`size = 4` (correct for the pointer *slot* itself). The `0x29`/`0x26` branch forgot to
reset it back to `0` (unknown), so the first working version read exactly 4 bytes from
the dereferenced target — visibly wrong (`ST.LASTERROR` showed only 4 raw bytes,
truncating real content). Fixed by explicitly setting `size = 0` in that branch, which
makes `FormatValueAt` fall back to its existing bounded-read logic instead.

## The length problem: there is no reliable signal

A dynamically-allocated `&STRING` (`NEW STRING(n)` under the hood, whether by StringTheory
or plain Clarion code) has no NUL terminator or length prefix a debugger can trust:

- **StringTheory's `_DATAEND`** (an `int` sibling member) tracks the actual **data
  length** (how much of the buffer holds real content) — but per direct confirmation,
  this is unique to StringTheory; no other class does this.
- **Clarion's native `NEW(STRING(n))` allocator** appears to leave the **allocated
  buffer capacity** in the 4 bytes immediately following the pointer's own slot in the
  struct (verified against `LASTERROR`, `SELF.LastError &= NEW STRING(1)` in
  StringTheory's `Construct`: held `1`, content was one space) — but capacity is not the
  same as content length (a buffer can be over-allocated, or shrunk without
  reallocating), and this is a heuristic observation, not documented behavior.
- The type record itself never carries a real length for a `&STRING` — confirmed via raw
  byte inspection: the `0x29` referent's "count"-shaped field is `FFFFFFFF`, a sentinel,
  not a length.

Implemented, in priority order:
1. If the member is `VALUE` (case-insensitive) in a group that also has a `_DATAEND`
   sibling, use `_DATAEND`'s live value (the one case where we have an actual,
   documented-by-behavior data length).
2. Otherwise, for any other by-ref `STRING`/`CHAR` member, peek 4 bytes after the
   pointer's own slot and use it **only** as a plausibility-bounded (`0 < n <= 8192`)
   capacity hint for the type label.
3. Regardless of which of the above applied (or neither), **the actual on-screen text is
   always capped at 32 bytes** (`FormatValueAt`) — deliberately not the full guessed
   length. Rationale (explicit product decision, not a technical limitation): a capacity
   hint is not proof of content length, Clarion `STRING` has no in-band terminator to
   trust either, and inflating the read to match a possibly-wrong "size" risks a garbage
   tail read as real content. A short, bounded preview plus an accurate-when-known label
   is safer than a longer, potentially-misleading one; full byte-exact inspection belongs
   in a separate raw-memory/export view, not this text preview.

## Encoding: ASCII → Windows-1252

`FormatValueAt` decoded dereferenced STRING bytes with `Encoding.ASCII`, which silently
replaces every byte ≥ 0x80 with a literal `'?'` — indistinguishable on screen from a
genuine `'?'` character in the data. Clarion `STRING` content is Windows ANSI (cp1252),
not 7-bit ASCII. Switched both call sites (`0x18` direct STRING, and the `0x16`→`0x18`
dereferenced case) to `Encoding.GetEncoding(1252)`. This does not make the preview
byte-exact-provable (still a display decode, not a raw dump) but it stops actively
destroying information before it even reaches the UI.

## Type label: `STRING(N)` → `&STRING(N)`

By-ref `STRING` was deliberately labeled without a `&` prefix ("to the user, just a
STRING(N) — the pointer is an ABI detail"), inconsistent with `&GROUP`/`&CLASS`/`&REF`
elsewhere in the same function (`ClarionTypeLabel`). Given everything above — `N` here is
always a best-effort hint (capacity or, at best, StringTheory's own data-length
bookkeeping), never a compile-time-guaranteed size the way a plain inline `STRING(N)`
local's is — restored the `&` prefix (`&STRING(N)` / `&STRING(?)` when no hint at all) so
the label itself signals "this is a live guess, not the whole guaranteed string".

## Known limitations

- The 32-byte preview cap is a fixed constant, not (yet) configurable. Flagged during
  review as a reasonable candidate for a future per-user setting if anyone wants a
  different tradeoff.
- The "peek 4 bytes after the pointer slot" capacity heuristic is unproven beyond the
  `LASTERROR` test case — it is *not* a documented Clarion/TSWD convention, just an
  observed pattern. It only affects the type label, never the (separately, hard-capped)
  on-screen text, so a wrong guess there is low-risk.
- `0x29`/`0x26` referents are still not actually decoded — they're heuristically treated
  as "probably string-like" wherever `CodeForType` sees one as a referent. A referent of
  that tag that is genuinely something else (not yet observed) would be mis-rendered.

## Files changed

- `ClarionDbg.Cli/DebugEngine.Locals.cs`
  - `CodeForType`: propagate `target=0x18` (+ size where knowable) for a `STRING`/`CHAR`
    or `0x29`/`0x26` referent, not just `Group`.
  - `FormatValueAt`: dereferenced `&STRING` preview hard-capped at 32 bytes regardless of
    source; decodes with `Encoding.GetEncoding(1252)` instead of `Encoding.ASCII` (both
    the direct `0x18` case and the `0x16`→`0x18` dereferenced case).
  - `ClarionTypeLabel`: by-ref `STRING` labeled `&STRING(N)` / `&STRING(?)` (was
    `STRING(N)` / `STRING(?)`).
  - `GroupChildrenJson`: reads a `_DATAEND` sibling (if present) once per group and
    applies it to a member literally named `VALUE`; otherwise falls back to the
    peek-after-pointer capacity hint for any other unknown-length by-ref `STRING`/`CHAR`
    member.

## Suggested labels

`bug`, `tswd-parser`, `ui`, `investigated`
