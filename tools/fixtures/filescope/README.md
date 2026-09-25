# filescope: how Clarion names a FILE's record at each scope (ticket 04d7b4c8)

A hand-coded Clarion 11 app, built with full debug info, so the engine can be tested against the names
the compiler really emits instead of names we assumed.

| File | What it declares |
|---|---|
| `filescope.clw` | PROGRAM. A global `Customer` FILE, `PRE(CUS)`. |
| `filescope_a.clw` | MEMBER. `ProcA`, with an `Orders` FILE declared **inside the procedure** (`PRE(ORD)`) and a form-style `History::ORD:Record LIKE(ORD:Record),THREAD`. |
| `filescope_b.clw` | MEMBER. `ProcB`, with a second procedure-local `Orders` FILE with the **same** prefix. |

What the compiler emitted (Clarion 11.0.13630, measured 2026-09-25):

- A procedure-local FILE's record is `ORDERS$ORD:RECORD`, the same shape as a global FILE's
  (`CUSTOMER$CUS:RECORD`). There is **no** `PROCA::` scope prefix, so it ranks as a FILE record, ahead of the
  `HISTORY::ORD:RECORD` copy.
- The two procedure-local files both emit `ORDERS$ORD:RECORD`, in different modules of one image. A bare
  `ORD:ITEM` or `ORDERS$ORD:RECORD` is therefore ambiguous, and the engine says so (Owner decision 2: fail closed).

## Rebuild

Only the source is kept in the repo. `tools/test-engine-filescope.ps1` copies it to a temp folder and builds it
there. To build by hand:

```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe filescope.cwproj /p:ClarionBinPath=C:\Clarion11\bin
```

The Clarion compiler rejects LF line endings ("Illegal character" on line 1), so `.gitattributes` here checks
the `.clw` files out as CRLF.
