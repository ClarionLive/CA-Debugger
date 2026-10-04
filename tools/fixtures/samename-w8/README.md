# samename-w8: expand by image base, and a same-build copy that yields its path (fb5766d1 #3, #8)

A variant of `..\samename` (wave 7), built with Clarion 11 and full debug info. `tools/test-engine-samename-w8.ps1`
builds it in a temp folder and drives the engine over it.

It is a separate fixture rather than an extension of `samename`, because the class local moves the breakable
lines, and `test-engine-samename.ps1` pins `sharedmod.clw:19` as measured on its own files. The EXE that loads
both DLLs is not copied: the suite builds `..\samename\samehost.clw` beside these DLLs.

| File | What it is |
|---|---|
| `a\sharedmod.clw`, `a\shared.cwproj`, `a\shared.exp` | DLL A, `shared.dll`. `SHAREDPROC` has a local `Obj &ClsT`, a class whose members are `VA`, `VA2`. |
| `b\sharedmod.clw`, `b\shared.cwproj`, `b\shared.exp` | DLL B, also `shared.dll` from a `sharedmod.clw`. Its `ClsT` members are `PB`, `VB`, so a row read against the wrong image's TSWD shows the wrong names. Breakable lines are the same as A's: 13-14, 16-20 (measured 2026-10-03). |
| `d\sharedmod.clw`, `d\shared.cwproj`, `d\shared.exp` | DLL D (c4910921), `shared.dll` with TWO procedures: `SHAREDPROC` (local `Obj &ClsT`) calls `OTHERPROC` (local `Cnt2 LONG`), whose name sits at symbol-pool offset 0. The suite runs it as `two\a\shared.dll` beside a copy of `samehost.exe`, with B as `two\b\shared.dll`. Breakable lines: 14-15, 17-24, 26-27 (measured 2026-10-03). |
| `cpyhost.clw`, `cpyhost.cwproj` | Loads `c\shared.dll` (the suite makes it a byte copy of `a\shared.dll`), then `a\shared.dll`. Then frees A, frees C, loads C again and calls `SHAREDPROC` in it. Exit 0 = every step worked. |

Measured 2026-10-03, before the c4910921 fix: the engine skipped a +0x2C procedure record whose name sits at
symbol-pool offset 0, so that procedure's locals went to the record before it. In A and B (`SHAREDPROC` at offset
0) `OBJ` was keyed to `sharedmod$$$__attach_process` and `framelocals` at the stop was empty; in D, `OTHERPROC`'s
`CNT2` showed under `SHAREDPROC`. The suite asks `framelocals` at the stopped address, and its section (3) checks D.

## Rebuild by hand

From PowerShell (Git Bash mangles `/p:`):

```powershell
$msb = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe'
Push-Location a; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
Push-Location b; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
Push-Location d; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
& $msb cpyhost.cwproj /p:ClarionBinPath=C:\Clarion11\bin
```

The `.clw` files must be CRLF; `.gitattributes` here keeps them so.
