# samename: two DLLs with the same file name (ticket 1be3b82e item 2)

A hand-coded Clarion 11 app, built with full debug info, so the engine can be tested live against two images
that share a file name AND a compiland name.

| File | What it is |
|---|---|
| `a\sharedmod.clw`, `a\shared.cwproj`, `a\shared.exp` | DLL A: `shared.dll`, exporting `SHAREDPROC`. |
| `b\sharedmod.clw`, `b\shared.cwproj`, `b\shared.exp` | DLL B: also `shared.dll` from a `sharedmod.clw`, with different constants, so a different build. Its breakable lines sit on the same line numbers as A's (16, 18-20, measured 2026-09-25). |
| `samehost.clw`, `samehost.cwproj` | The EXE. Loads `a\shared.dll` and `b\shared.dll` beside it by full path, calls `SHAREDPROC` in A and then in B, and exits with 0 when both calls worked. |

How the two DLLs get into one process:

- Not through an import table: the loader matches an imported DLL by base name, so one process cannot import
  two `shared.dll`s.
- `LoadLibraryA` with a FULL path maps each one separately (different path, so a different module).
- Both are loaded up front and held, then called with `CALL(path, 'SHAREDPROC')`. `CALL` alone unloads its
  DLL when it returns, so B mapped at A's old base and the two were never loaded together (measured
  2026-09-25). Held, they map at two bases (0x6E3B0000 and 0x6E3A0000 on that run).

## Rebuild

Only the source is kept in the repo. `tools/test-engine-samename.ps1` copies it to a temp folder and builds it
there. To build by hand, from PowerShell (Git Bash mangles `/p:`), build the two DLLs and then the EXE:

```powershell
$msb = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe'
Push-Location a; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
Push-Location b; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
& $msb samehost.cwproj /p:ClarionBinPath=C:\Clarion11\bin
```

The EXE build copies `ClaRUN.dll` beside `samehost.exe`. The Clarion compiler rejects LF line endings
("Illegal character" on line 1), so `.gitattributes` here checks the `.clw`, `.cwproj` and `.exp` files out
as CRLF.
