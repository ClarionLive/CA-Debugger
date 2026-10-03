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
| `cpyhost.clw`, `cpyhost.cwproj` | Loads `c\shared.dll` (the suite makes it a byte copy of `a\shared.dll`), then `a\shared.dll`. Then frees A, frees C, loads C again and calls `SHAREDPROC` in it. Exit 0 = every step worked. |

Measured 2026-10-03: in these one-procedure DLLs the TSWD keys `OBJ`'s local record to the entry of
`sharedmod$$$__attach_process`, not `SHAREDPROC`, so `framelocals` at the stop finds no locals. The suite asks at
the entry that carries `OBJ`, with the stopped frame's EBP (a separate suggestion ticket tracks the attribution).

## Rebuild by hand

From PowerShell (Git Bash mangles `/p:`):

```powershell
$msb = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe'
Push-Location a; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
Push-Location b; & $msb shared.cwproj /p:ClarionBinPath=C:\Clarion11\bin; Pop-Location
& $msb cpyhost.cwproj /p:ClarionBinPath=C:\Clarion11\bin
```

The `.clw` files must be CRLF; `.gitattributes` here keeps them so.
