  PROGRAM

! Fixture for 1be3b82e item 2: an EXE that maps TWO DLLs with the same file name, a\shared.dll and
! b\shared.dll, and calls SHAREDPROC in each, A first. Both are loaded by FULL PATH at run time, not
! through an import table, because the loader matches an imported DLL by base name and would map only one.
! Both are LoadLibrary'd up front and held: CALL alone unloads its DLL when it returns, so B then mapped at
! A's old base and the two were never in the process together (measured 2026-09-25).
! The exit code says whether both calls worked: 0 = both, 1 = A failed, 2 = B failed, 3 = both failed,
! 4 = a DLL did not load by path.
! See README.md.

  MAP
    MODULE('kernel32')
      GetModuleFileName(LONG hModule, *CSTRING lpFilename, LONG nSize),LONG,PASCAL,RAW,NAME('GetModuleFileNameA')
      LoadLibrary(*CSTRING lpLibFileName),LONG,PASCAL,RAW,NAME('LoadLibraryA')
    END
  END

ExeDir                 CSTRING(261)
Slash                  LONG
PathA                  CSTRING(261)
PathB                  CSTRING(261)
RcA                    SIGNED
RcB                    SIGNED
Fails                  LONG

  CODE
  IF GetModuleFileName(0, ExeDir, SIZE(ExeDir)) = 0 THEN HALT(9).
  LOOP Slash = LEN(ExeDir) TO 1 BY -1
    IF ExeDir[Slash] = '\' THEN BREAK.
  END
  ExeDir = SUB(ExeDir, 1, Slash)
  PathA = ExeDir & 'a\shared.dll'
  PathB = ExeDir & 'b\shared.dll'
  IF LoadLibrary(PathA) = 0 THEN HALT(4).
  IF LoadLibrary(PathB) = 0 THEN HALT(4).
  RcA = CALL(PathA, 'SHAREDPROC')
  RcB = CALL(PathB, 'SHAREDPROC')
  Fails = 0
  IF RcA <> 0 THEN Fails += 1.
  IF RcB <> 0 THEN Fails += 2.
  HALT(Fails)
