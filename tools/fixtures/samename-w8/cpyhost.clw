  PROGRAM

! Fixture fb5766d1 #3: c\shared.dll is a byte copy of a\shared.dll (same build). Only a\ is named to the engine.
! Load C (claims A's preload, borrows its path), load A itself (C yields), free A, free C (the preload
! answers to A's path again), load C again, then call SHAREDPROC in C. Exit 0 = the call worked; 4 = a load
! failed; 5 = a free failed.

  MAP
    MODULE('kernel32')
      GetModuleFileName(LONG hModule, *CSTRING lpFilename, LONG nSize),LONG,PASCAL,RAW,NAME('GetModuleFileNameA')
      LoadLibrary(*CSTRING lpLibFileName),LONG,PASCAL,RAW,NAME('LoadLibraryA')
      FreeLibrary(LONG hModule),LONG,PASCAL,NAME('FreeLibrary')
    END
  END

ExeDir                 CSTRING(261)
Slash                  LONG
PathA                  CSTRING(261)
PathC                  CSTRING(261)
HA                     LONG
HC                     LONG
Rc                     SIGNED

  CODE
  IF GetModuleFileName(0, ExeDir, SIZE(ExeDir)) = 0 THEN HALT(9).
  LOOP Slash = LEN(ExeDir) TO 1 BY -1
    IF ExeDir[Slash] = '\' THEN BREAK.
  END
  ExeDir = SUB(ExeDir, 1, Slash)
  PathA = ExeDir & 'a\shared.dll'
  PathC = ExeDir & 'c\shared.dll'
  HC = LoadLibrary(PathC)
  IF HC = 0 THEN HALT(4).
  HA = LoadLibrary(PathA)
  IF HA = 0 THEN HALT(4).
  IF FreeLibrary(HA) = 0 THEN HALT(5).
  IF FreeLibrary(HC) = 0 THEN HALT(5).
  HC = LoadLibrary(PathC)
  IF HC = 0 THEN HALT(4).
  Rc = CALL(PathC, 'SHAREDPROC')
  HALT(Rc)
