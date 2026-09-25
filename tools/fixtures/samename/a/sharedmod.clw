  PROGRAM

! Fixture for 1be3b82e item 2, build A: one of two shared.dll images compiled from a file named
! sharedmod.clw. b\sharedmod.clw is the same shape with different constants, so the two DLLs are two
! different builds whose breakable lines sit on the SAME line numbers. See ..\README.md.

  MAP
SharedProc             PROCEDURE(),NAME('SHAREDPROC')
  END

SharedCount            LONG
SharedTag              STRING(1)

  CODE

SharedProc             PROCEDURE
  CODE
  SharedTag = 'A'
  SharedCount += 1
  SharedCount += 100
