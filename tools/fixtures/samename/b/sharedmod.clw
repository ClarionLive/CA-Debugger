  PROGRAM

! Fixture for 1be3b82e item 2, build B: the second shared.dll, compiled from a file of the same name
! (sharedmod.clw) as a\sharedmod.clw. Same shape and line numbers, different constants.
! See ..\README.md.

  MAP
SharedProc             PROCEDURE(),NAME('SHAREDPROC')
  END

SharedCount            LONG
SharedTag              STRING(1)

  CODE

SharedProc             PROCEDURE
  CODE
  SharedTag = 'B'
  SharedCount += 2
  SharedCount += 200
