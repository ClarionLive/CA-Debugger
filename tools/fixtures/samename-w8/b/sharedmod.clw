  PROGRAM
! Fixture fb5766d1 #8, build B: same lines as A, a class type with other member names. See README.md one folder up.
  MAP
SharedProc             PROCEDURE(),NAME('SHAREDPROC')
  END
ClsT                   CLASS,TYPE
PB                       LONG
VB                       LONG
                       END
SharedCount            LONG
SharedTag              STRING(1)
  CODE
SharedProc             PROCEDURE
Obj                    &ClsT
  CODE
  Obj &= NEW ClsT
  Obj.VB = 8
  SharedTag = 'B'
  SharedCount += 2
  DISPOSE(Obj)
