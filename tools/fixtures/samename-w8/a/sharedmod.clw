  PROGRAM
! Fixture fb5766d1 #8 (w8-expand-base), build A: Obj is a class reference whose members differ from B's. See README.md one folder up.
  MAP
SharedProc             PROCEDURE(),NAME('SHAREDPROC')
  END
ClsT                   CLASS,TYPE
VA                       LONG
VA2                      LONG
                       END
SharedCount            LONG
SharedTag              STRING(1)
  CODE
SharedProc             PROCEDURE
Obj                    &ClsT
  CODE
  Obj &= NEW ClsT
  Obj.VA = 7
  SharedTag = 'A'
  SharedCount += 1
  DISPOSE(Obj)
