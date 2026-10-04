  PROGRAM
! Fixture c4910921, build D: TWO procedures. OtherProc is named first in the symbol pool (offset 0). See README.md one folder up.
  MAP
SharedProc             PROCEDURE(),NAME('SHAREDPROC')
OtherProc              PROCEDURE(),NAME('OTHERPROC')
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
  SharedTag = 'D'
  OtherProc()
  SharedCount += 1
  DISPOSE(Obj)
OtherProc              PROCEDURE
Cnt2                   LONG
  CODE
  Cnt2 = 5
  SharedCount += Cnt2
