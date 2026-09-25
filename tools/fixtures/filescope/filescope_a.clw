  MEMBER('filescope.clw')

! A FILE declared inside a procedure, and a form-style History:: copy LIKE its record.

ProcA                PROCEDURE
Orders                 FILE,DRIVER('ASCII'),PRE(ORD),NAME('fs_ord_a.txt'),CREATE
Record                   RECORD
Item                       STRING(10)
                         END
                       END
History::ORD:Record    LIKE(ORD:Record),THREAD

  CODE
  ORD:Item = 'a'
  History::ORD:Record = ORD:Record
