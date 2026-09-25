  MEMBER('filescope.clw')

! A second procedure-local FILE with the SAME prefix as ProcA's, in another module: two genuine file
! records answer to ORD:Item.

ProcB                PROCEDURE
Orders                 FILE,DRIVER('ASCII'),PRE(ORD),NAME('fs_ord_b.txt'),CREATE
Record                   RECORD
Item                       STRING(10)
                         END
                       END

  CODE
  ORD:Item = 'b'
