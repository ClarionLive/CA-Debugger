  PROGRAM

! Fixture for 04d7b4c8: how Clarion names a FILE's record buffer at each scope, and a form-style
! History:: copy of a record. Built with debug info; see README.md next to this file.

  MAP
    MODULE('filescope_a.clw')
      ProcA()
    END
    MODULE('filescope_b.clw')
      ProcB()
    END
  END

Customer             FILE,DRIVER('ASCII'),PRE(CUS),NAME('fs_cust.txt'),CREATE
Record                 RECORD
Name                     STRING(20)
                       END
                     END

  CODE
  CUS:Name = 'global'
  ProcA()
  ProcB()
