  PROGRAM

! Fixture for ca29e2da: two threads run the same procedure a known number of times, so a breakpoint on its
! body must be hit exactly 2 x Iterations times. A thread that runs the address while the debugger has the
! original byte back for another thread's single-step goes past the breakpoint, and the count comes up short.
! Built with debug info; see README.md next to this file.

  MAP
    Worker(STRING pId)
    Bump()
  END

Iterations           LONG(2000)
Calls                LONG
Done1                LONG
Done2                LONG

! Clarion hands a STARTed thread its first run from the starting thread's ACCEPT loop, so the main
! program waits in one (a timer window) rather than in a plain loop, which never lets the workers begin.
WaitWin              WINDOW('racebp'),AT(,,120,30),TIMER(10)
                     END

  CODE
  OPEN(WaitWin)
  START(Worker, 25000, '1')
  START(Worker, 25000, '2')
  ACCEPT
    IF EVENT() = EVENT:Timer AND Done1 AND Done2 THEN BREAK.
  END
  CLOSE(WaitWin)

Worker               PROCEDURE(STRING pId)
I                      LONG
  CODE
  LOOP I = 1 TO Iterations
    Bump()
  END
  IF pId = '1' THEN Done1 = 1 ELSE Done2 = 1.

Bump                 PROCEDURE()
  CODE
  Calls += 1
