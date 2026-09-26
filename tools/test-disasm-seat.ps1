# Behavioural test of the Disassembly view's SEAT LIFECYCLE (ticket 8f352618).
#
#   pwsh -NoProfile -File tools\test-disasm-seat.ps1 [-SeatStatePath <SeatState.cs>] [-ViewPath <DisassemblyView.cs>]
# Exit code 0 = all checks passed.
#
# WHAT THIS REPLACES. test-addin-json.ps1 used to pin the ORDER of eight statements inside OnDisasm's WinTag
# branch, and said of itself that it saw a wrong PLACE and never a wrong VALUE: `bool wasSeat = true;` passed
# all six of its checks. It could not do better, because the seat state was fields on a WinForms Control and
# the handlers wrapped their bodies in UI(...), which returns at once without a created handle. 8f352618 moved
# that state into SeatState.cs, a plain class with no WinForms, no service and no I/O - so this compiles the
# REAL file as it ships and DRIVES the transitions, and a wrong value goes red here.
#
# WHAT IT DOES NOT COVER. SeatState answers what the seat state IS; it cannot see whether DisassemblyView calls
# the right transition at the right moment. Section 3 pins the few orderings that are still the view's own, by
# POSITION, and scans the view for any seat field it writes directly. Whether the engine answers as the view
# expects needs a live debuggee and is not tested here.
#
# ASCII only, so Windows PowerShell 5.1 parses it as well as pwsh does. Add-Type cannot redefine a type in one
# process, so a mutation run must start a FRESH pwsh per mutant.

param(
  [string] $SeatStatePath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Disassembly\SeatState.cs'),
  [string] $ViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Disassembly\DisassemblyView.cs'),
  # the service, whose ThreadSelection snapshot the view holds (49538b78 8b), and the wire rule it is built on
  [string] $ServicePath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs'),
  [string] $WireRulesPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Wire\WireRules.cs')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$script:checks = 0
$script:failures = 0

$seatSrc = Get-Content -Raw -LiteralPath $SeatStatePath
$viewSrc = Get-Content -Raw -LiteralPath $ViewPath

# The class is internal so the add-in cannot lean on it from outside the view; PowerShell can only reach a
# public type. That one word is the ONLY change made to the compiled text.
$compiled = $seatSrc -replace 'internal sealed class SeatState', 'public sealed class SeatState'
if ($compiled -eq $seatSrc) { Write-Host 'FAIL  SeatState.cs no longer declares `internal sealed class SeatState`'; exit 1 }
Add-Type -TypeDefinition $compiled -Language CSharp | Out-Null
# Printed so a mutation driver can tell "the mutant compiled and a check caught it" from "it never compiled".
Write-Host 'compiled SeatState.cs'

function New-Seat { New-Object ClarionDebugger.Disassembly.SeatState }
$Seated    = [ClarionDebugger.Disassembly.SeatState+WindowOutcome]::Seated
$EmptySeat = [ClarionDebugger.Disassembly.SeatState+WindowOutcome]::EmptySeat
$EmptySeek = [ClarionDebugger.Disassembly.SeatState+WindowOutcome]::EmptySeek

# Three threads. A is the one execution stopped on.
[uint32] $A = 116932
[uint32] $B = 4812
[uint32] $C = 7000
[uint32] $Z = 0
[uint32] $VA = 0x401000

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '1. the painted thread moves ONLY on a reply that decoded something - never on intent'

$s = New-Seat
$s.Stopped($A, 'MAIN')
Check 'a stop records its seat as IN FLIGHT, not painted' (($s.SeatingTid -eq $A) -and ($s.SeatedTid -eq 0)) `
  "seating=$($s.SeatingTid) seated=$($s.SeatedTid)"
Check 'a stop seat goes straight to disasm: it awaits no registers' (-not $s.AwaitRegs) ''
$o = $s.WindowLanded($A, $A, 12)
Check 'a decoded reply for the stop seat paints the stopped thread' (($o -eq $Seated) -and ($s.SeatedTid -eq $A)) "outcome=$o seated=$($s.SeatedTid)"
Check '...and releases the in-flight seat' (($s.SeatingTid -eq 0) -and (-not $s.AwaitRegs)) "seating=$($s.SeatingTid)"

# Now seat B through the registers, step by step, and watch the painted thread at every step.
$s.SelectionMoving($A, $B)
$began = $s.TryBeginSeat($B)
Check 'selecting another thread starts a seat for it' ($began -and ($s.SeatingTid -eq $B) -and $s.AwaitRegs) "began=$began seating=$($s.SeatingTid)"
Check 'starting a seat does not advance the painted thread (intent is not paint)' ($s.SeatedTid -eq $A) "seated=$($s.SeatedTid)"
$took = $s.TakeRegs($B, $VA)
Check 'the seat thread''s registers are taken, once' ($took -and (-not $s.AwaitRegs)) "took=$took await=$($s.AwaitRegs)"
Check 'taking the registers keeps the seat in flight until the LISTING lands' ($s.SeatingTid -eq $B) "seating=$($s.SeatingTid)"
Check 'taking the registers does not advance the painted thread either' ($s.SeatedTid -eq $A) "seated=$($s.SeatedTid)"
$o = $s.WindowLanded($B, $B, 40)
Check 'only the decoded reply paints the new thread' (($o -eq $Seated) -and ($s.SeatedTid -eq $B)) "outcome=$o seated=$($s.SeatedTid)"

# An UNSTAMPED engine: the reply names no thread, so the selection it passed the gate against is the answer.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($Z, $A, 5)
Check 'an unstamped decoded reply paints the selected thread' ($s.SeatedTid -eq $A) "seated=$($s.SeatedTid)"
# ...and a STAMPED one is believed over the selection. The view's tid gate has already proved the two agree,
# so they only differ here because this probe says so; the point is which one WindowLanded reads.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($B, $A, 5)
Check 'a stamped reply paints the thread it is stamped with' ($s.SeatedTid -eq $B) "seated=$($s.SeatedTid)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2. an EMPTY reply: a failed seat un-paints and records itself; an empty seek claims nothing'

# The Run 3 adversary's scenario, end to end: A painted, seat B, B decodes to nothing.
$s = New-Seat
$s.Stopped($A, 'MAIN')
[void]$s.WindowLanded($A, $A, 12)
$s.SelectionMoving($A, $B)
[void]$s.TryBeginSeat($B)
[void]$s.TakeRegs($B, $VA)
$o = $s.WindowLanded($B, $B, 0)
Check 'a failed seat does not advance SeatedTid to the failed thread' ($s.SeatedTid -ne $B) "seated=$($s.SeatedTid)"
# Successor of the `_seatedTid = 0` anchor: the listing is about to be ERASED, so the thread it showed is no
# longer painted. A still-A flag would let the banner claim A over an empty pane.
Check 'a failed seat UN-paints: the painted flag does not outlive the listing it described' ($s.SeatedTid -eq 0) "seated=$($s.SeatedTid)"
Check 'a failed seat is reported as EmptySeat' ($o -eq $EmptySeat) "outcome=$o"
# Successor of `_emptySeatTid = emptyTid`.
Check 'a failed seat records WHICH thread could not be decoded' ($s.EmptyTid -eq $B) "empty=$($s.EmptyTid)"
Check 'a failed seat still releases its latch, so a later seat can run' (($s.SeatingTid -eq 0) -and (-not $s.AwaitRegs)) "seating=$($s.SeatingTid)"
# ...and the already-painted guard no longer lies about A.
$s.SelectionMoving($B, $A)
Check 'after a failed seat, switching back to the old thread RESEATS it' ($s.TryBeginSeat($A)) "seated=$($s.SeatedTid)"

# wasSeat must be read BEFORE the in-flight state is released; read after, every empty reply looks like a
# seek. Both halves of "in flight" are exercised: the disasm-only stop seat and the registers-only seat.
$s = New-Seat
$s.Stopped($A, $null)
Check 'an empty reply to a STOP seat (seating only) is a seat, not a seek' ($s.WindowLanded($A, $A, 0) -eq $EmptySeat) ''
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
[void]$s.TryBeginSeat($B)
Check 'an empty reply while still AWAITING registers is a seat, not a seek' ($s.WindowLanded($B, $B, 0) -eq $EmptySeat) ''

# A coarse SEEK into unmapped memory says nothing about any thread's own address.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
$s.Seek()
$o = $s.WindowLanded($A, $A, 0)
Check 'an empty SEEK is reported as EmptySeek' ($o -eq $EmptySeek) "outcome=$o"
# Successor of the `if (wasSeat)` gate: only a SEAT may claim a thread's code could not be decoded.
Check 'an empty seek does NOT claim the thread could not be decoded' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"
Check 'an empty seek still un-paints, since it erases the listing too' ($s.SeatedTid -eq 0) "seated=$($s.SeatedTid)"
# ...and it RETIRES a claim a previous failed seat left behind, at the moment of the seek.
$s = New-Seat
$s.Stopped($B, $null)
[void]$s.WindowLanded($B, $B, 0)
Check 'CONTROL: the failed seat left its claim' ($s.EmptyTid -eq $B) "empty=$($s.EmptyTid)"
$s.Seek()
Check 'a seek retires an earlier failed seat''s claim immediately, before its reply lands' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"
[void]$s.WindowLanded($B, $B, 0)
Check '...and the seek''s own empty reply does not re-create it' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"

# A decoded reply clears an earlier empty claim: it decodes after all.
$s = New-Seat
$s.Stopped($B, $null)
[void]$s.WindowLanded($B, $B, 0)
$s.Seek()
[void]$s.WindowLanded($B, $B, 9)
Check 'a decoded reply clears the empty claim' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2b. every reseat retires what was in flight (the epoch), and nothing else can move it'

function Test-Retires([string] $Name, [scriptblock] $Prepare, [scriptblock] $Act) {
  $s = New-Seat
  & $Prepare $s
  [void]$s.TryBeginExtend($true)
  [void]$s.TryBeginExtend($false)
  $e0 = $s.Epoch
  & $Act $s
  Check "$Name retires in-flight replies (new epoch)" (($s.Epoch -ne $e0) -and (-not $s.IsCurrent($e0))) "epoch $e0 -> $($s.Epoch)"
  Check "$Name clears both edge-extension flags" ((-not $s.PendFwd) -and (-not $s.PendBwd)) "fwd=$($s.PendFwd) bwd=$($s.PendBwd)"
}
$painted = { param($x) $x.Stopped($A, $null); [void]$x.WindowLanded($A, $A, 3) }
Test-Retires 'a stop'            { param($x) }       { param($x) $x.Stopped($A, $null) }
Test-Retires 'a thread seat'     $painted            { param($x) [void]$x.TryBeginSeat($B) }
Test-Retires 'a recentre'        $painted            { param($x) [void]$x.BeginRecentre($A) }
Test-Retires 'a coarse seek'     $painted            { param($x) $x.Seek() }
Test-Retires 'a rebind'          $painted            { param($x) $x.Rebound() }
Test-Retires 'an exit'           $painted            { param($x) $x.Exited() }

# The reverse: transitions that are NOT a reseat must leave the epoch alone, or a reply the view still
# wants would be dropped.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.TryBeginSeat($B)
$e0 = $s.Epoch
[void]$s.TakeRegs($B, $VA)
[void]$s.TryBeginExtend($true); $s.ExtendLanded($true)
$s.SelectionMoving($B, $C)
[void]$s.Failed()
Check 'regs, extensions, selection moves and errors do not retire replies' ($s.IsCurrent($e0)) "epoch $e0 -> $($s.Epoch)"

# A seat that is REFUSED by a guard must not retire anything either: it started nothing.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
$e0 = $s.Epoch
[void]$s.TryBeginSeat($A)
Check 'a refused seat (already painted) leaves the epoch alone' ($s.IsCurrent($e0)) "epoch $e0 -> $($s.Epoch)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2c. the seat guards, and what clears them'

$s = New-Seat
Check 'no seat for an unknown thread' (-not $s.TryBeginSeat($Z)) ''
$s.Stopped($A, $null)
Check 'no second seat while the stop''s own seat is in flight' (-not $s.TryBeginSeat($A)) ''
[void]$s.WindowLanded($A, $A, 3)
Check 'no seat for the thread already painted' (-not $s.TryBeginSeat($A)) ''
[void]$s.TryBeginSeat($B)
Check 'no second seat for a thread already on its way' (-not $s.TryBeginSeat($B)) ''
[void]$s.TakeRegs($B, $VA)
[void]$s.WindowLanded($B, $B, 0)
Check 'no retry for a thread that decoded to nothing this episode' (-not $s.TryBeginSeat($B)) ''
$s.SelectionMoving($B, $B)
Check 're-selecting the SAME thread keeps that verdict' (($s.EmptyTid -eq $B) -and -not $s.TryBeginSeat($B)) "empty=$($s.EmptyTid)"
$s.SelectionMoving($B, $C)
Check 'moving to a DIFFERENT thread clears it' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"
Check '...so the failed thread may be tried again' ($s.TryBeginSeat($B)) ''
$s = New-Seat
$s.Stopped($B, $null)
[void]$s.WindowLanded($B, $B, 0)
$s.Stopped($B, $null)
Check 'a new stop clears the empty verdict' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"
$s = New-Seat
$s.Stopped($B, $null)
[void]$s.WindowLanded($B, $B, 0)
$s.Rebound()
Check 'a rebind clears the empty verdict' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"
# From a PAINTED state, or a rebind that forgot the painted thread would pass for want of one.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
[void]$s.TryBeginSeat($B)
$s.Rebound()
Check 'a rebind clears the painted thread and the seat in flight' (($s.SeatedTid -eq 0) -and ($s.SeatingTid -eq 0) -and (-not $s.AwaitRegs)) `
  "seated=$($s.SeatedTid) seating=$($s.SeatingTid)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2d. registers move the window only when WE asked, for THAT thread, and say where'

$s = New-Seat
$s.Stopped($A, $null)
Check 'registers nobody asked for are ignored (the stop seat needs none)' (-not $s.TakeRegs($A, $VA)) ''
[void]$s.WindowLanded($A, $A, 3)
[void]$s.TryBeginSeat($B)
Check 'another thread''s registers are ignored' (-not $s.TakeRegs($C, $VA)) ''
Check 'unstamped registers are ignored' (-not $s.TakeRegs($Z, $VA)) ''
Check 'registers with no usable EIP are ignored' (-not $s.TakeRegs($B, 0)) ''
Check '...and none of those consumed the request' ($s.AwaitRegs) ''
Check 'the right thread''s registers are taken' ($s.TakeRegs($B, $VA)) ''
Check 'and only once: the pad''s own later regs reply cannot move the window' (-not $s.TakeRegs($B, $VA)) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2e. an engine error releases a seat without inventing a decode failure'

$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
Check 'an error with nothing in flight is not ours' (-not $s.Failed()) ''
[void]$s.TryBeginSeat($B)
Check 'an error releases a seat in flight' ($s.Failed() -and ($s.SeatingTid -eq 0) -and (-not $s.AwaitRegs)) "seating=$($s.SeatingTid)"
Check 'an error does not claim the thread could not be decoded' ($s.EmptyTid -eq 0) "empty=$($s.EmptyTid)"
Check 'an error does not change what is painted' ($s.SeatedTid -eq $A) "seated=$($s.SeatedTid)"
$s.SelectionMoving($A, $B)
Check 'after an error the thread can be seated again' ($s.TryBeginSeat($B)) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2f. a seek abandons a pending seat and nothing re-asserts it (876ddf1d: the scroll wins)'

$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
$s.SelectionMoving($A, $B)
[void]$s.TryBeginSeat($B)
$s.Seek()
Check 'a seek abandons the pending thread seat' (($s.SeatingTid -eq 0) -and (-not $s.AwaitRegs)) "seating=$($s.SeatingTid)"
Check 'so the switch''s late registers cannot yank the view off the scroll' (-not $s.TakeRegs($B, $VA)) ''
[void]$s.WindowLanded($B, $B, 20)
Check 'the seek''s reply honestly paints the selected thread (its code, at the scrolled address)' ($s.SeatedTid -eq $B) "seated=$($s.SeatedTid)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2g. recentre: the explicit way back to the current instruction (876ddf1d)'

$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
$s.Seek()
[void]$s.WindowLanded($A, $A, 7)
Check 'CONTROL: after a seek the ordinary seat refuses, because the thread IS painted' (-not $s.TryBeginSeat($A)) ''
Check 'recentre seats anyway, on the selected thread, through its registers' `
  ($s.BeginRecentre($A) -and ($s.SeatingTid -eq $A) -and $s.AwaitRegs) "seating=$($s.SeatingTid) await=$($s.AwaitRegs)"
Check 'recentre leaves the painted thread alone until the new window lands' ($s.SeatedTid -eq $A) "seated=$($s.SeatedTid)"
Check 'recentre on an unknown thread does nothing' (-not (New-Seat).BeginRecentre($Z)) ''
$s = New-Seat
$s.Stopped($B, $null)
[void]$s.WindowLanded($B, $B, 0)
Check 'recentre retries a thread that decoded to nothing (an explicit ask is worth one retry)' ($s.BeginRecentre($B)) ''
# A STOP RETIRES A PENDING RECENTRE'S REGISTER REQUEST (wave 5, from Oscar). The stop seat goes straight to
# disasm, so a recentre still waiting on registers when the target stops must not stay armed: its regs reply
# would re-seat the fresh stop on the OLD request. Measured 2026-09-24: a Stopped() that carried the flag
# across its NewEpoch() passed all 130 checks before these two.
$s = New-Seat
$s.Stopped($A, $null)
[void]$s.WindowLanded($A, $A, 3)
[void]$s.BeginRecentre($A)
$s.Stopped($B, $null)
Check 'a stop clears a pending recentre''s AwaitRegs' (-not $s.AwaitRegs) "await=$($s.AwaitRegs) seating=$($s.SeatingTid)"
Check '...so the stopped thread''s registers are not taken on the recentre''s behalf' (-not $s.TakeRegs($B, [uint32] 0x401000)) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2h. edge extensions: one in flight per direction'

$s = New-Seat
Check 'a forward extension can start' ($s.TryBeginExtend($true)) ''
Check 'a second forward extension cannot' (-not $s.TryBeginExtend($true)) ''
Check 'a backward one is independent' ($s.TryBeginExtend($false)) ''
$s.ExtendLanded($true)
Check 'a landed forward extension frees that direction only' ($s.TryBeginExtend($true) -and -not $s.TryBeginExtend($false)) ''
$s.Stopped($A, $null)
[void]$s.TryBeginExtend($true)
[void]$s.WindowLanded($A, $A, 5)
Check 'a fresh window clears both extension flags' ((-not $s.PendFwd) -and (-not $s.PendBwd)) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2i. the derived answers: banner, stop symbol, late-open'

$s = New-Seat
$s.Stopped($A, 'MAIN')
[void]$s.WindowLanded($A, $A, 3)
Check 'banner blank while the stopped thread is painted' ($s.ForeignSeatedTid($A, $A) -eq 0) ''
[void]$s.TryBeginSeat($B)
Check 'banner blank while ANOTHER thread is only selected, not painted' ($s.ForeignSeatedTid($B, $A) -eq 0) ''
[void]$s.TakeRegs($B, $VA); [void]$s.WindowLanded($B, $B, 3)
Check 'banner names the painted thread once it is painted' ($s.ForeignSeatedTid($B, $A) -eq $B) ''
Check 'banner blank when the painted thread is no longer the selected one' ($s.ForeignSeatedTid($C, $A) -eq 0) ''
Check 'banner blank when the stopped thread is unknown' ($s.ForeignSeatedTid($B, $Z) -eq 0) ''
Check 'banner blank while nothing is painted' ((New-Seat).ForeignSeatedTid($B, $A) -eq 0) ''

$s = New-Seat
$s.Stopped($A, 'MAIN')
Check 'the stop symbol labels the stopped thread' ($s.SymbolFor($A, $A) -eq 'MAIN') (ShowVal $s.SymbolFor($A, $A))
Check 'the stop symbol is NOT shown for another selected thread' ($null -eq $s.SymbolFor($B, $A)) (ShowVal $s.SymbolFor($B, $A))
Check 'the stop symbol is shown when either thread is unknown' (($s.SymbolFor($Z, $A) -eq 'MAIN') -and ($s.SymbolFor($B, $Z) -eq 'MAIN')) ''
[void]$s.WindowLanded($A, $A, 0)
Check 'an empty seat does not destroy the stop symbol (still true for the stopped thread)' ($s.SymbolFor($A, $A) -eq 'MAIN') ''
$s.Exited()
Check 'an exit clears the stop symbol' ($null -eq $s.SymbolFor($A, $A)) ''

$s = New-Seat
Check 'a fresh seat knows nothing' ($s.KnowsNothing($Z)) ''
Check 'a known selection is knowing something' (-not $s.KnowsNothing($B)) ''
$s.Stopped($A, $null)
Check 'a seat in flight is knowing something' (-not $s.KnowsNothing($Z)) ''
[void]$s.WindowLanded($A, $A, 3)
Check 'a painted thread is knowing something' (-not $s.KnowsNothing($Z)) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '3. the shape rules that behaviour cannot see'

$seatCode = Get-CSharpCodeOnly $seatSrc
$viewCode = Get-CSharpCodeOnly $viewSrc

# NO SEAT FIELD LIVES IN THE VIEW ANY MORE. A reintroduced `_seatedTid` (or any of its siblings) in
# DisassemblyView.cs is the prose-rules machine coming back. Comments stripped first: the view's comments
# may name the old fields when explaining history.
$fieldRx = '\b_(seatedTid|seatingTid|emptySeatTid|awaitRegsSeat|pendFwd|pendBwd|epoch|curSym)\b'
$hits = [regex]::Matches($viewCode, $fieldRx)
Check 'DisassemblyView keeps no seat field of its own' ($hits.Count -eq 0) (($hits | ForEach-Object { $_.Value }) -join ', ')
Check 'CONTROL: the field scan sees one in code' ([regex]::Matches((Get-CSharpCodeOnly 'x = _seatedTid;'), $fieldRx).Count -eq 1) ''

# THE EPOCH MOVES IN ONE PLACE, and that place is private: no caller can bump it without a named transition.
$bumps = [regex]::Matches($seatCode, '_epoch\s*(\+\+|\+=|=[^=])')
Check 'the epoch is written in exactly one statement' ($bumps.Count -eq 1) "$($bumps.Count) write(s)"
Check 'and that statement is inside the private NewEpoch' `
  ((Get-CSharpCodeOnly (Get-Method 'private void NewEpoch()' $seatSrc)) -match '_epoch\s*\+\+') ''

# TidOf AND NOWHERE ELSE stays true: SeatState takes tids already converted, so it has no uint? to unwrap.
Check 'SeatState takes no uint?: the view''s TidOf stays the only conversion' ($seatCode -notmatch 'uint\?') ''

# THE VIEW'S OWN ORDER in the WinTag branch: the seat is settled BEFORE the listing is replaced, and the
# banner is re-derived AFTER. A WindowLanded moved below the cache replacement is a frame in which the painted
# flag and the screen disagree; a banner refresh moved above it reads the old state.
$onDisasm = Get-Method 'private void OnDisasm(string tag, List<DebugDisasmInstr> instrs, uint? tid)' $viewSrc
$winCode = Get-CSharpCodeOnly $onDisasm
$winAt = $winCode.IndexOf('if (kind == WinTag)')
$arm = if ($winAt -ge 0) { $winCode.Substring($winAt) } else { '' }
$iLanded = $arm.IndexOf('_seat.WindowLanded(')
$iLocClr = $arm.IndexOf('_curPath = _curModule = null')
$iCache  = $arm.IndexOf('_instrs = SortedUnique')
$iBanner = $arm.IndexOf('UpdateThreadBanner()')
# Anchors first: every check below is an order comparison, and -1 < anything.
Check 'every anchor the order checks need is present in OnDisasm' `
  (($iLanded -ge 0) -and ($iLocClr -ge 0) -and ($iCache -ge 0) -and ($iBanner -ge 0)) `
  "landed=$iLanded locclear=$iLocClr cache=$iCache banner=$iBanner"
Check 'the seat is settled BEFORE the listing is replaced' (($iLanded -ge 0) -and ($iLanded -lt $iCache)) "landed=$iLanded cache=$iCache"
Check 'the empty seat''s location clear sits between the two' (($iLocClr -gt $iLanded) -and ($iLocClr -lt $iCache)) "locclear=$iLocClr"
Check 'the location clear is gated on EmptySeat, not on any empty reply' `
  ($arm -match 'if\s*\(\s*outcome\s*==\s*SeatState\.WindowOutcome\.EmptySeat\s*\)\s*\{\s*_curPath = _curModule = null') ''
Check 'the banner is re-derived AFTER the listing is replaced' (($iBanner -ge 0) -and ($iBanner -gt $iCache)) "banner=$iBanner cache=$iCache"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '4. stepping while viewing another thread says what it will do (375d463b)'
# The step buttons stay ENABLED - stepping is defined on the stopped thread and is a legitimate thing to want
# from anywhere - but the tooltip and the banner name the thread that will run and say the view returns to it.
# The "another thread" rule is SeatState.IsOtherThread (compiled above) - ONE statement of it, read by the
# banner, the stop symbol and these tooltips. StepTip is compiled out of the shipped view; the wiring is
# pinned as statements.
$stepTip = Get-Method 'private static string StepTip(string tip, string stoppedName)' $viewSrc
Add-Type -TypeDefinition @"
public static class DisasmStepProbe {
$($stepTip -replace 'private static', 'public static')
}
"@ -Language CSharp | Out-Null
Check 'another selected thread, both known: viewing another thread' ([ClarionDebugger.Disassembly.SeatState]::IsOtherThread($B, $A)) ''
Check 'the stopped thread itself: not another thread' (-not [ClarionDebugger.Disassembly.SeatState]::IsOtherThread($A, $A)) ''
Check 'selection unknown: says nothing' (-not [ClarionDebugger.Disassembly.SeatState]::IsOtherThread($Z, $A)) ''
Check 'stopped thread unknown: says nothing' (-not [ClarionDebugger.Disassembly.SeatState]::IsOtherThread($B, $Z)) ''
$plain = 'Step over one instruction'
# [NullString]::Value, not $null: PowerShell hands a .NET string parameter "" for $null.
Check 'on the stopped thread the tooltip is the plain one' ([DisasmStepProbe]::StepTip($plain, [NullString]::Value) -eq $plain) ''
$tip = [DisasmStepProbe]::StepTip($plain, 'Thread 2')
Check 'elsewhere the tooltip keeps the plain text first' ($tip.StartsWith($plain)) $tip
Check '...names the thread that will run, as the stopped thread' ($tip -match 'on Thread 2, the stopped thread') $tip
Check '...and says the view returns to it' ($tip -match 'returns to it') $tip

$updTips = Get-CSharpCodeOnly (Get-Method 'private void UpdateStepTips()' $viewSrc)
Check 'the tooltips name the STOPPED thread, never the viewed one' `
  (($updTips -match 'ThreadName\(StoppedTid\)') -and ($updTips -notmatch 'ThreadName\(SelTid\)')) ''
Check 'the tooltips speak only when SeatState.IsOtherThread says so' ($updTips -match 'SeatState\.IsOtherThread\(SelTid,\s*StoppedTid\)') ''
foreach ($pair in @(@('_bOver', 'TipOver'), @('_bInto', 'TipInto'), @('_bOut', 'TipOut'))) {
  Check "$($pair[0]) gets its own tip through StepTip" `
    ($updTips -match ([regex]::Escape($pair[0]) + '\.ToolTipText\s*=\s*StepTip\(' + $pair[1] + ',\s*stopped\)')) ''
}
$banner = Get-CSharpCodeOnly (Get-Method 'private void UpdateThreadBanner()' $viewSrc)
# As a STATEMENT at the start of a line: `if (x) UpdateStepTips();` would disable it and still contain the text.
Check 'every banner refresh re-words the step tooltips (an unconditional statement)' ($banner -match '(?m)^\s*UpdateStepTips\(\);') ''
Check 'the visible banner says which thread Step runs' ($banner -match 'Step runs "\s*\+\s*ThreadName\(StoppedTid\)') ''
# THE DECISION ITSELF: the buttons are not disabled for viewing another thread. Enabled means paused, only.
$updBtns = Get-CSharpCodeOnly (Get-Method 'private void UpdateButtons(DebugSessionState s)' $viewSrc)
foreach ($btn in '_bOver', '_bInto', '_bOut') {
  Check "$btn stays enabled whenever paused (explained, not taken away)" `
    ($updBtns -match ('(?m)^\s*if \(' + $btn + '\s*!= null\) ' + $btn + '\.Enabled\s*=\s*paused;')) ''
}

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '5. the way back to the current instruction, and the scroll that it makes harmless (876ddf1d)'
# BeginRecentre's behaviour is section 2g. These pin the view's entry points to it, by statement.
$recentre = Get-CSharpCodeOnly (Get-Method 'private void Recentre()' $viewSrc)
Check 'recentre seats through SeatState and asks for the registers only if a seat began' `
  ($recentre -match 'if \(_seat\.BeginRecentre\(SelTid\)\) _svc\.RequestRegs\(\);') ''
# The SELECTED thread's registers, never the stopped thread's address: CurrentVa while another thread is
# selected is the blind-seat defect SeatOnLateOpen documents.
Check 'recentre never seats blind on an address' (($recentre -notmatch 'CurrentVa') -and ($recentre -notmatch 'RequestDisasmAt') -and ($recentre -notmatch 'StoppedTid')) ''
Check 'recentre does nothing unless paused' ($recentre -match '_svc\.State != DebugSessionState\.Paused\) return;') ''
Check 'the toolbar has a Current button wired to Recentre' ($viewCode -match '_bCur\s*=\s*AddButton\("[^"]*Current",\s*"[^"]*",\s*Recentre\);') ''
$cmdKey = Get-CSharpCodeOnly (Get-Method 'protected override bool ProcessCmdKey(ref Message msg, Keys keyData)' $viewSrc)
Check 'Alt+* recentres, and is consumed' ($cmdKey -match 'if \(keyData == \(Keys\.Alt \| Keys\.Multiply\)\) \{ Recentre\(\); return true; \}') ''
$updRec = Get-CSharpCodeOnly (Get-Method 'private void UpdateRecentre()' $viewSrc)
Check 'Current is enabled only while paused on a known thread' `
  ($updRec -match '_bCur\.Enabled = _svc\?\.State == DebugSessionState\.Paused && SelTid != 0;') ''
Check '...re-evaluated on every state change (an unconditional statement)' ($updBtns -match '(?m)^\s*UpdateRecentre\(\);') ''
Check '...and on every selection change, with the banner' ($banner -match '(?m)^\s*UpdateRecentre\(\);') ''
# THE SCROLL WINS (the PM's ruling on 876ddf1d): a seek retires the pending switch seat and nothing in it
# re-asserts one. Re-seating here would yank the view off where the user just scrolled.
$coarse = Get-CSharpCodeOnly (Get-Method 'private void OnCoarseScroll(object sender, ScrollEventArgs e)' $viewSrc)
Check 'a coarse seek goes through SeatState.Seek' ($coarse -match '(?m)^\s*_seat\.Seek\(\);') ''
Check 'a coarse seek never re-asserts a thread seat' `
  ($coarse -notmatch 'BeginRecentre|TryBeginSeat|SeatOnSelectedThread|RequestRegs') ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '6. ONE selected thread, and it is the service''s (49538b78 8b)'
# The view kept _selTid and _stoppedTid, fed by its own reading of Paused, threads and threadselected; the grant
# table kept a third copy. Now the service is the one writer (tools/test-addin-selection.ps1 runs it) and the
# view holds only the snapshot it was handed. RUN below: the real TakeSelection and ApplySelection, lifted out of
# the shipped view, over the real SeatState and the real ThreadSelection; the view's two other reactions
# (UpdateThreadBanner, SeatOnSelectedThread) are recorders. SeatState is compiled again under another namespace:
# one process cannot define a type twice.
$svcSrc = Get-Content -Raw -LiteralPath $ServicePath
$wireSrc = Get-Content -Raw -LiteralPath $WireRulesPath
$selSeat = ($compiled -replace '(?m)^using [^;]+;
?
', '') -replace 'namespace ClarionDebugger\.Disassembly', 'namespace SelProbe'
$selWire = ($wireSrc -replace '(?m)^using [^;]+;\r?\n', '') -replace 'namespace ClarionDebugger\.Wire', 'namespace SelProbe' -replace 'internal static class', 'public static class'
$selTypes = (Get-Method 'public enum ThreadSelectionCause' $svcSrc) + "`n" + (Get-Method 'public sealed class ThreadSelection' $svcSrc)
$selTake = (Get-Method 'internal static SelectionStep TakeSelection(ref ThreadSelection held, ThreadSelection s, SeatState seat)' $viewSrc) -replace '^internal static', 'public static'
$selApply = (Get-Method 'private void ApplySelection(ThreadSelection s)' $viewSrc) -replace '^private void', 'public void'
$selStep = (Get-Method 'internal enum SelectionStep' $viewSrc) -replace '^internal', 'public'
$selTidOf = Get-Method 'private static uint TidOf(uint? t)' $viewSrc
$selStopSeat = (Get-Method 'internal static uint StopSeatTid(uint? stoppedTid, uint selTid)' $viewSrc) -replace '^internal static', 'public static'
$selSrc = @"
using System;
using System.Collections.Generic;
using System.Globalization;
$selSeat
$selWire
namespace SelProbe {
$selTypes
public class ViewSelectionProbe {
  public ThreadSelection _selection = ThreadSelection.None;
  public SeatState _seat = new SeatState();
  public object _svc;   // the bound service; null here, and so is every snapshot's Source unless a test names one
  public int Banners, Seats;
  private void UpdateThreadBanner() { Banners++; }
  private void SeatOnSelectedThread() { Seats++; }
  $selStep
  $selTidOf
  $selStopSeat
  $selTake
  $selApply
  public uint SelTid { get { return TidOf(_selection.Tid); } }
}
}
"@
Add-Type -TypeDefinition $selSrc -Language CSharp | Out-Null
Write-Host 'compiled the view''s selection steps'
function Snap { param($tid, $stopped, [int] $epoch, $cause, $source = $null)
  New-Object SelProbe.ThreadSelection ([Nullable[uint32]]$tid), ([Nullable[uint32]]$stopped), $epoch, ([Enum]::Parse([SelProbe.ThreadSelectionCause], $cause)), $source
}

$v = New-Object SelProbe.ViewSelectionProbe
$v.ApplySelection((Snap $A $A 1 'Stop'))
Check 'a stop''s snapshot is held: SelTid is the stopped thread' (($v.SelTid -eq $A) -and ($v.Banners -eq 1)) "sel=$($v.SelTid) banners=$($v.Banners)"
Check '...and a stop does not re-seat here: OnPaused seats the stop''s own address' ($v.Seats -eq 0) "seats=$($v.Seats)"
$v.ApplySelection((Snap $B $A 2 'Switch'))
Check 'a switch''s snapshot moves the view and re-seats it, once' (($v.SelTid -eq $B) -and ($v.Seats -eq 1)) "sel=$($v.SelTid) seats=$($v.Seats)"
$v.ApplySelection((Snap $C $A 3 'Inventory'))
Check 'an inventory that moved the selection re-seats too' (($v.SelTid -eq $C) -and ($v.Seats -eq 2)) "sel=$($v.SelTid) seats=$($v.Seats)"
$b0 = $v.Banners
$v.ApplySelection((Snap $B $A 2 'Switch'))
Check 'an OLDER snapshot, queued behind a newer one, changes nothing' (($v.SelTid -eq $C) -and ($v.Seats -eq 2) -and ($v.Banners -eq $b0)) "sel=$($v.SelTid) seats=$($v.Seats)"
$v.ApplySelection((Snap $C $A 3 'Inventory'))
Check 'the SAME snapshot delivered twice (event and direct read) changes nothing' (($v.Seats -eq 2) -and ($v.Banners -eq $b0)) "seats=$($v.Seats)"
$v.ApplySelection((Snap $null $null 4 'Ended'))
Check 'a session''s end is held: nothing is selected, and nothing re-seats' (($v.SelTid -eq 0) -and ($v.Seats -eq 2)) "sel=$($v.SelTid) seats=$($v.Seats)"
# THE NEXT SESSION on the same service carries on from its epoch (never reset: test-addin-selection.ps1), so its
# first snapshot is newer and is taken, and a switch in it seats.
$v.ApplySelection((Snap $A $A 5 'Stop'))
$v.ApplySelection((Snap $B $A 6 'Switch'))
Check 'the next session''s first snapshot is taken, and its switch seats' (($v.SelTid -eq $B) -and ($v.Seats -eq 3)) "sel=$($v.SelTid) seats=$($v.Seats)"
# ...where a service that RESET its epoch would have been ignored for the rest of the view's life: this is the
# failure the never-reset rule prevents, shown on the view's side.
$r = New-Object SelProbe.ViewSelectionProbe
$r.ApplySelection((Snap $A $A 9 'Stop'))
$r.ApplySelection((Snap $B $B 1 'Stop'))
Check 'CONTROL: a snapshot whose epoch went BACKWARDS is ignored (why the service must never reset it)' ($r.SelTid -eq $A) "sel=$($r.SelTid)"
# A REBIND (pipeline run 1, debugger L1). The view outlives a service: bound to A, a snapshot of A's is queued,
# the view is rebound to B (Bind: SeatState.Rebound, the selection back to None), and A's snapshot is delivered
# after. It is not B's selection whatever its epoch, and B's own first snapshot must seat.
$svcA = New-Object object; $svcB = New-Object object
$rb = New-Object SelProbe.ViewSelectionProbe
$rb._svc = $svcA
$rb.ApplySelection((Snap $A $A 50 'Stop' $svcA))
$queuedA = Snap $B $A 51 'Switch' $svcA
$rb._svc = $svcB; $rb._seat.Rebound(); $rb._selection = [SelProbe.ThreadSelection]::None
$rb.ApplySelection($queuedA)
Check 'after a rebind, a snapshot the OLD service made is dropped' (($rb.SelTid -eq 0) -and ($rb.Seats -eq 0)) "sel=$($rb.SelTid) seats=$($rb.Seats)"
$rb.ApplySelection((Snap $C $C 52 'Switch' $svcB))
Check '...and the new service''s first snapshot is taken, and seats' (($rb.SelTid -eq $C) -and ($rb.Seats -eq 1)) "sel=$($rb.SelTid) seats=$($rb.Seats)"
# A switch lets a thread that decoded to nothing be tried again: TakeSelection hands the move to SeatState.
$m = New-Object SelProbe.ViewSelectionProbe
$m.ApplySelection((Snap $A $A 1 'Stop'))
[void]$m._seat.TryBeginSeat($B); [void]$m._seat.TakeRegs($B, $VA); [void]$m._seat.WindowLanded($B, $B, 0)
$emptyBefore = $m._seat.EmptyTid
$m.ApplySelection((Snap $B $A 2 'Switch'))
Check 'a switch to another thread clears the decoded-to-nothing record (SelectionMoving)' (($emptyBefore -eq $B) -and ($m._seat.EmptyTid -eq 0)) "before=$emptyBefore after=$($m._seat.EmptyTid)"

# The wiring, which a WinForms control keeps out of reach: subscribed and unsubscribed once each, handed on
# whole, and read before the late open asks for the inventory.
Check 'the view subscribes to SelectionChanged once and unsubscribes once' `
  (([regex]::Matches($viewCode, '_svc\.SelectionChanged\s*\+=\s*OnSelectionChanged;').Count -eq 1) -and `
   ([regex]::Matches($viewCode, '_svc\.SelectionChanged\s*-=\s*OnSelectionChanged;').Count -eq 1)) ''
Check 'OnSelectionChanged hands every snapshot to ApplySelection' `
  ($viewCode -match 'private void OnSelectionChanged\(ThreadSelection s\) => UI\(\(\) => ApplySelection\(s\)\);') ''
$lateOpen = Get-CSharpCodeOnly (Get-Method 'private void SeatOnLateOpen()' $viewSrc)
$iTake = $lateOpen.IndexOf('TakeSelection(ref _selection, _svc.Selection, _seat)'); $iThreads = $lateOpen.IndexOf('_svc.RequestThreads();')
Check 'a late open takes the service''s selection BEFORE it asks for the inventory' (($iTake -ge 0) -and ($iThreads -gt $iTake)) "take=$iTake threads=$iThreads"
# NO SELECTION OF ITS OWN: every write of _selection is None, the service's own, or TakeSelection's ref; and no
# uint field names a thread.
$selWrites = @([regex]::Matches($viewCode, '(?<![=!<>])_selection\s*=(?!=)\s*([^;]+);') | ForEach-Object { $_.Groups[1].Value.Trim() })
$badWrites = @($selWrites | Where-Object { $_ -ne 'ThreadSelection.None' -and $_ -ne '_svc.Selection' })
Check 'the view assigns _selection only from ThreadSelection.None or _svc.Selection' (($selWrites.Count -ge 2) -and ($badWrites.Count -eq 0)) `
  ("writes: " + ($selWrites -join ' | '))
$tidFieldRx = '(?m)^\s*private\s+uint\??\s+_\w*[Tt]id\s*[;=]'
Check 'the view declares no thread-id field of its own' ([regex]::Matches($viewCode, $tidFieldRx).Count -eq 0) (([regex]::Matches($viewCode, $tidFieldRx) | ForEach-Object { $_.Value.Trim() }) -join ', ')
Check 'CONTROL: that scan finds the field this ticket removed' ([regex]::Matches((Get-CSharpCodeOnly "        private uint _selTid;        // x`n"), $tidFieldRx).Count -eq 1) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '7. a stop is seated under ITS OWN thread, never under a newer selection (debugger L3, wave 6)'
# A late open reads the service's selection directly, and that read can be AHEAD of a stop still queued for the
# UI thread: a switch made since. OnPaused used to record the stop's seat under the held (newer) selection, with
# the STOPPED thread's address. RUN: the real StopSeatTid over the real SeatState; OnPaused's use of it is pinned
# by position below, since the view is a WinForms control.
Check 'a stop that names its thread is seated under it, whatever selection is held' `
  (([SelProbe.ViewSelectionProbe]::StopSeatTid([Nullable[uint32]]$A, $B) -eq $A) -and ([SelProbe.ViewSelectionProbe]::StopSeatTid([Nullable[uint32]]$A, $A) -eq $A)) ''
Check 'a stop that names none (an unstamped engine) is seated under the held selection, as before' `
  (([SelProbe.ViewSelectionProbe]::StopSeatTid($null, $B) -eq $B) -and ([SelProbe.ViewSelectionProbe]::StopSeatTid([Nullable[uint32]]0, $B) -eq $B)) ''
# The whole sequence OnPaused runs when the held selection (B) is newer than the stop (A): the stop's seat is A's,
# and because B is another thread the view reseats on B - a new epoch, which retires the window asked at A's VA.
$l3 = New-Object SelProbe.ViewSelectionProbe
$l3.ApplySelection((Snap $A $A 1 'Stop')); $l3.ApplySelection((Snap $B $A 2 'Switch'))   # the late read, ahead of the stop
$seatTid = [SelProbe.ViewSelectionProbe]::StopSeatTid([Nullable[uint32]]$A, $l3.SelTid)
$l3._seat.Stopped($seatTid, 'MAIN')
$stopEpoch = $l3._seat.Epoch
Check 'the stop''s window is in flight for the STOPPED thread, not the held one' ($l3._seat.SeatingTid -eq $A) "seating=$($l3._seat.SeatingTid)"
$other = [ClarionDebugger.Disassembly.SeatState]::IsOtherThread($l3.SelTid, $seatTid)
$began = $l3._seat.TryBeginSeat($l3.SelTid)
Check '...and the held selection being another thread starts a seat on it, retiring the stop''s window' `
  ($other -and $began -and ($l3._seat.SeatingTid -eq $B) -and (-not $l3._seat.IsCurrent($stopEpoch))) "other=$other began=$began seating=$($l3._seat.SeatingTid)"
$paused = Get-CSharpCodeOnly (Get-Method 'private void OnPaused(DebugPause p)' $viewSrc)
$iSeatTid = $paused.IndexOf('uint seatTid = StopSeatTid(p.Tid, SelTid);')
$iStopped = $paused.IndexOf('_seat.Stopped(seatTid, p.Sym);')
$iWindow = $paused.IndexOf('_svc?.RequestDisasmAt(p.Va, WindowCount, MakeTag(WinTag), Context);')
$iReseat = $paused.IndexOf('if (SeatState.IsOtherThread(SelTid, seatTid)) SeatOnSelectedThread();')
Check 'OnPaused seats the stop under StopSeatTid, asks for its window, THEN reseats on another held thread' `
  (($iSeatTid -ge 0) -and ($iStopped -gt $iSeatTid) -and ($iWindow -gt $iStopped) -and ($iReseat -gt $iWindow)) `
  "seatTid=$iSeatTid stopped=$iStopped window=$iWindow reseat=$iReseat"
Check 'and nothing else in OnPaused records a seat under SelTid' ($paused -notmatch '_seat\.Stopped\(SelTid') ''

# The count, asserted: "ALL CHECKS PASSED" is equally true of a run that silently skipped a section.
$EXPECTED_CHECKS = 156
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
