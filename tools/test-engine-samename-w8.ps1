# suite: live=yes
# suite: live=no; args=-SelfTest
#
# Same-named DLLs, wave 8 (fb5766d1 #3 and #8), live: builds tools\fixtures\samename-w8 (plus the wave 7
# samehost.exe) with Clarion 11 and drives the engine over it in two interactive sessions.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE:
#   CAN  - (1) that an expandable row carries its OWN image's imgBase, and that `expand ... <imgBase>` reads the
#          referent in THAT image's TSWD (A's class members VA/VA2, B's PB/VB); that a base no shared.dll has, or
#          a malformed one, gets no children; and that no base keeps today's first-match;
#          (2) that a same-build copy (c\shared.dll, never named to the engine) arms the breakpoint of the
#          preload it claims; that when A's own file maps too, the copy's entry yields A's path (a bp-list naming
#          C); and that the unmap that moves the path back re-sends bp-list, so the host's rows - replayed here
#          through the host's own merge rules - hold ONE row after the reload, not a ghost and a live one.
#          (3) that a procedure named at symbol-pool offset 0 owns its locals (c4910921): in the two-procedure
#          d\shared.dll, OBJ is SHAREDPROC's and CNT2 is OTHERPROC's, in the TSWD and in `framelocals` at each
#          stop, with no phantom CNT2 under SHAREDPROC. (1) asks `framelocals` at the stopped VA too: before
#          the fix, the one-procedure DLLs keyed OBJ to sharedmod$$$__attach_process (measured 2026-10-03).
#   CANNOT - the page or add-in (rows are replayed, not rendered); an image that is not a byte copy; attach.
#
# -SelfTest (no Clarion, no debuggee): feeds the host-row replay and the (2) verdicts two recorded event
# streams, one with the unload re-sync and one without it, and shows the verdicts pass the first and FAIL the
# second (the ghost row). Measured 2026-10-03: the same live run against an engine built without the unload
# re-sync failed exactly those verdicts (two rows: owner c\shared.dll and owner a\shared.dll).
#
# Only one live debug session may run on the machine at a time.
#
#   pwsh tools/test-engine-samename-w8.ps1 [-SelfTest] [-Verbose2]
# Exit code 0 = all checks passed.

param(
  [string] $Engine     = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe'),
  [string] $Fixture    = (Join-Path $PSScriptRoot 'fixtures\samename-w8'),
  [string] $HostFixture = (Join-Path $PSScriptRoot 'fixtures\samename'),
  [string] $MSBuild    = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe',
  [string] $ClarionBin = 'C:\Clarion11\bin',
  # sharedmod.clw's `SharedTag = ...` line, after Obj is set. Breakable lines in both builds are 13-14, 16-20
  # (measured 2026-10-03), so this binds exactly in each.
  [int]    $BpLine     = 18,
  # d\sharedmod.clw (two procedures): SHAREDPROC's `SharedTag = 'D'`, after Obj is set, and OTHERPROC's
  # `SharedCount += Cnt2`, after Cnt2 = 5. Breakable lines are 14-15, 17-24, 26-27 (measured 2026-10-03).
  [int]    $BpLineD1   = 19,
  [int]    $BpLineD2   = 27,
  [int]    $StopTimeoutSec = 30,
  [switch] $SelfTest,
  [switch] $Verbose2
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'engine-session.ps1')
. (Join-Path $PSScriptRoot 'lib-engine-events.ps1')   # Read-Events, Wait-Event, Wait-Stop, Send, Ask, Show-Stop
. (Join-Path $PSScriptRoot 'lib-extract.ps1')   # dot-sources lib-check.ps1 too
$script:checks = 0
$script:failures = 0

$script:work = Join-Path ([IO.Path]::GetTempPath()) ('ClarionDbg-samename-w8-' + [Guid]::NewGuid().ToString('N'))
$script:tag  = Split-Path -Leaf $script:work
$BpSpec = "sharedmod.clw:$BpLine"

# --- helpers ------------------------------------------------------------------------------------------

function U32([string] $s) { if ($s -and $s.StartsWith('0x')) { return [Convert]::ToUInt32($s.Substring(2), 16) } return $null }

# Which fixture image a path is: 'a', 'b', 'c' or $null, matched on this run's own folder name.
function Get-ImageTag([string] $Path) {
  if (-not $Path) { return $null }
  $p = $Path.Replace('/', '\')
  foreach ($x in 'a', 'b', 'c') { if ($p -like "*\$($script:tag)\$x\shared.dll") { return $x } }
  return $null
}

# --- the host's breakpoint rows, through the REAL host merge code ---------------------------------------
#
# DebugBreakpoint and the five merge predicates (SameBpIdentity, BpLineMatches, BpOwnerMatches, BpDelMatches,
# LearnBpOwner) are EXTRACTED from ClarionDebuggerService.cs and compiled, not re-typed here, so a change to
# the host's merge changes this suite's verdicts. The three event arms that call them sit inside a switch that
# cannot be extracted on its own; HostRows below calls the predicates exactly as those arms do, and
# Get-HostArmPins position-pins the arms' own statements in the service, so an arm edited away from this
# shape turns the pins red rather than leaving the replay describing old code.
$ServicePath = Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs'
$svc = Get-Content -Raw -LiteralPath $ServicePath
$pub = { param($m) $m -replace '^(\s*)(private|internal) static', '$1public static' }
$hostRows = @"
using System;
using System.Collections.Generic;
namespace W8Rows {
$(Get-Method 'public sealed class DebugBreakpoint' $svc)
public static class HostRows {
  public static List<DebugBreakpoint> Rows = new List<DebugBreakpoint>();
  $(& $pub (Get-Method 'internal static bool SameBpIdentity(DebugBreakpoint a, DebugBreakpoint b)' $svc))
  $(& $pub (Get-Method 'internal static bool BpLineMatches(DebugBreakpoint b, int? requestedLine, int plantedLine)' $svc))
  $(& $pub (Get-Method 'internal static bool BpOwnerMatches(string a, string b)' $svc))
  $(& $pub (Get-Method 'internal static bool BpDelMatches(DebugBreakpoint b, string module, int? requestedLine, int plantedLine, string ownerPath)' $svc))
  $(& $pub (Get-Method 'private static void LearnBpOwner(DebugBreakpoint known, DebugBreakpoint echo)' $svc))
  public static DebugBreakpoint Bp(string module, int? requestedLine, int line, string ownerPath) {
    var b = new DebugBreakpoint(); b.Module = module; b.RequestedLineOrNull = requestedLine; b.Line = line; b.OwnerPath = ownerPath; return b;
  }
  // case "bp-set": the first row with the same identity takes the echo, else the echo is a new row.
  public static void Set(DebugBreakpoint bp) {
    DebugBreakpoint known = null;
    foreach (var b in Rows)
      if (SameBpIdentity(b, bp)) { known = b; break; }
    if (known == null) Rows.Add(bp);
    else { known.Line = bp.Line; LearnBpOwner(known, bp); }
  }
  // case "bp-del"
  public static void Del(string delMod, int? delRequested, int delLine, string delOwner) {
    Rows.RemoveAll(b => BpDelMatches(b, delMod, delRequested, delLine, delOwner));
  }
  // case "bp-list"
  public static void List(List<DebugBreakpoint> list) { Rows.Clear(); Rows.AddRange(list); }
}
}
"@
Add-Type -TypeDefinition $hostRows -Language CSharp | Out-Null
Set-StrictMode -Off   # lib-extract.ps1 turns it on; this suite reads optional event members freely
$PSDefaultParameterValues = Get-EngineEventDefaults -TimeoutSec $StopTimeoutSec -Verbose2 ([bool]$Verbose2)

# The service's own arm statements, as the HostRows arms call them. Text, but POSITION-pinned: each must start
# its line, so `if (false) ...` in front of one does not pass.
function Get-HostArmPins {
  return @(
    , @('host bp-set arm: the first SameBpIdentity row is the known one', ($svc -match '(?m)^\s*if \(SameBpIdentity\(b, bp\)\) \{ known = b; break; \}'))
    , @('host bp-set arm: no known row adds the echo', ($svc -match '(?m)^\s*if \(known == null\) _breakpoints\.Add\(bp\);'))
    , @('host bp-set arm: a known row takes the line and learns the owner', ($svc -match '(?m)^\s*known\.Line = bp\.Line;[^\r\n]*\r?\n\s*LearnBpOwner\(known, bp\);'))
    , @('host bp-del arm: every BpDelMatches row is removed', ($svc -match '(?m)^\s*_breakpoints\.RemoveAll\(b => BpDelMatches\(b, delMod, delRequested, delLine, delOwner\)\);'))
    , @('host bp-list arm: the list is replaced', ($svc -match '(?m)^\s*_breakpoints\.Clear\(\);\r?\n\s*_breakpoints\.AddRange\(list\);'))
  )
}

# PowerShell passes $null into a C# string parameter as "", which BpOwnerMatches reads as a KNOWN owner, so
# a pending row would stop being a wildcard. Every string that may be null crosses as [NullString]::Value.
function NStr($s) { if ($null -eq $s) { return [NullString]::Value } return [string]$s }

# The host's breakpoint rows after $Events (bp-set / bp-del / bp-list), through HostRows.
function Get-HostBpRows($Events) {
  [W8Rows.HostRows]::Rows.Clear()
  foreach ($e in @($Events)) {
    switch -CaseSensitive ($e.event) {
      'bp-set'  { [W8Rows.HostRows]::Set([W8Rows.HostRows]::Bp((NStr $e.module), $e.requestedLine, $e.line, (NStr $e.ownerPath))) }
      'bp-del'  { [W8Rows.HostRows]::Del((NStr $e.module), $e.requestedLine, $e.line, (NStr $e.ownerPath)) }
      'bp-list' {
        $l = [Collections.Generic.List[W8Rows.DebugBreakpoint]]::new()
        foreach ($b in @($e.bps)) { if ($b) { $l.Add([W8Rows.HostRows]::Bp((NStr $b.module), $b.requestedLine, $b.line, (NStr $b.ownerPath))) } }
        [W8Rows.HostRows]::List($l)
      }
    }
  }
  return , @([W8Rows.HostRows]::Rows)
}

# The (2) verdicts over one session's events, as [name, ok, detail] triples, so the live run and -SelfTest
# judge with the same code.
function Get-CopyVerdicts($Events) {
  $loads = @($Events | Where-Object { $_.event -ceq 'module-loaded' -and $_.name -eq 'shared.dll' })
  $lists = @($Events | Where-Object { $_.event -ceq 'bp-list' })
  $y = $lists | Select-Object -First 1
  $u = $lists | Select-Object -Skip 1 -First 1
  $mine = @((Get-HostBpRows $Events) | Where-Object { $_.module -eq 'sharedmod.clw' })
  return @(
    , @('(2) shared.dll mapped three times (C, A, C again)', ($loads.Count -eq 3), "$($loads.Count)")
    , @('(2) two bp-list re-syncs: the yield, and the unmap that moved the path back', ($lists.Count -eq 2), "$($lists.Count)")
    , @("(2) the yield's bp-list names c\shared.dll as the copy's owner",
        ($null -ne $y -and (@($y.bps) | Where-Object { (Get-ImageTag $_.ownerPath) -eq 'c' }).Count -ge 1), "$($y | ConvertTo-Json -Compress -Depth 4)")
    , @("(2) the unmap's bp-list leaves the one breakpoint pending (owner null)",
        ($null -ne $u -and @($u.bps).Count -eq 1 -and (@($u.bps) | Where-Object { $_.module -eq 'sharedmod.clw' -and $null -eq $_.ownerPath }).Count -eq 1),
        "$($u | ConvertTo-Json -Compress -Depth 4)")
    , @("(2) the host holds ONE row for $BpSpec after the reload, not a ghost and a live one",
        ($mine.Count -eq 1), (($mine | ForEach-Object { ShowVal $_.OwnerPath }) -join ' ; '))
  )
}

# --- live session plumbing (the rest is lib-engine-events.ps1) -----------------------------------------------

function New-Session([string] $Target, [string] $BreakArgs) {
  $s = New-EngineSession -Engine $Engine -Target $Target -BreakArgs $BreakArgs -WorkingDirectory $script:work
  $s.Events = [Collections.ArrayList]::new()
  $s.Seen = 0
  $s.Raw = [Collections.ArrayList]::new()
  return $s
}

function Close-Session($S) {
  Stop-EngineSession $S
  Start-Sleep -Milliseconds 300
  Read-Events $S
  Stop-EngineTarget $S
  Remove-EngineSession $S
}

function Names($Items) { return (@($Items | ForEach-Object { $_.name }) -join ',') }

# --- -SelfTest: the (2) verdicts on recorded streams ---------------------------------------------------

if ($SelfTest) {
  $pa = "C:\x\$($script:tag)\a\shared.dll"; $pc = "C:\x\$($script:tag)\c\shared.dll"
  $j = { param($s) $s | ConvertFrom-Json }
  $bp = { param($o) "{`"module`":`"sharedmod.clw`",`"requestedLine`":$BpLine,`"line`":$BpLine,`"ownerPath`":$(if ($o) { ConvertTo-Json $o } else { 'null' })}" }
  # As recorded from the live run 2026-10-03 (paths and bases normalised).
  $clean = @(
    (& $j ('{"event":"bp-set",' + (& $bp $pa).Substring(1)))
    (& $j "{`"event`":`"module-loaded`",`"name`":`"shared.dll`",`"path`":$(ConvertTo-Json $pa),`"base`":`"0x752E0000`",`"size`":`"0x8000`"}")
    (& $j "{`"event`":`"bp-list`",`"bps`":[$(& $bp $pc)]}")
    (& $j ('{"event":"bp-set",' + (& $bp $pa).Substring(1)))
    (& $j "{`"event`":`"module-loaded`",`"name`":`"shared.dll`",`"path`":$(ConvertTo-Json $pa),`"base`":`"0x752D0000`",`"size`":`"0x8000`"}")
    (& $j ('{"event":"bp-del",' + (& $bp $pa).Substring(1)))
    (& $j '{"event":"module-unloaded","name":"shared.dll","base":"0x752D0000"}')
    (& $j '{"event":"module-unloaded","name":"shared.dll","base":"0x752E0000"}')
    (& $j "{`"event`":`"bp-list`",`"bps`":[$(& $bp $null)]}")
    (& $j ('{"event":"bp-set",' + (& $bp $pa).Substring(1)))
    (& $j "{`"event`":`"module-loaded`",`"name`":`"shared.dll`",`"path`":$(ConvertTo-Json $pa),`"base`":`"0x752E0000`",`"size`":`"0x8000`"}")
  )
  # The same stream from an engine without the unmap re-sync: the second bp-list never comes.
  $dirty = @($clean | Where-Object { -not ($_.event -ceq 'bp-list' -and $null -eq @($_.bps)[0].ownerPath) })

  Invoke-CheckSection '-SelfTest: the (2) verdicts pass the recorded clean stream' {
    foreach ($v in (Get-CopyVerdicts $clean)) { Check ("clean: " + $v[0]) $v[1] $v[2] }
  }
  Invoke-CheckSection '-SelfTest: without the unmap re-sync, the ghost-row verdicts FAIL' {
    Check 'the dirty stream lacks exactly the one owner-null bp-list' ($dirty.Count -eq $clean.Count - 1) "$($dirty.Count) vs $($clean.Count)"
    $dv = @{}; foreach ($v in (Get-CopyVerdicts $dirty)) { $dv[$v[0]] = $v }
    foreach ($k in @($dv.Keys | Where-Object { $_ -like '*two bp-list*' -or $_ -like '*pending*' -or $_ -like '*ONE row*' })) {
      Check ("dirty fails: " + $k) (-not $dv[$k][1]) $dv[$k][2]
    }
    $rows = @((Get-HostBpRows $dirty) | Where-Object { $_.module -eq 'sharedmod.clw' })
    Check 'the dirty replay is the ghost: one row owned by c\shared.dll and one by a\shared.dll' `
      ($rows.Count -eq 2 -and (@($rows | ForEach-Object { Get-ImageTag $_.OwnerPath } | Sort-Object) -join ',') -eq 'a,c') (($rows | ForEach-Object { ShowVal $_.OwnerPath }) -join ' ; ')
  }
  Invoke-CheckSection '-SelfTest: the replay''s arms are the service''s own statements' {
    foreach ($p in (Get-HostArmPins)) { Check $p[0] $p[1] '' }
  }
  Invoke-CheckSection '-SelfTest: the host-row replay follows the host rules' {
    $r = Get-HostBpRows @((& $j "{`"event`":`"bp-list`",`"bps`":[$(& $bp $null)]}"), (& $j ('{"event":"bp-set",' + (& $bp $pa).Substring(1))))
    Check 'a pending row learns the owner a bp-set names' ($r.Count -eq 1 -and $r[0].OwnerPath -eq $pa) (($r | ForEach-Object { ShowVal $_.OwnerPath }) -join ' ; ')
    $r = Get-HostBpRows @((& $j ('{"event":"bp-set",' + (& $bp $pc).Substring(1))), (& $j ('{"event":"bp-set",' + (& $bp $pa).Substring(1))))
    Check 'a row with a known owner does not absorb another owner (two rows)' ($r.Count -eq 2) "$($r.Count)"
    $r = Get-HostBpRows @((& $j ('{"event":"bp-set",' + (& $bp $pc).Substring(1))), (& $j ('{"event":"bp-del",' + (& $bp $pc).Substring(1))))
    Check 'bp-del with the owner removes the row' ($r.Count -eq 0) "$($r.Count)"
  }
  $EXPECTED_SELFTEST = 18
  Assert-CheckTotal $EXPECTED_SELFTEST
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# --- live ----------------------------------------------------------------------------------------------

$Engine = (Resolve-Path -LiteralPath $Engine).Path
$dllA = Join-Path $script:work 'a\shared.dll'
$dllB = Join-Path $script:work 'b\shared.dll'
$dllC = Join-Path $script:work 'c\shared.dll'
$dllD = Join-Path $script:work 'd\shared.dll'
$two  = Join-Path $script:work 'two'

try {
  Invoke-CheckSection 'the fixture builds with Clarion 11' {
    Check 'MSBuild is present' (Test-Path -LiteralPath $MSBuild) $MSBuild
    Check 'the Clarion build targets are present' (Test-Path -LiteralPath (Join-Path $ClarionBin 'SoftVelocity.Build.Clarion.targets')) $ClarionBin
    $copy = @(@($Fixture, '', '*'), @($Fixture, 'a', '*'), @($Fixture, 'b', '*'), @($Fixture, 'd', '*'), @($HostFixture, '', 'samehost.*'))
    foreach ($c in $copy) {
      $to = Join-Path $script:work $c[1]
      New-Item -ItemType Directory -Force -Path $to | Out-Null
      foreach ($f in Get-ChildItem -LiteralPath (Join-Path $c[0] $c[1]) -File -Filter $c[2] | Where-Object { $_.Extension -in '.clw', '.cwproj', '.exp' }) {
        # CRLF whatever the checkout did: the Clarion compiler rejects LF.
        $text = [IO.File]::ReadAllText($f.FullName) -replace "`r?`n", "`r`n"
        [IO.File]::WriteAllText((Join-Path $to $f.Name), $text, [Text.Encoding]::ASCII)
      }
    }
    $log = ''
    foreach ($p in 'a\shared.cwproj', 'b\shared.cwproj', 'd\shared.cwproj', 'samehost.cwproj', 'cpyhost.cwproj') {
      Push-Location (Split-Path (Join-Path $script:work $p))
      try { $log += & $MSBuild (Split-Path -Leaf $p) -nologo -v:m "/p:ClarionBinPath=$ClarionBin" 2>&1 | Out-String }
      finally { Pop-Location }
    }
    if (Test-Path -LiteralPath $dllA) {
      New-Item -ItemType Directory -Force -Path (Split-Path $dllC) | Out-Null
      Copy-Item -LiteralPath $dllA -Destination $dllC
    }
    # (3)'s run folder: samehost.exe and its runtime beside two\a\shared.dll (the two-procedure D build) and
    # two\b\shared.dll (B), since samehost loads a\ and b\ beside itself.
    if ((Test-Path -LiteralPath $dllD) -and (Test-Path -LiteralPath $dllB)) {
      foreach ($x in 'a', 'b') { New-Item -ItemType Directory -Force -Path (Join-Path $two $x) | Out-Null }
      Get-ChildItem -LiteralPath $script:work -File | Where-Object { $_.Name -eq 'samehost.exe' -or $_.Extension -eq '.dll' } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $two }
      Copy-Item -LiteralPath $dllD -Destination (Join-Path $two 'a\shared.dll')
      Copy-Item -LiteralPath $dllB -Destination (Join-Path $two 'b\shared.dll')
    }
    $built = (Test-Path -LiteralPath (Join-Path $script:work 'samehost.exe')) -and (Test-Path -LiteralPath (Join-Path $script:work 'cpyhost.exe')) `
             -and (Test-Path -LiteralPath $dllA) -and (Test-Path -LiteralPath $dllB) -and (Test-Path -LiteralPath $dllC) `
             -and (Test-Path -LiteralPath (Join-Path $two 'samehost.exe')) -and (Test-Path -LiteralPath (Join-Path $two 'a\shared.dll'))
    Check 'samehost.exe, cpyhost.exe, a\, b\, c\ and d\shared.dll, and the two\ run folder are in place' $built $(if ($built) { '' } else { $log.Trim() })
    if (-not $built) { return }
    $ha = (Get-FileHash -LiteralPath $dllA).Hash; $hb = (Get-FileHash -LiteralPath $dllB).Hash; $hc = (Get-FileHash -LiteralPath $dllC).Hash
    Check 'a\ and b\shared.dll are different builds' ($ha -ne $hb) "a=$ha b=$hb"
    Check 'c\shared.dll is a byte copy of a\shared.dll' ($ha -eq $hc) "a=$ha c=$hc"
    foreach ($x in @(@('a', $dllA), @('b', $dllB))) {
      $lines = & $Engine lines $x[1] --module sharedmod.clw 2>&1 | Out-String
      $ok = $false
      if ($lines -match 'breakable lines:\s*(.+)') {
        foreach ($part in $matches[1].Trim().Split(',')) {
          $lh = $part.Trim().Split('-')
          if ([int]$lh[0] -le $BpLine -and $BpLine -le [int]$lh[-1]) { $ok = $true }
        }
      }
      Check "$($x[0])\shared.dll carries sharedmod.clw with line $BpLine breakable" $ok $lines.Trim()
    }
    $lines = & $Engine lines $dllD --module sharedmod.clw 2>&1 | Out-String
    $ok = 0
    if ($lines -match 'breakable lines:\s*(.+)') {
      foreach ($part in $matches[1].Trim().Split(',')) {
        $lh = $part.Trim().Split('-')
        foreach ($want in $BpLineD1, $BpLineD2) { if ([int]$lh[0] -le $want -and $want -le [int]$lh[-1]) { $ok++ } }
      }
    }
    Check "d\shared.dll carries sharedmod.clw with lines $BpLineD1 and $BpLineD2 breakable" ($ok -eq 2) $lines.Trim()
  }

  Invoke-CheckSection "(1) expand resolves in the image the row's imgBase names" {
    $s = New-Session (Join-Path $script:work 'samehost.exe') "--solution-dll `"$dllB`" --solution-dll `"$dllA`" --bp $BpSpec"
    $req = 100
    try {
      for ($i = 0; $i -lt 2; $i++) {
        $stop = Wait-Stop $s
        $mods = @($s.Events | Where-Object { $_.event -ceq 'module-loaded' -and $_.name -eq 'shared.dll' })
        $va = if ($stop -and $stop.event -ceq 'paused') { U32 $stop.va } else { 0 }
        $here = $mods | Where-Object { $va -ge (U32 $_.base) -and $va -lt ((U32 $_.base) + (U32 $_.size)) } | Select-Object -First 1
        $other = $mods | Where-Object { $_ -ne $here } | Select-Object -First 1
        $t = Get-ImageTag $here.path
        $want = if ($t -eq 'a') { 'VA' } else { 'VB' }
        $notWant = if ($t -eq 'a') { 'VB' } else { 'VA' }
        Check "(1) stop $($i + 1) is $BpSpec in a shared.dll" ($null -ne $here -and $stop.line -eq $BpLine -and $t -in 'a', 'b') (Show-Stop $stop)
        if ($null -eq $here) { break }

        $req++
        $fl = Ask $s "framelocals $req $($stop.va) $($stop.regs.ebp)" 'framelocals' "$req"
        $obj = @($fl.items | Where-Object { $_.name -ieq 'OBJ' }) | Select-Object -First 1
        Check "(1) [$t] the Obj row is a ref row carrying its image's base $($here.base) as 0x + 8 hex digits" `
          ($null -ne $obj -and $obj.ref -eq $true -and $obj.imgBase -cmatch '^0x[0-9A-F]{8}$' -and (U32 $obj.imgBase) -eq (U32 $here.base)) "$($obj | ConvertTo-Json -Compress)"

        $req++
        $x = Ask $s "expand $req $($obj.module) $($obj.typeRef) $($obj.addr) $($obj.imgBase)" 'expanded' "$req"
        $n = Names $x.items
        Check "(1) [$t] expand with its own imgBase reads $t's members ($want)" ((($n -split ',') -contains $want) -and -not (($n -split ',') -contains $notWant)) "members: $n"
        $req++
        $x = Ask $s "expand $req $($obj.module) $($obj.typeRef) $($obj.addr) 0x7FFE0000" 'expanded' "$req"
        Check "(1) [$t] a base no shared.dll has gets no children (fails closed)" ($null -ne $x -and @($x.items).Count -eq 0) "items: $(Names $x.items)"
        $req++
        $x = Ask $s "expand $req $($obj.module) $($obj.typeRef) $($obj.addr) 12345678" 'expanded' "$req"
        Check "(1) [$t] a malformed base gets no children" ($null -ne $x -and @($x.items).Count -eq 0) "items: $(Names $x.items)"
        $req++
        $x = Ask $s "expand $req $($obj.module) $($obj.typeRef) $($obj.addr)" 'expanded' "$req"
        $req++
        $b = $mods | Where-Object { (Get-ImageTag $_.path) -eq 'b' } | Select-Object -First 1
        $y = Ask $s "expand $req $($obj.module) $($obj.typeRef) $($obj.addr) $($b.base)" 'expanded' "$req"
        # B is named first, so it is the first shared.dll in the module table: today's first-match.
        Check "(1) [$t] no base keeps today's first-match (b\shared.dll, the first preloaded)" ((Names $x.items) -eq (Names $y.items) -and (Names $x.items) -ne '') "no base: $(Names $x.items) ; b's base: $(Names $y.items)"
        Send $s 'continue'
      }
      $end = Wait-Stop $s
      Check '(1) samehost exits 0 with no third stop' ($null -ne $end -and $end.event -ceq 'exited' -and $end.code -eq 0) (Show-Stop $end)
    }
    finally { Close-Session $s }
  }

  Invoke-CheckSection '(2) a same-build copy arms, yields its borrowed path, and the unmap re-sync leaves one row' {
    $s = New-Session (Join-Path $script:work 'cpyhost.exe') "--solution-dll `"$dllA`" --bp $BpSpec"
    $stop = $null; $end = $null
    try {
      $stop = Wait-Stop $s
      $events = @($s.Events)
      if ($stop -and $stop.event -ceq 'paused') { Send $s 'continue'; $end = Wait-Stop $s }
    }
    finally { Close-Session $s }
    foreach ($p in (Get-HostArmPins)) { Check ("(2) " + $p[0]) $p[1] '' }
    foreach ($v in (Get-CopyVerdicts $events)) { Check $v[0] $v[1] $v[2] }
    $last = @($events | Where-Object { $_.event -ceq 'module-loaded' -and $_.name -eq 'shared.dll' }) | Select-Object -Last 1
    $va = if ($stop -and $stop.va) { U32 $stop.va } else { 0 }
    Check "(2) the copy armed: the call in C stops at $BpSpec inside the reloaded image" `
      ($null -ne $last -and $stop.event -ceq 'paused' -and $stop.line -eq $BpLine -and $va -ge (U32 $last.base) -and $va -lt ((U32 $last.base) + (U32 $last.size))) (Show-Stop $stop)
    Check '(2) cpyhost exits 0 (every load, free and the call worked)' ($null -ne $end -and $end.event -ceq 'exited' -and $end.code -eq 0) (Show-Stop $end)
  }

  Invoke-CheckSection '(3) two procedures: the one named at pool offset 0 owns its locals (c4910921)' {
    # The TSWD, read by the engine's own `locals` verb: procedure -> its local names.
    $lo = & $Engine locals $dllD 2>&1 | Out-String
    $owned = @{}; $cur = $null
    foreach ($ln in ($lo -split "`r?`n")) {
      if ($ln -match '^\s{2}(\S+)\s+\(entry 0x[0-9A-Fa-f]+\)') { $cur = $matches[1]; $owned[$cur] = @() }
      elseif ($cur -and $ln -match '^\s+\[ebp[-+][0-9A-Fa-fx]+\]\s+(\S+)') { $owned[$cur] += $matches[1] }
    }
    Check '(3) d\shared.dll: SHAREDPROC owns OBJ and nothing else (no phantom CNT2)' ((@($owned['SHAREDPROC']) -join ',') -eq 'OBJ') $lo.Trim()
    Check '(3) d\shared.dll: OTHERPROC owns CNT2 and nothing else' ((@($owned['OTHERPROC']) -join ',') -eq 'CNT2') ''

    $pathD = Join-Path $two 'a\shared.dll'
    $s = New-Session (Join-Path $two 'samehost.exe') "--solution-dll `"$pathD`" --bp sharedmod.clw:$BpLineD1 --bp sharedmod.clw:$BpLineD2"
    $req = 300; $atShared = $null; $atOther = $null; $end = $null
    try {
      for ($i = 0; $i -lt 6; $i++) {
        $stop = Wait-Stop $s
        if ($null -eq $stop -or $stop.event -cne 'paused') { $end = $stop; break }
        $va = U32 $stop.va
        $inD = @($s.Events | Where-Object { $_.event -ceq 'module-loaded' -and $_.path -eq $pathD -and
                                           $va -ge (U32 $_.base) -and $va -lt ((U32 $_.base) + (U32 $_.size)) }).Count -gt 0
        if ($inD -and $stop.line -in $BpLineD1, $BpLineD2) {
          $req++
          $fl = Ask $s "framelocals $req $($stop.va) $($stop.regs.ebp)" 'framelocals' "$req"
          $r = [pscustomobject]@{ Stop = $stop; Names = (@($fl.items | ForEach-Object { $_.name }) -join ','); Items = @($fl.items) }
          if ($stop.line -eq $BpLineD1) { $atShared = $r }
          else {
            $atOther = $r
            $req++
            $r | Add-Member -NotePropertyName Watch -NotePropertyValue (Ask $s "watch OBJ reqid=$req" 'watch' "$req")
            $req++
            $r | Add-Member -NotePropertyName Stack -NotePropertyValue (Ask $s "stack reqid=$req" 'stack' "$req")
          }
        }
        Send $s 'continue'
      }
      if ($null -eq $end) { $end = Wait-Stop $s }
    }
    finally { Close-Session $s }
    Check "(3) framelocals at the SHAREDPROC stop (line $BpLineD1, in d) lists OBJ and no CNT2" `
      ($null -ne $atShared -and $atShared.Names -eq 'OBJ') "$(if ($atShared) { "$(Show-Stop $atShared.Stop): [$($atShared.Names)]" } else { '(no stop in d)' })"
    $cnt = if ($atOther) { @($atOther.Items | Where-Object { $_.name -eq 'CNT2' }) | Select-Object -First 1 }
    Check "(3) framelocals at the OTHERPROC stop (line $BpLineD2, in d) lists CNT2 = 5 and nothing else" `
      ($null -ne $atOther -and $atOther.Names -eq 'CNT2' -and "$($cnt.value)" -eq '5') "$(if ($atOther) { "$(Show-Stop $atOther.Stop): [$($atOther.Names)] CNT2=$($cnt.value)" } else { '(no stop in d)' })"
    if ($atOther) {
      Write-Host "  watch OBJ at the OTHERPROC stop: $($atOther.Watch | ConvertTo-Json -Compress -Depth 4)"
      Write-Host "  stack there: $($atOther.Stack | ConvertTo-Json -Compress -Depth 5)"
    }
    Check '(3) samehost exits 0 (both CALLs worked)' ($null -ne $end -and $end.event -ceq 'exited' -and $end.code -eq 0) (Show-Stop $end)
  }
}
finally {
  if (Test-Path -LiteralPath $script:work) { Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue }
}

# The backstop for a section that returns early without throwing (lib-check.ps1, guard (b)). Update the
# number deliberately when adding or removing a check.
$EXPECTED_CHECKS = 38
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
Write-Host 'NOT PROVED HERE: the page or add-in rendering of the rows, a copy that is not byte-identical, attach.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
