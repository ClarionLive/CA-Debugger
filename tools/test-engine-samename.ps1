# Two DLLs with the SAME file name, live (ticket 1be3b82e item 2): builds the hand-coded fixture
# tools\fixtures\samename with Clarion 11 - a\shared.dll and b\shared.dll, each compiled from a file named
# sharedmod.clw, plus samehost.exe, which loads both by full path and calls SHAREDPROC in A and then in B -
# and drives the engine over it in two interactive sessions.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE:
#   CAN  - (a) that each shared.dll gets its OWN module entry: two module-loaded events, two paths, two bases,
#          with both DLLs also named as solution DLLs so the preload path is the one exercised;
#          (b) that an UNQUALIFIED startup bp on sharedmod.clw:LINE arms in both preloaded images and stops in
#          BOTH at run time (each paused va falls inside that image's [base, base+size));
#          (c) that a transient `bp add sharedmod.clw:LINE` (no |one=1) stops in whichever image runs it
#          first, and that `bp del sharedmod.clw:LINE` then leaves no copy: every armed copy is echoed
#          bp-del, bp list carries none, and the next continue runs to exit. (b) is (c)'s known-dirty
#          control: it shows B's copy WOULD stop if it were still armed.
#   CANNOT - a same-named DLL loaded through an IMPORT TABLE (the loader matches imports by base name, so one
#          process cannot import two), an image the host never named (the same-build fallback in
#          ClaimUnmapped), attach, or anything the pad/add-in does with the echoes. It also cannot tell a
#          wrong module ENTRY from a right one except through where the stops land.
#
# Needs Clarion 11 (MSBuild + SoftVelocity.Build.Clarion.targets) and a live debuggee, so run-all lists it as
# live. Only one live debug session may run on the machine at a time.
#
#   pwsh tools/test-engine-samename.ps1 [-Verbose2]
# Exit code 0 = all checks passed.

param(
  [string] $Engine     = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe'),
  [string] $Fixture    = (Join-Path $PSScriptRoot 'fixtures\samename'),
  [string] $MSBuild    = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe',
  [string] $ClarionBin = 'C:\Clarion11\bin',
  # sharedmod.clw's `SharedCount += <n>` line, the first after the tag assignment. Breakable lines in both
  # builds are 16,18-20 (measured 2026-09-25), so this line binds exactly in each, with no snapping.
  [int]    $BpLine     = 19,
  [int]    $StopTimeoutSec = 30,
  [switch] $Verbose2
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'engine-session.ps1')
. (Join-Path $PSScriptRoot 'lib-check.ps1')
$script:checks = 0
$script:failures = 0

$script:work = Join-Path ([IO.Path]::GetTempPath()) ('ClarionDbg-samename-' + [Guid]::NewGuid().ToString('N'))
$script:tag  = Split-Path -Leaf $script:work
$script:exe  = Join-Path $script:work 'samehost.exe'
$script:dllA = Join-Path $script:work 'a\shared.dll'
$script:dllB = Join-Path $script:work 'b\shared.dll'
$BpSpec = "sharedmod.clw:$BpLine"
$Engine = (Resolve-Path -LiteralPath $Engine).Path

# --- helpers ------------------------------------------------------------------------------------------

function Hex([string] $s) { if ($s -and $s.StartsWith('0x')) { return [Convert]::ToUInt32($s.Substring(2), 16) } return $null }

# Which fixture image a path is: 'a', 'b' or $null. Matched on the run's own temp folder name, so the 8.3
# spelling GetTempPath returns and the long spelling the engine canonicalizes to both match.
function Get-ImageTag([string] $Path) {
  if (-not $Path) { return $null }
  $p = $Path.Replace('/', '\')
  if ($p -like "*\$($script:tag)\a\shared.dll") { return 'a' }
  if ($p -like "*\$($script:tag)\b\shared.dll") { return 'b' }
  return $null
}

# The image ('a'/'b') whose [base, base+size) holds $Va, from the session's shared.dll module-loaded events.
function Get-ImageOfVa($Mods, [string] $Va) {
  $v = Hex $Va
  if ($null -eq $v) { return $null }
  foreach ($m in $Mods) {
    $b = Hex $m.base; $n = Hex $m.size
    if ($null -ne $b -and $null -ne $n -and $v -ge $b -and $v -lt ($b + $n)) { return (Get-ImageTag $m.path) }
  }
  return $null
}

# The bp-list entries for sharedmod.clw: the "no copy left" predicate.
function Get-SharedBps($BpList) {
  if ($null -eq $BpList) { return @() }
  return @(@($BpList.bps) | Where-Object { $_ -and $_.module -eq 'sharedmod.clw' })
}

function New-Session([string] $BreakArgs) {
  $s = New-EngineSession -Engine $Engine -Target $script:exe -BreakArgs $BreakArgs -WorkingDirectory $script:work -CaptureStdErr
  $s.Events = [Collections.ArrayList]::new()
  $s.Seen = 0
  $s.Raw = [Collections.ArrayList]::new()
  return $s
}

function Read-Events($S) {
  foreach ($l in (Read-EngineLines $S)) {
    if ($null -eq $l) { continue }
    [void]$S.Raw.Add($l)
    if ($Verbose2) { Write-Host "    | $l" }
    if ($l.StartsWith('@JSON ')) {
      $o = $null
      try { $o = $l.Substring(6) | ConvertFrom-Json } catch { }
      if ($null -ne $o) { [void]$S.Events.Add($o) }
    }
  }
}

# The next event (from the session's cursor) that $Pred accepts, or $null on timeout / engine exit. Events
# skipped on the way stay in $S.Events for the whole-session checks.
function Wait-Event($S, [scriptblock] $Pred, [int] $TimeoutSec = $StopTimeoutSec) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    Read-Events $S
    while ($S.Seen -lt $S.Events.Count) {
      $e = $S.Events[$S.Seen]; $S.Seen++
      if (& $Pred $e) { return $e }
    }
    if ($S.Proc.HasExited) {
      Start-Sleep -Milliseconds 200; Read-Events $S
      if ($S.Seen -ge $S.Events.Count) { return $null }
      continue
    }
    Start-Sleep -Milliseconds 100
  }
  return $null
}

function Wait-Stop($S) { return (Wait-Event $S { param($e) $e.event -ceq 'paused' -or $e.event -ceq 'exited' }) }

function Send($S, [string] $Cmd) {
  if ($Verbose2) { Write-Host "    > $Cmd" }
  $S.Proc.StandardInput.WriteLine($Cmd)
}

function Close-Session($S) {
  Stop-EngineSession $S
  Start-Sleep -Milliseconds 300
  Read-Events $S
  Stop-EngineTarget $S
  Remove-EngineSession $S
}

function Show-Stop($e) {
  if ($null -eq $e) { return '(no stop)' }
  if ($e.event -ceq 'exited') { return "exited code $($e.code)" }
  return "paused $($e.reason) $($e.module):$($e.line) va $($e.va)"
}

function Get-SharedMods($S) { return @($S.Events | Where-Object { $_.event -ceq 'module-loaded' -and $_.name -eq 'shared.dll' }) }

# B FIRST, and that order is the test. The EXE loads A first. With the module table keyed on the file name,
# only the first-named DLL was preloaded, and A, loading first, claimed THAT entry: named B, A took B's path,
# PE and TSWD. Naming A first would let the old engine pass, since A would claim its own entry by luck.
$solutionArgs = "--solution-dll `"$($script:dllB)`" --solution-dll `"$($script:dllA)`""

try {
  Invoke-CheckSection 'the fixture builds with Clarion 11' {
    Check 'MSBuild is present' (Test-Path -LiteralPath $MSBuild) $MSBuild
    Check 'the Clarion build targets are present' (Test-Path -LiteralPath (Join-Path $ClarionBin 'SoftVelocity.Build.Clarion.targets')) $ClarionBin
    foreach ($d in '', 'a', 'b') {
      $to = Join-Path $script:work $d
      New-Item -ItemType Directory -Force -Path $to | Out-Null
      foreach ($f in Get-ChildItem -LiteralPath (Join-Path $Fixture $d) -File | Where-Object { $_.Extension -in '.clw', '.cwproj', '.exp' }) {
        # CRLF whatever the checkout did: the Clarion compiler rejects LF.
        $text = [IO.File]::ReadAllText($f.FullName) -replace "`r?`n", "`r`n"
        [IO.File]::WriteAllText((Join-Path $to $f.Name), $text, [Text.Encoding]::ASCII)
      }
    }
    $log = ''
    foreach ($p in 'a\shared.cwproj', 'b\shared.cwproj', 'samehost.cwproj') {
      Push-Location (Split-Path (Join-Path $script:work $p))
      try { $log += & $MSBuild (Split-Path -Leaf $p) -nologo -v:m "/p:ClarionBinPath=$ClarionBin" 2>&1 | Out-String }
      finally { Pop-Location }
    }
    $built = (Test-Path -LiteralPath $script:exe) -and (Test-Path -LiteralPath $script:dllA) -and (Test-Path -LiteralPath $script:dllB)
    Check 'samehost.exe, a\shared.dll and b\shared.dll were built' $built $(if ($built) { '' } else { $log.Trim() })
    # The build copies ClaRUN.dll beside the EXE (measured 2026-09-25), so the debuggee does not pick up
    # whichever Clarion's runtime is first on PATH.
    Check 'the Clarion 11 runtime sits beside the EXE' (Test-Path -LiteralPath (Join-Path $script:work 'ClaRUN.dll')) $script:work
    $ha = if (Test-Path -LiteralPath $script:dllA) { (Get-FileHash -LiteralPath $script:dllA).Hash } else { 'a-missing' }
    $hb = if (Test-Path -LiteralPath $script:dllB) { (Get-FileHash -LiteralPath $script:dllB).Hash } else { 'b-missing' }
    Check 'the two shared.dll files are different builds' ($ha -ne $hb) "a=$ha b=$hb"
    foreach ($x in @(@('a', $script:dllA), @('b', $script:dllB))) {
      $lines = & $Engine lines $x[1] --module sharedmod.clw 2>&1 | Out-String
      $ok = $false
      if ($lines -match 'breakable lines:\s*(\S+)') {
        foreach ($part in $Matches[1].Split(',')) {
          $r = $part.Split('-'); $lo = [int]$r[0]; $hi = [int]$r[-1]
          if ($BpLine -ge $lo -and $BpLine -le $hi) { $ok = $true }
        }
      }
      Check "$($x[0])\shared.dll carries sharedmod.clw with line $BpLine breakable" $ok $lines.Trim()
    }
  }

  Invoke-CheckSection 'the verdict helpers can fail (known-dirty inputs)' {
    $mods = @([pscustomobject]@{ path = "C:\x\$($script:tag)\a\shared.dll"; base = '0x10000000'; size = '0x1000' },
              [pscustomobject]@{ path = "C:\x\$($script:tag)\b\shared.dll"; base = '0x10010000'; size = '0x1000' })
    Check 'a va past the end of A is in neither image' ($null -eq (Get-ImageOfVa $mods '0x10001000')) ''
    Check 'a va inside B is B, not A' ((Get-ImageOfVa $mods '0x10010010') -eq 'b') ''
    Check 'another run''s shared.dll is not this run''s' ($null -eq (Get-ImageTag 'C:\x\ClarionDbg-samename-other\a\shared.dll')) ''
    $dirty = [pscustomobject]@{ bps = @([pscustomobject]@{ module = 'sharedmod.clw'; line = $BpLine; ownerPath = 'C:\x\b\shared.dll' }) }
    Check 'a bp-list still holding a sharedmod.clw copy is flagged' ((Get-SharedBps $dirty).Count -eq 1) ''
  }

  Invoke-CheckSection "(a)+(b) a startup bp on $BpSpec, both DLLs preloaded as solution DLLs" {
    $s = New-Session "$solutionArgs --bp $BpSpec"
    $stops = @()
    try {
      for ($i = 0; $i -lt 3; $i++) {
        $e = Wait-Stop $s
        $stops += , $e
        if ($null -eq $e -or $e.event -ceq 'exited') { break }
        Send $s 'continue'
      }
    }
    finally { Close-Session $s }

    $mods = Get-SharedMods $s
    Write-Host ('  module-loaded shared.dll: ' + (($mods | ForEach-Object { "$($_.path) @ $($_.base)+$($_.size)" }) -join ' | '))
    Write-Host ('  stops: ' + (($stops | ForEach-Object { Show-Stop $_ }) -join ' ; '))
    $tags = @($mods | ForEach-Object { Get-ImageTag $_.path })
    Check '(a) two module-loaded events for shared.dll' ($mods.Count -eq 2) "$($mods.Count)"
    Check '(a) one from a\shared.dll and one from b\shared.dll' (($tags -contains 'a') -and ($tags -contains 'b')) ($mods.path -join ' | ')
    # Not a formality: with CALL alone the EXE unloaded A before loading B, B mapped at A's old base, and a
    # stop in B was indistinguishable from one in A - this check and the second-stop check both failed on
    # that build (measured 2026-09-25). samehost.clw now holds both loaded.
    Check '(a) at two different bases' (($mods.Count -eq 2) -and ($mods[0].base -ne $mods[1].base)) ($mods.base -join ' ')
    Check '(a) both with debug info' (($mods.Count -eq 2) -and @($mods | Where-Object { $_.hasDebug -eq $true }).Count -eq 2) ''

    $sets = @($s.Events | Where-Object { $_.event -ceq 'bp-set' -and $_.module -eq 'sharedmod.clw' })
    $setTags = @($sets | ForEach-Object { Get-ImageTag $_.ownerPath })
    Check '(b) the unqualified startup bp armed a copy in each preloaded image' (($setTags -contains 'a') -and ($setTags -contains 'b')) (($sets | ForEach-Object { "$($_.ownerPath):$($_.line)" }) -join ' | ')

    $s1 = if ($stops.Count -ge 1) { $stops[0] } else { $null }
    $s2 = if ($stops.Count -ge 2) { $stops[1] } else { $null }
    $s3 = if ($stops.Count -ge 3) { $stops[2] } else { $null }
    $in1 = if ($s1 -and $s1.event -ceq 'paused') { Get-ImageOfVa $mods $s1.va } else { $null }
    $in2 = if ($s2 -and $s2.event -ceq 'paused') { Get-ImageOfVa $mods $s2.va } else { $null }
    Check "(b) the first stop is $BpSpec inside A's image" (($in1 -eq 'a') -and $s1.module -eq 'sharedmod.clw' -and $s1.line -eq $BpLine) "$(Show-Stop $s1) in $(ShowVal $in1)"
    Check "(b) the second stop is $BpSpec inside B's image" (($in2 -eq 'b') -and $s2.module -eq 'sharedmod.clw' -and $s2.line -eq $BpLine) "$(Show-Stop $s2) in $(ShowVal $in2)"
    Check '(b) then the debuggee exits 0 (both CALLs worked), with no third stop' (($null -ne $s3) -and $s3.event -ceq 'exited' -and $s3.code -eq 0) (Show-Stop $s3)
  }

  Invoke-CheckSection "(c) a transient bp add $BpSpec, one stop, then bp del leaves no copy" {
    $s = New-Session "$solutionArgs --entry"
    $entry = $null; $hit = $null; $after = $null; $list = $null
    $addFrom = 0; $delFrom = 0; $delTo = 0
    try {
      $entry = Wait-Stop $s
      if ($entry -and $entry.event -ceq 'paused') {
        $addFrom = $s.Seen
        Send $s "bp add $BpSpec"
        Send $s 'continue'
        $hit = Wait-Stop $s
        if ($hit -and $hit.event -ceq 'paused') {
          $delFrom = $s.Seen
          Send $s "bp del $BpSpec"
          Send $s 'bp list'
          $list = Wait-Event $s { param($e) $e.event -ceq 'bp-list' }
          $delTo = $s.Seen
          Send $s 'continue'
          $after = Wait-Stop $s
        }
      }
    }
    finally { Close-Session $s }

    $mods = Get-SharedMods $s
    $slice = { param($a, $b) if ($b -le $a) { @() } else { @($s.Events[$a..($b - 1)]) } }
    $sets = @(& $slice $addFrom $delFrom | Where-Object { $_.event -ceq 'bp-set' -and $_.module -eq 'sharedmod.clw' })
    $dels = @(& $slice $delFrom $delTo | Where-Object { $_.event -ceq 'bp-del' -and $_.module -eq 'sharedmod.clw' })
    $setOwners = @($sets | ForEach-Object { ShowVal $_.ownerPath } | Sort-Object -Unique)
    $delOwners = @($dels | ForEach-Object { ShowVal $_.ownerPath } | Sort-Object -Unique)
    Write-Host "  stops: $(Show-Stop $entry) ; $(Show-Stop $hit) ; $(Show-Stop $after)"
    Write-Host "  bp-set owners: $($setOwners -join ' | ')"
    Write-Host "  bp-del owners: $($delOwners -join ' | ')"

    Check '(c) the session paused at the PE entry first' (($null -ne $entry) -and $entry.event -ceq 'paused' -and $entry.module -ne 'sharedmod.clw') (Show-Stop $entry)
    Check "(c) bp add $BpSpec was echoed bp-set" ($sets.Count -ge 1) "$($sets.Count) bp-set: $($setOwners -join ' | ')"
    $inHit = if ($hit -and $hit.event -ceq 'paused') { Get-ImageOfVa $mods $hit.va } else { $null }
    Check "(c) continue stopped at $BpSpec in one of the two images" (($inHit -in 'a', 'b') -and $hit.module -eq 'sharedmod.clw' -and $hit.line -eq $BpLine) "$(Show-Stop $hit) in $(ShowVal $inHit)"
    Check '(c) bp del echoed bp-del for every copy bp add armed' (($dels.Count -ge 1) -and (($setOwners -join '|') -eq ($delOwners -join '|'))) "set: $($setOwners -join ' | ') ; del: $($delOwners -join ' | ')"
    $left = Get-SharedBps $list
    Check '(c) bp list afterwards holds no sharedmod.clw copy' (($null -ne $list) -and $left.Count -eq 0) $(if ($null -eq $list) { 'no bp-list reply' } else { ($left | ForEach-Object { "$($_.ownerPath):$($_.line)" }) -join ' | ' })
    Check '(c) the next continue runs to exit 0 with no further stop' (($null -ne $after) -and $after.event -ceq 'exited' -and $after.code -eq 0) (Show-Stop $after)
  }
}
finally {
  if (Test-Path -LiteralPath $script:work) { Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue }
}

# The backstop for a section that returns early without throwing (lib-check.ps1, guard (b)). Update the
# number deliberately when adding or removing a check.
$EXPECTED_CHECKS = 25
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
Write-Host 'NOT PROVED HERE: import-table loading, an image the host never named, attach. See the header.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
