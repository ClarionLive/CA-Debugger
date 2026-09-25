# Live regression rig for ca29e2da: a breakpoint two threads run through must be hit EVERY time.
#
# The engine re-arms a breakpoint by putting the original byte back, single-stepping the thread that hit it,
# and planting the INT3 again at that thread's trap. Before the fix every OTHER thread ran during that step,
# and one that reached the address in that window went straight past the breakpoint. The fixture
# (tools\fixtures\racebp) has two threads call one procedure a fixed number of times each, so a breakpoint on
# its body has an exact expected hit count; a short count is the race.
#
# Measured 2026-09-25 with Iterations 2000 (4000 hits expected): the engine at 0d9d44b reported 575 and 2000;
# the fixed engine 4000 and 4000. Run with -Engine pointing at an older build to see it fail.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE:
#   CAN  - that no hit is missed on this fixture, in -Runs runs of the non-interactive engine, and that the
#          target ran to completion (exit code 0) under it: a hold left in place would have hung it.
#   CANNOT - that no interleaving misses one (a pass is evidence, not proof; protocolcheck CheckRearmHold is
#          where the bookkeeping is pinned), or the interactive routes (test-bp-threaded.ps1, test-interactive.ps1).
#
# Needs Clarion 11 (MSBuild + SoftVelocity.Build.Clarion.targets) and runs a live debuggee, so run-all lists
# it as live, and a caller should hold the clbrws-live lock.
#
#   pwsh tools/test-bp-race.ps1 [-Runs 3] [-Engine <ClarionDbg.exe>]
# Exit code 0 = all checks passed.

param(
  [string] $Engine     = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe'),
  [string] $Fixture    = (Join-Path $PSScriptRoot 'fixtures\racebp'),
  [string] $MSBuild    = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe',
  [string] $ClarionBin = 'C:\Clarion11\bin',
  [int]    $Runs       = 3,
  [int]    $TimeoutMs  = 30000
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-check.ps1')

$script:work = Join-Path ([IO.Path]::GetTempPath()) ('ClarionDbg-racebp-' + [Guid]::NewGuid().ToString('N'))
$script:exe = Join-Path $script:work 'racebp.exe'
$Engine = (Resolve-Path -LiteralPath $Engine).Path

# The breakpoint line and the expected count come from the fixture source, not from numbers typed here.
$src = [IO.File]::ReadAllLines((Join-Path $Fixture 'racebp.clw'))
$script:bpLine = 0
for ($i = 0; $i -lt $src.Length; $i++) { if ($src[$i] -match '^\s+Calls \+= 1\s*$') { $script:bpLine = $i + 1 } }
$script:iterations = 0
foreach ($l in $src) { if ($l -match '^Iterations\s+LONG\((\d+)\)') { $script:iterations = [int]$Matches[1] } }
$script:expected = 2 * $script:iterations

try {
  Invoke-CheckSection 'the fixture builds with Clarion 11' {
    Check 'MSBuild is present' (Test-Path -LiteralPath $MSBuild) $MSBuild
    Check 'the Clarion build targets are present' (Test-Path -LiteralPath (Join-Path $ClarionBin 'SoftVelocity.Build.Clarion.targets')) $ClarionBin
    Check 'the fixture names its breakpoint line and iteration count' (($script:bpLine -gt 0) -and ($script:iterations -gt 0)) "line $($script:bpLine), iterations $($script:iterations)"
    New-Item -ItemType Directory -Path $script:work | Out-Null
    foreach ($f in Get-ChildItem -LiteralPath $Fixture -File | Where-Object { $_.Extension -in '.clw', '.cwproj' }) {
      # CRLF whatever the checkout did: the Clarion compiler rejects LF.
      $text = [IO.File]::ReadAllText($f.FullName) -replace "`r?`n", "`r`n"
      [IO.File]::WriteAllText((Join-Path $script:work $f.Name), $text, [Text.Encoding]::ASCII)
    }
    Push-Location $script:work
    try { $build = & $MSBuild racebp.cwproj -nologo -v:m "/p:ClarionBinPath=$ClarionBin" 2>&1 | Out-String }
    finally { Pop-Location }
    Check 'racebp.exe was built' (Test-Path -LiteralPath $script:exe) $(if (Test-Path -LiteralPath $script:exe) { '' } else { $build.Trim() })
  }

  Invoke-CheckSection 'the fixture runs to completion on its own' {
    # The Process object holds the handle of the process it started, so the kill below cannot reach a
    # recycled pid.
    $p = Start-Process -FilePath $script:exe -WorkingDirectory $script:work -PassThru
    $done = $p.WaitForExit($TimeoutMs)
    if (-not $done) { $p.Kill(); $p.WaitForExit(5000) | Out-Null }
    Check 'racebp.exe exits 0 without a debugger' ($done -and $p.ExitCode -eq 0) $(if ($done) { "exit $($p.ExitCode)" } else { "still running after $TimeoutMs ms - killed" })
  }

  for ($r = 1; $r -le $Runs; $r++) {
    Invoke-CheckSection "run $r of ${Runs}: every hit is reported" {
      $out = @(& $Engine break $script:exe --bp "racebp.clw:$($script:bpLine)" --timeout $TimeoutMs 2>&1 | ForEach-Object { "$_" })
      # "done <dash> N breakpoint hit(s)." - the dash is matched as any non-space, so the console code page
      # cannot break the match.
      $doneLine = @($out | Where-Object { $_ -match '^done \S+ (\d+) breakpoint hit' }) | Select-Object -Last 1
      $hits = if ($doneLine -and $doneLine -match '^done \S+ (\d+) breakpoint hit') { [int]$Matches[1] } else { -1 }
      $exited = @($out | Where-Object { $_ -match '^process exited \(code 0\)$' }).Count -eq 1
      Check "the target ran to completion under the engine (exit code 0)" $exited (($out | Select-Object -Last 3) -join ' | ')
      Check "the engine reported exactly $($script:expected) hits" ($hits -eq $script:expected) "reported $hits"
    }
  }
}
finally {
  if (Test-Path -LiteralPath $script:work) { Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue }
}

# The backstop for a section that returns early without throwing (lib-check.ps1, guard (b)).
$EXPECTED_CHECKS = 5 + 2 * $Runs
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
Write-Host 'NOT PROVED HERE: every interleaving, or the interactive routes. See the header.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
