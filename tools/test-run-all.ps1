# suite: live=no
# run-all.ps1's suite DISCOVERY can fail (ticket 49538b78, w8-suite-header).
#
# run-all builds its list from each suite's own `suite:` header lines (tools\lib-suites.ps1) instead of a
# hand-kept array. A discovery that silently drops a suite would print a smaller green, so every guard on it
# is broken here once and must turn run-all RED with its own message. Each case copies tools\ to a temp
# directory, plants ONE fault in the copy, and runs the copy's `run-all.ps1 -List` (discovery only: no build,
# no suites) in a fresh pwsh. A case is CAUGHT only if run-all exits non-zero AND prints the FAIL message of
# the guard aimed at it, so a run-all that went red for another reason does not count. 2026-10-03: a case
# that matched only "MALFORMED" passed with the prefix guard disabled, because the parser then rejected the
# same line under a different message.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE:
#   CAN    - that the real tools\ discovers cleanly (control), and that each planted fault turns it red; that
#            test-engine-session.ps1 goes red when a harness's header stops saying live=yes.
#   CANNOT - that the discovered list is the RIGHT list; $MinEntries in run-all.ps1 is the floor on that.
#
#   pwsh -NoProfile -File tools\test-run-all.ps1
# Exit code 0 = all checks passed.

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-check.ps1')
$script:checks = 0
$script:failures = 0
$script:pwsh = (Get-Command pwsh).Source

function New-ToolsCopy {
  $root = Join-Path ([IO.Path]::GetTempPath()) ('run-all-probe-' + [guid]::NewGuid().ToString('N'))
  $dir = Join-Path $root 'tools'
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Get-ChildItem -LiteralPath $PSScriptRoot -File | Copy-Item -Destination $dir
  return $dir
}
function Remove-ToolsCopy([string] $dir) { Remove-Item -LiteralPath (Split-Path -Parent $dir) -Recurse -Force -ErrorAction SilentlyContinue }

# ONE copy for every case, each fault undone after its run: a fresh copy per case cost ~11 s each
# (2026-10-03, measured: the copy, not the run - new script files in %TEMP% are slow to write here).
# Restore-ToolsCopy puts back every file's bytes and deletes nothing a case did not add.
function Save-ToolsCopy([string] $dir) {
  $snap = @{}
  foreach ($f in Get-ChildItem -LiteralPath $dir -File) { $snap[$f.Name] = [IO.File]::ReadAllBytes($f.FullName) }
  return $snap
}
function Restore-ToolsCopy([string] $dir, [hashtable] $snap) {
  foreach ($f in Get-ChildItem -LiteralPath $dir -File) { if (-not $snap.ContainsKey($f.Name)) { Remove-Item -LiteralPath $f.FullName } }
  foreach ($name in $snap.Keys) {
    $path = Join-Path $dir $name
    if (-not (Test-Path -LiteralPath $path) -or -not [Linq.Enumerable]::SequenceEqual([byte[]][IO.File]::ReadAllBytes($path), [byte[]]$snap[$name])) {
      [IO.File]::WriteAllBytes($path, $snap[$name])
    }
  }
}

# Rewrites one file in the copy, keeping its bytes otherwise (BOM, CRLF). Throws if $Find is not there
# exactly once, so a fault that plants nothing cannot pass as a fault that was caught.
function Set-Fault([string] $dir, [string] $file, [string] $find, [string] $replace) {
  $path = Join-Path $dir $file
  $text = [IO.File]::ReadAllText($path, [Text.Encoding]::Latin1)
  $at = $text.IndexOf($find, [StringComparison]::Ordinal)
  if ($at -lt 0 -or $text.IndexOf($find, $at + 1, [StringComparison]::Ordinal) -ge 0) { throw "fault not planted: '$find' is not in $file exactly once" }
  [IO.File]::WriteAllText($path, $text.Substring(0, $at) + $replace + $text.Substring($at + $find.Length), [Text.Encoding]::Latin1)
}

function Invoke-List([string] $dir) {
  $out = @(& $script:pwsh -NoProfile -File (Join-Path $dir 'run-all.ps1') -List 2>&1 | ForEach-Object { "$_" })
  return @{ Code = $LASTEXITCODE; Out = $out }
}

# One planted fault: red, and the FAIL line names the file and the reason.
function Test-Fault([string] $name, [scriptblock] $plant, [string] $failFile, [string] $failText) {
  $dir = $script:copy
  try {
    & $plant $dir
    $r = Invoke-List $dir
    $hit = @($r.Out | Where-Object { $_ -match '^FAIL\s' -and $_.Contains($failFile) -and $_.Contains($failText) })
    Check "CAUGHT: $name" ($r.Code -ne 0 -and $hit.Count -ge 1 -and @($r.Out | Where-Object { $_ -like 'RUN-ALL LIST FAILED:*' }).Count -eq 1) `
      "exit $($r.Code); $(($r.Out | Where-Object { $_ -match '^FAIL\s' }) -join ' / ')"
  }
  finally { Restore-ToolsCopy $dir $script:pristine }
}

function Test-CleanList([string] $name) {
  $r = Invoke-List $script:copy
  $ok = @($r.Out | Where-Object { $_ -match '^RUN-ALL LIST OK: (\d+) entries$' })
  $entries = @($r.Out | Where-Object { $_ -match '^test-\S+ \| args=' })
  Check $name ($r.Code -eq 0 -and $ok.Count -eq 1 -and $ok[0] -eq "RUN-ALL LIST OK: $($entries.Count) entries" -and
               -not @($r.Out | Where-Object { $_ -match '^FAIL\s' }).Count) `
    "exit $($r.Code); $(($r.Out | Select-Object -Last 1) -join '') ; $($entries.Count) entry line(s)"
}

$script:copy = New-ToolsCopy
$script:pristine = Save-ToolsCopy $script:copy

$S = '# suite: '   # split here, so no line of THIS file reads as a suite header
$J = '// suite: '

Invoke-CheckSection '1) control: a copy of the real tools\ discovers cleanly' {
  Test-CleanList 'the unmodified copy lists OK, one line per entry it counts, and no FAIL line'
}

Invoke-CheckSection '2) each discovery guard turns run-all red' {
  Test-Fault 'a suite with no suite line' { param($d) Set-Fault $d 'test-pad-csp.js' ($J + "live=no`r`n") '' } `
    'test-pad-csp.js' 'NO SUITE LINE'
  Test-Fault 'a malformed value (live=maybe)' { param($d) Set-Fault $d 'test-disasm-seat.ps1' ($S + 'live=no') ($S + 'live=maybe') } `
    'test-disasm-seat.ps1' 'MALFORMED suite line (live=yes|no is required)'
  Test-Fault 'a malformed prefix (#suite: with no space)' { param($d) Set-Fault $d 'test-disasm-seat.ps1' ($S + 'live=no') ('#suite: live=no') } `
    'test-disasm-seat.ps1' 'MALFORMED suite line (must start'
  Test-Fault 'an unknown key' { param($d) Set-Fault $d 'test-disasm-seat.ps1' ($S + 'live=no') ($S + 'live=no; tag=x') } `
    'test-disasm-seat.ps1' 'MALFORMED suite line (unknown key ''tag'')'
  Test-Fault 'a success regex without ^' { param($d) Set-Fault $d 'test-pad-parse.js' "success='^all" "success='all" } `
    'test-pad-parse.js' 'UNANCHORED'
  Test-Fault 'a $SelfTest parameter with no args=-SelfTest line' { param($d) Set-Fault $d 'test-procs.ps1' ($S + "live=no; args=-SelfTest`r`n") '' } `
    'test-procs.ps1' 'no ''args=-SelfTest'''
  Test-Fault 'a suite line below param()' {
    param($d)
    Set-Fault $d 'test-file-record-predicate.ps1' ($S + "live=no`r`n") ''
    Set-Fault $d 'test-file-record-predicate.ps1' "`$ErrorActionPreference = 'Stop'" ($S + "live=no`r`n`$ErrorActionPreference = 'Stop'")
  } 'test-file-record-predicate.ps1' 'below param()'
  Test-Fault 'a .ps1 with no Assert-CheckTotal whose nototal reason is removed' {
    param($d)
    $p = Join-Path $d 'test-interactive.ps1'
    $t = [IO.File]::ReadAllText($p, [Text.Encoding]::Latin1)
    $m = [regex]::Match($t, "; nototal='[^']*'")
    if (-not $m.Success) { throw 'fault not planted: no nototal in test-interactive.ps1' }
    [IO.File]::WriteAllText($p, $t.Remove($m.Index, $m.Length), [Text.Encoding]::Latin1)
  } 'test-interactive.ps1' 'Assert-CheckTotal'
  Test-Fault 'fewer entries than $MinEntries (every test-pad-*.js deleted)' {
    param($d)
    $gone = @(Get-ChildItem -LiteralPath $d -Filter 'test-pad-*.js')
    if (-not $gone.Count) { throw 'fault not planted: no test-pad-*.js to delete' }
    $gone | Remove-Item
  } 'suite list' 'BELOW THE FLOOR'
  # Every case above ran against the same copy, so this proves each fault was undone and no case was red
  # for an earlier case's reason.
  Test-CleanList 'control: after every fault is undone, the copy lists OK again'
}

Invoke-CheckSection '3) test-engine-session pins the harness set to the live=yes headers' {
  $dir = $script:copy
  try {
    $clean = @(& $script:pwsh -NoProfile -File (Join-Path $dir 'test-engine-session.ps1') 2>&1 | ForEach-Object { "$_" })
    $cleanCode = $LASTEXITCODE
    Check 'control: the unmodified copy passes' ($cleanCode -eq 0 -and @($clean | Where-Object { $_ -match '^ALL \d+ CHECKS PASSED$' }).Count -eq 1) "exit $cleanCode"
    Set-Fault $dir 'test-setip.ps1' ($S + 'live=yes') ($S + 'live=no')
    $out = @(& $script:pwsh -NoProfile -File (Join-Path $dir 'test-engine-session.ps1') 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $hit = @($out | Where-Object { $_ -match '^\s*FAIL\s+the scripts that launch the engine binary, plus the one-shot pair, are exactly the live=yes suites' })
    Check 'CAUGHT: a harness whose header says live=no turns it red on the set check' ($code -ne 0 -and $hit.Count -eq 1) "exit $code"
  }
  finally { Restore-ToolsCopy $dir $script:pristine }
}
Remove-ToolsCopy $script:copy

# The backstop for a section that returns early without throwing (lib-check.ps1). Update the number
# deliberately when adding or removing a check.
$EXPECTED_CHECKS = 13
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
