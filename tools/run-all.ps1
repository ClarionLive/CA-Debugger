# The verify set for this repo, and the one command that runs all of it (ticket a0becd69).
#
#   pwsh -NoProfile -File tools\run-all.ps1                 # build the engine, then every offline suite
#   pwsh -NoProfile -File tools\run-all.ps1 -IncludeLive    # ...and the suites that drive a live debuggee
#   pwsh -NoProfile -File tools\run-all.ps1 -Only test-addin-hooks.ps1,test-pad-parse.js
#
# There is no CI. Before this file the only full list of suites lived in the PM's spawn briefs, so a new
# suite was born unlisted and rotted unrun, and a green reported as "12 suites" was really 12 of 15 - the
# three missing were the three SLOWEST, which is what a list people have to remember always sheds.
#
# IT FAILS CLOSED, and each of these is a FAILURE, never a skip:
#   - a suite that exits non-zero;
#   - a suite that exits 0 WITHOUT printing its own success line. A top-level `break` in a harness gives
#     exit 0 and no summary at all (measured by ticket 60344b78: 69 of 222 checks, no summary, exit 0), so
#     an exit code alone would certify a suite that died politely;
#   - a tools\test-* file on disk that is not in $Suites below, so a new suite cannot rot unlisted;
#   - a $Suites entry whose file is gone;
#   - a listed PowerShell suite that does not pin its own total with Assert-CheckTotal (tools\lib-check.ps1),
#     unless its entry names why not. The success line is only trustworthy if the suite counted itself;
#   - a .ps1 anywhere in the repo that carries non-ASCII bytes without a UTF-8 BOM. Windows PowerShell 5.1
#     reads such a file as CP1252 and can fail to parse it far from the cause (ticket 718ea446);
#   - the engine build failing or warning, protocolcheck missing, or node missing.
# LIVE suites launch the Clarion example app under the engine and poke its windows. They are skipped by
# default with a visible "SKIPPED (live)" line - never silently - and run with -IncludeLive.
#
# Each PowerShell suite runs in a FRESH pwsh: most compile extracted C# with Add-Type, which cannot
# redefine a type already loaded in the process.

[CmdletBinding()]
param(
  [switch] $IncludeLive,
  # Skip the engine build and use the binary already on disk. protocolcheck and the live suites run it.
  [switch] $NoBuild,
  # Run only these suite files (the list and encoding checks still run in full).
  [string[]] $Only = @(),
  # Print every suite's full output, not only a failing suite's.
  [switch] $ShowOutput
)

$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$repo = Split-Path -Parent $tools
$engineProj = Join-Path $repo 'src\ClarionDbg.Cli\ClarionDbg.Cli.csproj'
$engineExe = Join-Path $repo 'src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe'

# ---------------------------------------------------------------------------------------------- THE LIST
#
# ADDING A SUITE IS ONE LINE HERE. Fields:
#   File      the file in tools\ (required)
#   Args      extra arguments, e.g. @('-SelfTest'). A file may be listed more than once with different Args.
#   Live      $true for a suite that needs the Clarion example app and a live debuggee
#   Success   regex for the suite's own success line, matched against each output line. Defaults below.
#   NoTotal   a .ps1 that deliberately does not call Assert-CheckTotal must say why here
$Suites = @(
  @{ File = 'test-addin-bpident.ps1' }
  @{ File = 'test-addin-bpremove.ps1' }
  @{ File = 'test-addin-hooks.ps1' }
  @{ File = 'test-addin-json.ps1' }
  @{ File = 'test-addin-lifecycle.ps1' }
  @{ File = 'test-host-tid-members.ps1' }
  @{ File = 'test-host-tid-members.ps1'; Args = @('-SelfTest') }
  @{ File = 'test-disasm-seat.ps1' }
  @{ File = 'test-file-record-predicate.ps1'
     NoTotal = 'wave 3 integration: Bea opts it in to Assert-CheckTotal with her phase-2 merge (04d7b4c8)' }
  @{ File = 'test-threaded-template-rule.ps1'
     NoTotal = 'wave 3 integration: Bea opts it in to Assert-CheckTotal with her phase-2 merge (3c031cdc)' }
  @{ File = 'test-engine-bpowner.ps1'; Success = '^ALL CHECKS PASSED$'
     NoTotal = 'not yet opted in to Assert-CheckTotal and prints no count - ticket 6493d226' }
  @{ File = 'test-engine-session.ps1' }
  @{ File = 'test-engine-tid-members.ps1' }
  @{ File = 'test-engine-tid-members.ps1'; Args = @('-SelfTest') }
  @{ File = 'test-pad-bpstate.js' }
  @{ File = 'test-pad-contrast.js' }
  @{ File = 'test-pad-editmeta.js' }
  @{ File = 'test-pad-parse.js'; Success = '^all \d+ inline script block\(s\) parse OK$' }
  @{ File = 'test-pad-source.js' }
  @{ File = 'test-pad-threads.js' }
  @{ File = 'test-pad-watch-persist.js' }
  @{ File = 'test-bp-threaded.ps1'; Live = $true }
  @{ File = 'test-watch-threaded.ps1'; Live = $true }
  @{ File = 'test-interactive.ps1'; Live = $true; Success = '^=== exit code: 0 ===$'
     NoTotal = 'a paced step/stepover/stepout smoke run with no Check calls; its verdict is the engine exit code' }
)
# A .ps1 suite's success line names its count (lib-check's summary). The node suites predate a shared
# summary, so theirs may or may not carry one.
$DefaultSuccess = @{ '.ps1' = '^ALL \d+ CHECKS PASSED'; '.js' = '^ALL (\d+ )?CHECKS PASSED$' }

# ---------------------------------------------------------------------------------------------- output
$script:failed = 0
$script:passed = 0
$script:skipped = 0
function Report {
  param([string] $Status, [string] $Name, [string] $Detail)
  if ($Status -eq 'FAIL') { $script:failed++ } elseif ($Status -eq 'PASS') { $script:passed++ } else { $script:skipped++ }
  Write-Host ('{0,-15} {1,-42} {2}' -f $Status, $Name, $Detail)
}
function Show-Tail {
  param([string[]] $Lines, [int] $Count = 40)
  $from = [Math]::Max(0, $Lines.Count - $Count)
  if ($from -gt 0) { Write-Host "        ... ($from earlier line(s); -ShowOutput prints all of them)" }
  for ($i = $from; $i -lt $Lines.Count; $i++) { Write-Host "        | $($Lines[$i])" }
}

# ---------------------------------------------------------------------------------------------- the list is complete
Write-Host "run-all: $repo"
Write-Host ''
$listed = @($Suites | ForEach-Object { $_.File } | Sort-Object -Unique)
$onDisk = @(Get-ChildItem -LiteralPath $tools -File | Where-Object { $_.Name -like 'test-*.ps1' -or $_.Name -like 'test-*.js' } |
            ForEach-Object { $_.Name } | Sort-Object)
foreach ($f in $onDisk) {
  if ($listed -notcontains $f) { Report 'FAIL' $f 'UNLISTED: a suite on disk that nothing runs - add one line to $Suites in tools\run-all.ps1' }
}
foreach ($f in $listed) {
  if ($onDisk -notcontains $f) { Report 'FAIL' $f 'LISTED BUT MISSING: remove it from $Suites, or restore the file' }
}
foreach ($s in $Suites) {
  $path = Join-Path $tools $s.File
  if ($s.File -like '*.ps1' -and -not $s.NoTotal -and (Test-Path -LiteralPath $path)) {
    # Code only, not comments: a file that merely DISCUSSES Assert-CheckTotal has not opted in.
    $code = @(Get-Content -LiteralPath $path | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    if ($code -notmatch '(?m)^\s*Assert-CheckTotal\b') {
      Report 'FAIL' $s.File 'does not pin its total with Assert-CheckTotal, so its success line cannot be trusted (or give its entry a NoTotal reason)'
    }
  }
}

# ---------------------------------------------------------------------------------------------- encoding
# KNOWN VIOLATORS, each parsing under 5.1 by luck (measured 2026-09-22), awaiting ticket 075e9071. This
# list may only SHRINK: a file here that no longer needs the exception is a FAILURE, so the list cannot
# outlive its reason.
$EncodingPending = @(
  'spikes/decode-tswd.ps1'
  'spikes/tswd-datasym2.ps1'
  'spikes/tswd-datasym5.ps1'
  'spikes/tswd-datasym6.ps1'
  'spikes/tswd-locate-line317.ps1'
  'spikes/watch-eval-probe.ps1'
)
$nonAsciiNoBom = @()
# Tracked AND untracked-but-not-ignored, so a new script is checked before its first commit, not after.
foreach ($rel in @(& git -C $repo ls-files --cached --others --exclude-standard '*.ps1')) {
  $full = Join-Path $repo $rel
  if (-not (Test-Path -LiteralPath $full)) { continue }     # deleted in the working tree
  $bytes = [IO.File]::ReadAllBytes($full)
  $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
  # Latin-1 maps each byte to one char, so a regex finds any byte above 0x7F without a per-byte pipeline.
  if (-not $bom -and [Text.Encoding]::GetEncoding(28591).GetString($bytes) -match '[^\x00-\x7F]') { $nonAsciiNoBom += $rel }
}
$newBad = @($nonAsciiNoBom | Where-Object { $EncodingPending -notcontains $_ })
$stale = @($EncodingPending | Where-Object { $nonAsciiNoBom -notcontains $_ })
if ($LASTEXITCODE -ne 0) { Report 'FAIL' 'encoding' 'git ls-files failed, so the .ps1 encoding check read nothing' }
elseif ($newBad.Count) {
  Report 'FAIL' 'encoding' ("non-ASCII with no UTF-8 BOM, which Windows PowerShell 5.1 misreads: " + ($newBad -join ', '))
}
elseif ($stale.Count) {
  Report 'FAIL' 'encoding' ("fixed or gone, so remove from `$EncodingPending: " + ($stale -join ', '))
}
else { Report 'PASS' 'encoding' "every .ps1 is ASCII or carries a UTF-8 BOM, bar $($EncodingPending.Count) pending (075e9071)" }

# ---------------------------------------------------------------------------------------------- build + protocolcheck
if (-not $NoBuild) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $build = @(& dotnet build $engineProj --nologo 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  $warn = @($build | Where-Object { $_ -match '^\s*(\d+) Warning\(s\)' } | ForEach-Object { [int] ($_ -replace '^\s*(\d+).*', '$1') })
  $t = '{0:0.0}s' -f $sw.Elapsed.TotalSeconds
  if ($code -ne 0) { Report 'FAIL' 'build ClarionDbg.Cli' "exit $code ($t)"; Show-Tail $build }
  elseif ($warn.Count -ne 1 -or $warn[0] -ne 0) { Report 'FAIL' 'build ClarionDbg.Cli' "warnings: $($warn -join ',') ($t)"; Show-Tail $build }
  else { Report 'PASS' 'build ClarionDbg.Cli' "0 warnings ($t)" }
}
if (-not $Only.Count -or $Only -contains 'protocolcheck') {
  if (-not (Test-Path -LiteralPath $engineExe)) { Report 'FAIL' 'protocolcheck' "no engine binary at $engineExe" }
  else {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = @(& $engineExe protocolcheck 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $line = @($out | Where-Object { $_ -match '^protocolcheck: \d+ checks, all OK\.$' }) | Select-Object -First 1
    $t = '{0:0.0}s' -f $sw.Elapsed.TotalSeconds
    if ($code -eq 0 -and $line) { Report 'PASS' 'protocolcheck' "$line ($t)"; if ($ShowOutput) { Show-Tail $out 100000 } }
    else { Report 'FAIL' 'protocolcheck' "exit $code, success line $(if ($line) { 'present' } else { 'MISSING' }) ($t)"; Show-Tail $out }
  }
}

# ---------------------------------------------------------------------------------------------- the suites
$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
foreach ($s in $Suites) {
  $args0 = @(if ($s.Args) { $s.Args })
  $name = (@($s.File) + $args0) -join ' '
  if ($Only.Count -and $Only -notcontains $s.File) { continue }
  $path = Join-Path $tools $s.File
  if (-not (Test-Path -LiteralPath $path)) { continue }     # already reported as LISTED BUT MISSING
  if ($s.Live -and -not $IncludeLive) {
    Report 'SKIPPED (live)' $name 'drives the Clarion example app under the engine - run with -IncludeLive'
    continue
  }
  $ext = [IO.Path]::GetExtension($s.File)
  $success = if ($s.Success) { $s.Success } else { $DefaultSuccess[$ext] }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  if ($ext -eq '.ps1') {
    if (-not $pwsh) { Report 'FAIL' $name 'pwsh not found on PATH'; continue }
    $out = @(& $pwsh -NoProfile -File $path @args0 2>&1 | ForEach-Object { "$_" })
  }
  else {
    if (-not $node) { Report 'FAIL' $name 'node not found on PATH'; continue }
    $out = @(& $node $path @args0 2>&1 | ForEach-Object { "$_" })
  }
  $code = $LASTEXITCODE
  $t = '{0:0.0}s' -f $sw.Elapsed.TotalSeconds
  # -cmatch: the success line is this repo's own fixed spelling, and "all checks passed" is not it.
  $line = @($out | Where-Object { $_ -cmatch $success }) | Select-Object -Last 1
  if ($code -eq 0 -and $line) {
    Report 'PASS' $name "$line ($t)"
    if ($ShowOutput) { Show-Tail $out 100000 }
  }
  elseif ($code -eq 0) {
    Report 'FAIL' $name "exit 0 but NO SUCCESS LINE matching '$success' - the suite stopped without a verdict ($t)"
    Show-Tail $out
  }
  else {
    Report 'FAIL' $name "exit $code ($t)"
    Show-Tail $out
  }
}

Write-Host ''
$summary = "$($script:passed) passed, $($script:failed) failed, $($script:skipped) skipped"
if ($script:failed) { Write-Host "RUN-ALL FAILED: $summary"; exit 1 }
Write-Host "RUN-ALL PASSED: $summary"
exit 0
