# The verify set for this repo, and the one command that runs all of it (ticket a0becd69).
#
#   pwsh -NoProfile -File tools\run-all.ps1                 # build the engine, then every offline suite
#   pwsh -NoProfile -File tools\run-all.ps1 -IncludeLive    # ...and the suites that drive a live debuggee
#   pwsh -NoProfile -File tools\run-all.ps1 -Only test-addin-hooks.ps1,test-pad-parse.js
#   pwsh -NoProfile -File tools\run-all.ps1 -List           # discover and validate the suite list, print it, stop
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
#   - a tools\test-* file with no `suite:` header line, so a new suite cannot rot unlisted. The list is
#     DISCOVERED from those headers (w8-suite-header, tools\lib-suites.ps1), not hand-kept here: the old
#     $Suites array was hand-merged at every wave's integration. Discovery reads the files on disk, so the
#     old "listed but missing" failure can no longer arise;
#   - a malformed header line, a success regex not anchored with ^, and a .ps1 with a $SelfTest parameter
#     but no args=-SelfTest variant (lib-suites.ps1 lists the rest);
#   - fewer entries discovered than $MinEntries, so a suite deleted together with its header is noticed;
#   - a PowerShell suite that does not pin its own total with Assert-CheckTotal (tools\lib-check.ps1),
#     unless its header names why not (nototal=). The success line is only trustworthy if the suite counted
#     itself;
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
  [switch] $ShowOutput,
  # Discover and validate the suite list, print one line per entry, and stop: no encoding check, no build,
  # no suites. Exit 1 if discovery failed. tools\test-run-all.ps1 drives the discovery guards through this.
  [switch] $List
)

$ErrorActionPreference = 'Stop'
$tools = $PSScriptRoot
$repo = Split-Path -Parent $tools
$engineProj = Join-Path $repo 'src\ClarionDbg.Cli\ClarionDbg.Cli.csproj'
$engineExe = Join-Path $repo 'src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe'

# ---------------------------------------------------------------------------------------------- THE LIST
#
# ADDING A SUITE IS ONE LINE IN THE SUITE, not here: `# suite: live=no` (a .js: `// suite: live=no`) within
# its first 40 lines, above param(), one line per run variant. The grammar and each way a line can fail:
# tools\lib-suites.ps1.
. (Join-Path $tools 'lib-suites.ps1')
$discovered = Get-SuiteHeaders -ToolsDir $tools
$Suites = @($discovered.Entries)
# A FLOOR on the entries discovered. It may only be RAISED: lowered, a suite deleted together with its header
# is gone without a word. 2026-10-03: 56 = the 55 entries of the hand-kept $Suites at 81f268e, plus
# tools\test-run-all.ps1.
$MinEntries = 56
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
foreach ($e in $discovered.Errors) { Report 'FAIL' $e.File $e.Message }
$fileCount = @($Suites | ForEach-Object { $_.File } | Sort-Object -Unique).Count
Write-Host "run-all: discovered $($Suites.Count) suite entries in $fileCount files (floor `$MinEntries = $MinEntries)"
if ($Suites.Count -lt $MinEntries) {
  Report 'FAIL' 'suite list' "BELOW THE FLOOR: $($Suites.Count) entries discovered, `$MinEntries = $MinEntries - a suite lost its header or its file"
}
foreach ($s in $Suites) {
  $path = Join-Path $tools $s.File
  if ($s.File -like '*.ps1' -and -not $s.NoTotal -and (Test-Path -LiteralPath $path)) {
    # Code only, not comments: a file that merely DISCUSSES Assert-CheckTotal has not opted in.
    $code = @(Get-Content -LiteralPath $path | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    if ($code -notmatch '(?m)^\s*Assert-CheckTotal\b') {
      Report 'FAIL' $s.File 'does not pin its total with Assert-CheckTotal, so its success line cannot be trusted (or give its suite line a nototal= reason)'
    }
  }
}
if ($List) {
  foreach ($s in $Suites) { Write-Host (Format-SuiteEntry $s) }
  Write-Host ''
  if ($script:failed) { Write-Host "RUN-ALL LIST FAILED: $($script:failed) problem(s), $($Suites.Count) entries"; exit 1 }
  Write-Host "RUN-ALL LIST OK: $($Suites.Count) entries"
  exit 0
}

# ---------------------------------------------------------------------------------------------- encoding
# KNOWN VIOLATORS, each parsing under 5.1 by luck. Empty since ticket 075e9071 gave the last six (spikes/)
# a BOM (2026-09-24). This list may only SHRINK: a file here that no longer needs the exception is a
# FAILURE, so the list cannot outlive its reason. Do not add to it; give the file a BOM instead.
$EncodingPending = @()
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
else { Report 'PASS' 'encoding' "every .ps1 is ASCII or carries a UTF-8 BOM, bar $($EncodingPending.Count) pending" }

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
