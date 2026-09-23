# Source-level check: "is this a FILE record buffer's name" has ONE shape test (ticket 04d7b4c8 item 2).
#
# The module-data panel used a bare EndsWith(":RECORD"), which also counted a form's HISTORY::COU:RECORD and
# hid it from the panel, while the name index (TswdDebugInfo.DataNameRank) used the FILE$PRE:RECORD shape.
# Both now call TswdDebugInfo.IsFileRecordName. They want different VERDICTS on a scoped PROC::FILE$PRE:RECORD,
# so the rank adds its own no-"::" condition on top: the test is shared, the answer is not.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE:
#   CAN  - that the engine sources hold exactly one ":RECORD" suffix test, inside IsFileRecordName; that the
#          panel's skip is that call, immediately followed by `continue`; and that DataNameRank calls it.
#   CANNOT - that the shape rule is right (protocolcheck CheckFileRecordShape asserts it), or what the
#          panel shows on a live stop.
#
#   pwsh tools/test-file-record-predicate.ps1
# Exit code 0 = all checks passed.

param(
  [string] $EngineDir = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli'),
  [string] $CoreDir   = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Core')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$script:checks = 0
$script:failures = 0

$suffixTest = '(?i)EndsWith\(\s*":RECORD"'

Write-Host 'the scan can fail: known-dirty inputs are flagged'
Check 'flagged: the panel''s old suffix test' `
  ([regex]::Matches('if (ds.Name != null && ds.Name.EndsWith(":RECORD", StringComparison.OrdinalIgnoreCase)) continue;', $suffixTest).Count -eq 1) ''
Check 'not flagged: the same call quoted in a comment' `
  ([regex]::Matches((Get-CSharpCodeOnly "// was ds.Name.EndsWith("":RECORD"")`nint x = 1;"), $suffixTest).Count -eq 0) ''

Write-Host ''
Write-Host 'exactly one ":RECORD" suffix test in the engine, and it is IsFileRecordName'
$tswdPath = Join-Path $CoreDir 'TswdDebugInfo.cs'
$tswd = Get-Content -Raw -LiteralPath $tswdPath
$files = @(Get-ChildItem -LiteralPath $EngineDir -Filter '*.cs' -File) + @(Get-ChildItem -LiteralPath $CoreDir -Filter '*.cs' -File)
Check 'the scan found engine sources to read' ($files.Count -gt 10) "$($files.Count) files"
$total = 0
$where = @()
foreach ($f in $files) {
  $n = [regex]::Matches((Get-CSharpCodeOnly (Get-Content -Raw -LiteralPath $f.FullName)), $suffixTest).Count
  if ($n -gt 0) { $total += $n; $where += "$($f.Name) x$n" }
}
Check 'one suffix test across the engine' ($total -eq 1) ($where -join ', ')
$pred = Get-CSharpBlock 'public static bool IsFileRecordName(' $tswd
Check 'IsFileRecordName exists' ($null -ne $pred) ''
if ($null -ne $pred) {
  Check 'and holds that one test' ([regex]::Matches((Get-CSharpCodeOnly $pred), $suffixTest).Count -eq 1) ''
}

Write-Host ''
Write-Host 'both callers ask it'
$rank = Get-CSharpBlock 'private static int DataNameRank(' $tswd
Check 'DataNameRank exists' ($null -ne $rank) ''
if ($null -ne $rank) {
  Check 'DataNameRank calls IsFileRecordName' ((Get-CSharpCodeOnly $rank) -match '\bIsFileRecordName\(container\)') ''
}
$locals = Get-Content -Raw -LiteralPath (Join-Path $EngineDir 'DebugEngine.Locals.cs')
$panel = Get-CSharpBlock 'private void HandleModuleDataCommand(' $locals
Check 'HandleModuleDataCommand exists' ($null -ne $panel) ''
if ($null -ne $panel) {
  # The CALL and its POSITION: the skip is the predicate, followed directly by `continue`. A check for the
  # call text alone passes against `if (false && TswdDebugInfo.IsFileRecordName(ds.Name))`.
  Check 'the module-data panel skips exactly on IsFileRecordName(ds.Name)' `
    ((Get-CSharpCodeOnly $panel) -match 'if \(TswdDebugInfo\.IsFileRecordName\(ds\.Name\)\)\s*continue;') ''
}

Write-Host ''
Write-Host 'NOT PROVED HERE: that the shape rule is right, or what the panel shows live.'
Write-Host '  protocolcheck CheckFileRecordShape asserts the rule; the panel needs a live stop.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
