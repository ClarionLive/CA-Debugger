# Asserts, against the ENGINE'S OWN SOURCE, that every watch reply is emitted through EmitWatchEvent, the one
# place that adds the request id.
#
#   pwsh -NoProfile -File tools\test-engine-reqid-sites.ps1
#   pwsh -NoProfile -File tools\test-engine-reqid-sites.ps1 -SelfTest
#
# WHY THIS FILE EXISTS (contract C1, wave 7). A watch request carrying reqid=N must be answered with
# "reqId":"N" on EVERY reply shape, because the host mints an edit grant only from a reply to an id it still
# holds. protocolcheck (CheckWatchAndModuleDataReqId) drives the found, missed and ambiguous replies, but the
# out-of-scope miss and the path-walk failures need a stack to reach, which it has not got. Those replies are
# built by the same three Json builders, so the rule checked here covers them by construction:
#   1. in DebugEngine.Watch.cs, every Json.Watch( / Json.WatchMiss( / Json.WatchError( call is the argument of
#      EmitWatchEvent(tid, ...), so none goes out without the id;
#   2. EmitThreadEvent appears in DebugEngine.Watch.cs exactly once, inside EmitWatchEvent, and that call
#      passes Json.WithReqId(..., _watchReqId);
#   3. no other engine source builds a watch reply at all.
# Comments are stripped first (Get-CSharpCodeOnly), so a comment that quotes a banned call neither fails a
# clean source nor satisfies a dirty one; -SelfTest checks both directions.
#
# ASCII ONLY: Windows PowerShell 5.1 reads a BOM-less .ps1 as CP1252.

[CmdletBinding()]
param(
  [string] $EngineDir = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli'),
  [switch] $SelfTest
)

. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$ErrorActionPreference = 'Stop'

$script:WatchFile = 'DebugEngine.Watch.cs'
$script:BuilderRx = 'Json\s*\.\s*Watch(Miss|Error)?\s*\('
$script:WrappedRx = 'EmitWatchEvent\s*\(\s*\w+\s*,\s*Json\s*\.\s*Watch(Miss|Error)?\s*\('

# The verdict over a set of sources (file name -> text). Pure over its input, so -SelfTest can hand it
# mutated text.
function Get-ReqIdSiteVerdict {
  param([hashtable] $Sources)
  $v = [ordered]@{ AllWrapped = $false; OneEmit = $false; EmitCarriesId = $false; NoOtherFile = $false; Reason = @() }
  $watch = Get-CSharpCodeOnly $Sources[$script:WatchFile]

  $built = ([regex]::Matches($watch, $script:BuilderRx)).Count
  $wrapped = ([regex]::Matches($watch, $script:WrappedRx)).Count
  $v.AllWrapped = ($built -gt 0) -and ($built -eq $wrapped)
  if (-not $v.AllWrapped) { $v.Reason += "$built watch builder call(s), $wrapped inside EmitWatchEvent" }

  $emits = ([regex]::Matches($watch, 'EmitThreadEvent\s*\(')).Count
  $block = Get-CSharpBlock 'private void EmitWatchEvent(' $watch
  $inBlock = if ($block) { ([regex]::Matches($block, 'EmitThreadEvent\s*\(')).Count } else { 0 }
  $v.OneEmit = ($emits -eq 1) -and ($inBlock -eq 1)
  if (-not $v.OneEmit) { $v.Reason += "EmitThreadEvent $emits time(s) in $($script:WatchFile), $inBlock in EmitWatchEvent" }
  # POSITION, NOT TEXT: the body is that one statement, so `if (DateTime.Now.Year < 0) <the call>` fails it.
  $v.EmitCarriesId = [bool] $block -and ($block -match '^[^{]*\{\s*EmitThreadEvent\s*\(\s*\w+\s*,\s*Json\s*\.\s*WithReqId\s*\([^;]*_watchReqId\s*\)\s*\)\s*;\s*\}$')
  if (-not $v.EmitCarriesId) { $v.Reason += 'EmitWatchEvent does not pass Json.WithReqId(..., _watchReqId)' }

  $others = @()
  foreach ($name in $Sources.Keys) {
    if ($name -eq $script:WatchFile) { continue }
    if ((Get-CSharpCodeOnly $Sources[$name]) -match $script:BuilderRx) { $others += $name }
  }
  $v.NoOtherFile = ($others.Count -eq 0)
  if (-not $v.NoOtherFile) { $v.Reason += "a watch reply is built in $($others -join ', ')" }
  $v.Reason = $v.Reason -join '; '
  return [pscustomobject] $v
}

function Test-ReqIdSiteVerdictOk {
  param($V)
  return $V.AllWrapped -and $V.OneEmit -and $V.EmitCarriesId -and $V.NoOtherFile
}

$sources = @{}
foreach ($f in Get-ChildItem -LiteralPath $EngineDir -Filter 'DebugEngine*.cs' -File) {
  $sources[$f.Name] = Get-Content -Raw -LiteralPath $f.FullName
}

Invoke-CheckSection 'every watch reply goes out through EmitWatchEvent, which adds the request id' {
  Check "$($script:WatchFile) is among the $($sources.Count) engine sources read" $sources.ContainsKey($script:WatchFile) ''
  $v = Get-ReqIdSiteVerdict $sources
  Check 'every Json.Watch/WatchMiss/WatchError call is the argument of EmitWatchEvent' $v.AllWrapped $v.Reason
  Check '  EmitThreadEvent appears once in the file, inside EmitWatchEvent' $v.OneEmit $v.Reason
  Check '  and that call passes Json.WithReqId(..., _watchReqId)' $v.EmitCarriesId $v.Reason
  Check 'no other engine source builds a watch reply' $v.NoOtherFile $v.Reason
}

if ($SelfTest) {
  Invoke-CheckSection 'mutation self-test (each must be CAUGHT)' {
    $src = $sources[$script:WatchFile]
    $miss = 'EmitWatchEvent(tid, Json.WatchMiss(name, false));'
    $n = ([regex]::Matches($src, [regex]::Escape($miss))).Count
    Check 'the path-failure miss call is found exactly once, so the first mutation changes one site' ($n -eq 1) "$n match(es)"
    $emitCall = 'EmitThreadEvent(tid, Json.WithReqId(json, _watchReqId));'
    $m = ([regex]::Matches($src, [regex]::Escape($emitCall))).Count
    Check 'the EmitWatchEvent call is found exactly once' ($m -eq 1) "$m match(es)"
    $mutations = [ordered]@{
      'a miss emitted straight through EmitThreadEvent' = @{ $script:WatchFile = $src.Replace($miss, 'EmitThreadEvent(tid, Json.WatchMiss(name, false));') }
      'EmitWatchEvent dropping the id' = @{ $script:WatchFile = $src.Replace($emitCall, 'EmitThreadEvent(tid, json);') }
      'EmitWatchEvent disabled behind if (DateTime.Now.Year < 0)' = @{ $script:WatchFile = $src.Replace($emitCall, "if (DateTime.Now.Year < 0) $emitCall") }
      'a watch reply built in another engine file' = @{ 'DebugEngine.Locals.cs' = $sources['DebugEngine.Locals.cs'] + "`nclass X { void F() { EmitThreadEvent(1, Json.WatchError(`"n`", `"r`")); } }`n" }
    }
    foreach ($name in $mutations.Keys) {
      $mutated = $sources.Clone()
      $changed = $false
      foreach ($k in $mutations[$name].Keys) { if ($mutated[$k] -cne $mutations[$name][$k]) { $changed = $true }; $mutated[$k] = $mutations[$name][$k] }
      $v = Get-ReqIdSiteVerdict $mutated
      $caught = if ($name -like 'EmitWatchEvent disabled*') { -not $v.EmitCarriesId } else { -not (Test-ReqIdSiteVerdictOk $v) }
      Check "CAUGHT: $name" ($changed -and $caught) $(if ($changed) { $v.Reason } else { 'the mutation did not change the source' })
    }
    # Both directions of the comment rule: a banned call quoted in a comment does not fail a clean source,
    # and a correct call quoted in a comment does not satisfy a source whose real call is gone.
    $commented = $sources.Clone()
    $commented[$script:WatchFile] = $src + "`n// never: EmitThreadEvent(tid, Json.WatchMiss(name, false));`n"
    $v = Get-ReqIdSiteVerdict $commented
    Check 'CONTROL: a banned call quoted in a comment passes' (Test-ReqIdSiteVerdictOk $v) $v.Reason
    $hidden = $sources.Clone()
    $hidden[$script:WatchFile] = $src.Replace($miss, "EmitThreadEvent(tid, Json.WatchMiss(name, false)); // $miss")
    $v = Get-ReqIdSiteVerdict $hidden
    Check 'CAUGHT: a bypass beside a comment quoting the right call' (-not (Test-ReqIdSiteVerdictOk $v)) $v.Reason
    $v = Get-ReqIdSiteVerdict ($sources.Clone())
    Check 'CONTROL: the unmutated sources, cloned the same way, pass' (Test-ReqIdSiteVerdictOk $v) $v.Reason
  }
}

# Clean: 5. -SelfTest adds 2 finds + 4 mutations + 2 comment checks + 1 control = 9.
$EXPECTED_CHECKS = if ($SelfTest) { 14 } else { 5 }
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
