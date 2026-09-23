# Asserts, against the ENGINE'S OWN SOURCE, that setip's observations are cut back at every resume.
#
#   pwsh -NoProfile -File tools\test-engine-setip-sites.ps1
#   pwsh -NoProfile -File tools\test-engine-setip-sites.ps1 -SelfTest
#
# WHY (a77abd94 item 4, pipeline run 2). setip allows a move "via observed" when this frame instance already
# stopped at the target with the current ESP. Across a FREE RUN a procedure can return and be re-entered at the
# same EBP from the same call site with no stop between, so an old observation would match the new call. The
# rule lives at ONE choke point: ArmResume, which every resume verb calls, starts with SetIpOnResume(...).
# protocolcheck proves what SetIpOnResume DECIDES; it cannot run ArmResume, so it cannot see whether anything
# CALLS it. Deleting the call, or guarding it, or moving it after the resume, would pass every other suite.
#
# POSITION, NOT TEXT (see test-engine-hover-sites.ps1 for the history). With comments stripped:
#   1. SetIpOnResume( is the FIRST statement of ArmResume's body: nothing but whitespace between the body's
#      opening brace and the call. That alone rules out a guard, a braced block, an earlier return, and any
#      code that could resume the thread before it;
#   2. StepMachine calls SetIpNoteStepEsp( as a TOP-LEVEL statement (brace depth 1) that starts a statement and
#      has no return before it, so every trap of a step records its ESP.
#
# -SelfTest applies the mutations IN MEMORY and requires each to fail the check.
#
# ASCII ONLY: Windows PowerShell 5.1 reads a BOM-less .ps1 as CP1252.

[CmdletBinding()]
param(
  [string] $EnginePath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.cs'),
  [string] $SteppingPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Stepping.cs'),
  [switch] $SelfTest
)

. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$ErrorActionPreference = 'Stop'

$script:ResumeSig = 'private void ArmResume('
$script:ResumeCall = 'SetIpOnResume('
$script:StepSig = 'private void StepMachine('
$script:StepCall = 'SetIpNoteStepEsp('

# Is $Call the first statement of $Sig's body?
function Get-FirstStatementVerdict {
  param([string] $Src, [string] $Sig, [string] $Call)
  $block = Get-CSharpBlock $Sig $Src
  if ($null -eq $block) { return "$Sig not found" }
  $code = Get-CSharpCodeOnly $block
  $open = $code.IndexOf('{')
  $body = $code.Substring($open + 1).TrimStart()
  if ($body.StartsWith($Call, [StringComparison]::Ordinal)) { return $null }
  return "the first statement of $Sig is: $($body.Substring(0, [Math]::Min(60, $body.Length)))"
}

# Is $Call a top-level statement of $Sig's body, at a statement start, with no return before it?
function Get-TopLevelVerdict {
  param([string] $Src, [string] $Sig, [string] $Call)
  $block = Get-CSharpBlock $Sig $Src
  if ($null -eq $block) { return "$Sig not found" }
  $code = Get-CSharpCodeOnly $block
  $open = $code.IndexOf('{')
  $depth = 0; $callAt = -1; $callDepth = -1; $j = $open
  while ($j -lt $code.Length) {
    $k = Skip-CSharpLiteral $code $j
    if ($k -ne $j) { $j = $k; continue }
    $c = $code[$j]
    if ($c -eq '{') { $depth++ } elseif ($c -eq '}') { $depth-- }
    elseif ($callAt -lt 0 -and [string]::CompareOrdinal($code, $j, $Call, 0, $Call.Length) -eq 0 -and
            -not ([char]::IsLetterOrDigit($code[$j - 1]) -or $code[$j - 1] -eq '_' -or $code[$j - 1] -eq '.')) { $callAt = $j; $callDepth = $depth }
    $j++
  }
  if ($callAt -lt 0) { return "no $Call in $Sig" }
  if ($callDepth -ne 1) { return "the call is nested at brace depth $callDepth" }
  $before = $code.Substring($open + 1, $callAt - $open - 1).TrimEnd()
  if ($before.Length -gt 0 -and $before[$before.Length - 1] -notin @(';', '{', '}')) { return 'the call is the body of a braceless statement' }
  if ($before -match '\breturn\b') { return 'a return before the call can skip it' }
  return $null
}

# 3. (pipeline run 3) Run's EXCEPTION branch hands a first-chance exception back to the app with
#    `status = Native.DBG_EXCEPTION_NOT_HANDLED;` - the app's handler can unwind a watched step - and the VERY
#    NEXT statement must be SetIpOnExceptionPassed(tid);. The assignment must occur exactly once in Run, so a
#    second hand-back cannot appear without this check noticing.
$script:RunSig = 'public int Run('
$script:PassStmt = 'status = Native.DBG_EXCEPTION_NOT_HANDLED;'
$script:PassCall = 'SetIpOnExceptionPassed(tid);'
function Get-ExceptionPassVerdict {
  param([string] $Src)
  $block = Get-CSharpBlock $script:RunSig $Src
  if ($null -eq $block) { return 'Run not found' }
  $code = Get-CSharpCodeOnly $block
  $n = ([regex]::Matches($code, [regex]::Escape($script:PassStmt))).Count
  if ($n -ne 1) { return "Run hands an exception back $n time(s); expected exactly 1" }
  $at = $code.IndexOf($script:PassStmt, [StringComparison]::Ordinal) + $script:PassStmt.Length
  $after = $code.Substring($at).TrimStart()
  if ($after.StartsWith($script:PassCall, [StringComparison]::Ordinal)) { return $null }
  return "the statement after the hand-back is: $($after.Substring(0, [Math]::Min(60, $after.Length)))"
}

$engineSrc = Get-Content -Raw -LiteralPath $EnginePath
$stepSrc = Get-Content -Raw -LiteralPath $SteppingPath

Invoke-CheckSection 'every resume cuts setip''s observations back, before anything else' {
  $r = Get-FirstStatementVerdict $engineSrc $script:ResumeSig $script:ResumeCall
  Check "ArmResume's first statement is $($script:ResumeCall)...)" ($null -eq $r) $r
}

Invoke-CheckSection 'every trap of a step records its ESP' {
  $r = Get-TopLevelVerdict $stepSrc $script:StepSig $script:StepCall
  Check "StepMachine calls $($script:StepCall)...) unconditionally, before any return" ($null -eq $r) $r
}

Invoke-CheckSection 'an exception handed back to the app ends a watched step' {
  $r = Get-ExceptionPassVerdict $engineSrc
  Check "Run's DBG_EXCEPTION_NOT_HANDLED is followed at once by $($script:PassCall)" ($null -eq $r) $r
}

if ($SelfTest) {
  Invoke-CheckSection 'mutation self-test, the exception hand-back (each must be CAUGHT)' {
    $block = Get-CSharpBlock $script:RunSig $engineSrc
    $lineRx = '(?m)^[ \t]*SetIpOnExceptionPassed\(tid\);[^\r\n]*\r?\n'
    $n = ([regex]::Matches($block, $lineRx)).Count
    Check 'the call line is found exactly once' ($n -eq 1) "$n match(es)"
    $line = [regex]::Match($block, $lineRx).Value
    $nl = if ($line.EndsWith("`r`n")) { "`r`n" } else { "`n" }
    $indent = [regex]::Match($line, '^[ \t]*').Value
    $exitRx = '(?m)^[ \t]*running = false;[^\r\n]*\r?\n'
    $exitLine = [regex]::Match($block, $exitRx).Value
    $without = $block.Replace($line, '')
    $mutations = [ordered]@{
      'the call deleted' = $without
      'the call wrapped in if (DateTime.Now.Year < 0)' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) SetIpOnExceptionPassed(tid);$nl")
      'the call moved to another case (EXIT_PROCESS)' = $(if ($exitLine) { $without.Replace($exitLine, "$exitLine${indent}SetIpOnExceptionPassed(tid);$nl") } else { $block })
      'a second hand-back without the call' = $block.Replace($line, "$line${indent}status = Native.DBG_EXCEPTION_NOT_HANDLED;$nl")
    }
    foreach ($name in $mutations.Keys) {
      $mutated = $engineSrc.Replace($block, $mutations[$name])
      $changed = $mutated -cne $engineSrc
      $r = Get-ExceptionPassVerdict $mutated
      Check "CAUGHT: $name" ($changed -and $null -ne $r) $(if ($changed) { $r } else { 'the mutation did not change the source' })
    }
    Check 'CONTROL: the unmutated source passes' ($null -eq (Get-ExceptionPassVerdict ($engineSrc.Replace($block, $block)))) ''
  }

  Invoke-CheckSection 'mutation self-test, the resume choke point (each must be CAUGHT)' {
    $block = Get-CSharpBlock $script:ResumeSig $engineSrc
    $lineRx = '(?m)^[ \t]*SetIpOnResume\([^\r\n]*\r?\n'
    $n = ([regex]::Matches($block, $lineRx)).Count
    Check 'the call line is found exactly once' ($n -eq 1) "$n match(es)"
    $line = [regex]::Match($block, $lineRx).Value
    $nl = if ($line.EndsWith("`r`n")) { "`r`n" } else { "`n" }
    $indent = [regex]::Match($line, '^[ \t]*').Value
    $stmt = $line.Trim() -replace '\s*//.*$', ''
    $without = $block.Replace($line, '')
    $closeAt = $without.LastIndexOf('}')
    $mutations = [ordered]@{
      'the call deleted' = $without
      'the call wrapped in if (DateTime.Now.Year < 0)' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) $stmt$nl")
      'the call moved after the resume (end of ArmResume)' = $without.Substring(0, $closeAt) + "${indent}$stmt$nl        }"
      'the call after an early return' = $block.Replace($line, "${indent}if (!haveCtx) return;$nl$line")
    }
    foreach ($name in $mutations.Keys) {
      $mutated = $engineSrc.Replace($block, $mutations[$name])
      $changed = $mutated -cne $engineSrc
      $r = Get-FirstStatementVerdict $mutated $script:ResumeSig $script:ResumeCall
      Check "CAUGHT: $name" ($changed -and $null -ne $r) $(if ($changed) { $r } else { 'the mutation did not change the source' })
    }
    Check 'CONTROL: the unmutated source passes' ($null -eq (Get-FirstStatementVerdict ($engineSrc.Replace($block, $block)) $script:ResumeSig $script:ResumeCall)) ''
  }

  Invoke-CheckSection 'mutation self-test, the step trap (each must be CAUGHT)' {
    $block = Get-CSharpBlock $script:StepSig $stepSrc
    $lineRx = '(?m)^[ \t]*SetIpNoteStepEsp\([^\r\n]*\r?\n'
    $n = ([regex]::Matches($block, $lineRx)).Count
    Check 'the call line is found exactly once' ($n -eq 1) "$n match(es)"
    $line = [regex]::Match($block, $lineRx).Value
    $nl = if ($line.EndsWith("`r`n")) { "`r`n" } else { "`n" }
    $indent = [regex]::Match($line, '^[ \t]*').Value
    $stmt = $line.Trim() -replace '\s*//.*$', ''
    $mutations = [ordered]@{
      'the call deleted' = $block.Replace($line, '')
      'the call wrapped in if (DateTime.Now.Year < 0)' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) $stmt$nl")
      'the call in a braced if' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) { $stmt }$nl")
      'the call after an early return' = $block.Replace($line, "${indent}if (_stepCount < 0) return;$nl$line")
    }
    foreach ($name in $mutations.Keys) {
      $mutated = $stepSrc.Replace($block, $mutations[$name])
      $changed = $mutated -cne $stepSrc
      $r = Get-TopLevelVerdict $mutated $script:StepSig $script:StepCall
      Check "CAUGHT: $name" ($changed -and $null -ne $r) $(if ($changed) { $r } else { 'the mutation did not change the source' })
    }
    Check 'CONTROL: the unmutated source passes' ($null -eq (Get-TopLevelVerdict ($stepSrc.Replace($block, $block)) $script:StepSig $script:StepCall)) ''
  }
}

# Clean: 3 checks. -SelfTest adds 1 find + 4 mutations + 1 control per site, for 3 sites = 18.
$EXPECTED_CHECKS = if ($SelfTest) { 21 } else { 3 }
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
