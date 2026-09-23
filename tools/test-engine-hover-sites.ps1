# Asserts, against the ENGINE'S OWN SOURCE, that every stop resets the hover tracker before the pause loop.
#
#   pwsh -NoProfile -File tools\test-engine-hover-sites.ps1
#   pwsh -NoProfile -File tools\test-engine-hover-sites.ps1 -SelfTest
#
# WHY THIS FILE EXISTS (ticket f6e547ce item 2). PausedWait calls HoverNewStop(), which makes the hover
# tracker forget its last answer so that every stop gets exactly one fresh `hover` event. Without it, the
# page's view of a stop depended on how long the step took (pipeline run 1). protocolcheck proves that
# HoverNewStop WORKS, but it cannot run PausedWait, so it cannot see whether anything CALLS it: deleting the
# call site passed every suite.
#
# POSITION, NOT TEXT. A check that the text `HoverNewStop();` appears in PausedWait passes against
# `if (DateTime.Now.Year < 0) HoverNewStop();`, a call that is still present and never runs (see the
# guard-deletion-vs-disabling note in this repo's history). So the check is structural. The call must be:
#   1. a statement at the TOP LEVEL of PausedWait's body (brace depth 1), so it is not inside any block;
#   2. the START of a statement (the code before it ends in ; { or }), so it is not the braceless body of
#      an if, else, while or for;
#   3. BEFORE the first TryDequeue, which is where the command loop starts;
#   4. preceded by no `return`, so no early exit can skip it.
# Comments are stripped first (Get-CSharpCodeOnly), so a comment that quotes the call cannot satisfy it.
#
# -SelfTest applies the three mutations Diana named, IN MEMORY, and requires each to fail the check: the
# call deleted, the call wrapped in `if (DateTime.Now.Year < 0)`, and the call moved after the loop. Plus a
# braced-if wrap and an early return, one per rule above.
#
# ASCII ONLY: Windows PowerShell 5.1 reads a BOM-less .ps1 as CP1252.

[CmdletBinding()]
param(
  [string] $EnginePath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.cs'),
  [switch] $SelfTest
)

. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$ErrorActionPreference = 'Stop'

$script:Signature = 'private void PausedWait('
$script:Call = 'HoverNewStop();'

# The verdict on one source text: which of the four rules hold, and a one-line reason for the first that
# does not. Pure over its input, so -SelfTest can hand it mutated text.
function Get-HoverStopVerdict {
  param([string] $Src)
  $v = [ordered]@{ Found = $false; TopLevel = $false; StatementStart = $false; BeforeLoop = $false;
                   NoReturnBefore = $false; Reason = '' }
  $block = Get-CSharpBlock $script:Signature $Src
  if ($null -eq $block) { $v.Reason = 'PausedWait not found'; return [pscustomobject] $v }
  $code = Get-CSharpCodeOnly $block
  $open = $code.IndexOf('{')
  $loop = $code.IndexOf('TryDequeue(', [StringComparison]::Ordinal)

  # Walk the body once, tracking brace depth and stepping over literals, and take the FIRST call.
  $depth = 0; $callAt = -1; $callDepth = -1
  $j = $open
  while ($j -lt $code.Length) {
    $k = Skip-CSharpLiteral $code $j
    if ($k -ne $j) { $j = $k; continue }
    $c = $code[$j]
    if ($c -eq '{') { $depth++ }
    elseif ($c -eq '}') { $depth-- }
    elseif ($callAt -lt 0 -and [string]::CompareOrdinal($code, $j, $script:Call, 0, $script:Call.Length) -eq 0 -and
            ($j -eq 0 -or -not ([char]::IsLetterOrDigit($code[$j - 1]) -or $code[$j - 1] -eq '_' -or $code[$j - 1] -eq '.'))) {
      $callAt = $j; $callDepth = $depth
    }
    $j++
  }
  if ($callAt -lt 0) { $v.Reason = "no $($script:Call) in PausedWait"; return [pscustomobject] $v }
  $v.Found = $true
  $v.TopLevel = ($callDepth -eq 1)
  $before = $code.Substring($open + 1, $callAt - $open - 1).TrimEnd()
  $v.StatementStart = ($before.Length -eq 0) -or ($before[$before.Length - 1] -in @(';', '{', '}'))
  $v.BeforeLoop = ($loop -ge 0) -and ($callAt -lt $loop)
  $v.NoReturnBefore = -not ($before -match '\breturn\b')
  if (-not $v.TopLevel) { $v.Reason = "the call is nested at brace depth $callDepth, inside a block" }
  elseif (-not $v.StatementStart) { $v.Reason = "the call is the body of a braceless statement: ...$($before.Substring([Math]::Max(0, $before.Length - 40)))" }
  elseif (-not $v.BeforeLoop) { $v.Reason = 'the call comes after the command loop (first TryDequeue)' }
  elseif (-not $v.NoReturnBefore) { $v.Reason = 'a return before the call can skip it' }
  return [pscustomobject] $v
}

# THE SECOND SITE (a77abd94 item 4, pipeline run 2). `setip` re-announces the stop from INSIDE the command loop
# (AnnounceStop with reason "setip"), not through PausedWait's entry, so the top-level call above does not run
# for it - but the page re-baselines its hover on that `paused` all the same. So the setip case must call
# HoverNewStop() as the VERY NEXT STATEMENT after that AnnounceStop: nothing between them but whitespace, so it
# is neither guarded, nor moved before the announce, nor outside the block the announce runs in.
$script:SetIpAnnounce = 'AnnounceStop(tid, ref ctx, haveCtx, "setip"'
function Get-SetIpHoverVerdict {
  param([string] $Src)
  $v = [ordered]@{ Found = $false; Follows = $false; Reason = '' }
  $block = Get-CSharpBlock $script:Signature $Src
  if ($null -eq $block) { $v.Reason = 'PausedWait not found'; return [pscustomobject] $v }
  $code = Get-CSharpCodeOnly $block
  $a = $code.IndexOf($script:SetIpAnnounce, [StringComparison]::Ordinal)
  if ($a -lt 0) { $v.Reason = 'no setip AnnounceStop in PausedWait'; return [pscustomobject] $v }
  $v.Found = $true
  $end = $code.IndexOf(';', $a)
  $after = if ($end -ge 0) { $code.Substring($end + 1).TrimStart() } else { '' }
  $v.Follows = $after.StartsWith($script:Call, [StringComparison]::Ordinal)
  if (-not $v.Follows) { $v.Reason = "the statement after the setip AnnounceStop is: $($after.Substring(0, [Math]::Min(50, $after.Length)))" }
  return [pscustomobject] $v
}

function Test-HoverStopVerdictOk {
  param($V)
  return $V.Found -and $V.TopLevel -and $V.StatementStart -and $V.BeforeLoop -and $V.NoReturnBefore
}

$engineSrc = Get-Content -Raw -LiteralPath $EnginePath

Invoke-CheckSection 'PausedWait resets the hover tracker, unconditionally, before its command loop' {
  $v = Get-HoverStopVerdict $engineSrc
  Check "PausedWait calls $($script:Call)" $v.Found $v.Reason
  Check '  as a statement at the top level of its body (not inside any block)' $v.TopLevel $v.Reason
  Check '  at the start of a statement (not the braceless body of an if/else/loop)' $v.StatementStart $v.Reason
  Check '  before the command loop (the first TryDequeue)' $v.BeforeLoop $v.Reason
  Check '  with no return before it' $v.NoReturnBefore $v.Reason
}

Invoke-CheckSection 'setip''s re-announce resets the hover tracker too, as the very next statement' {
  $v = Get-SetIpHoverVerdict $engineSrc
  Check 'PausedWait re-announces a setip stop' $v.Found $v.Reason
  Check "  and the next statement is $($script:Call)" $v.Follows $v.Reason
}

if ($SelfTest) {
  Invoke-CheckSection 'mutation self-test (each must be CAUGHT)' {
    $block = Get-CSharpBlock $script:Signature $engineSrc
    # The call's own line, whatever its comment and line ending. Count-asserted: a find that matches
    # nothing would make every mutation below a no-op that "passes" by leaving the source clean. There are TWO
    # call lines since the setip site (a77abd94 item 4); this section is about the FIRST, the top-level one, so
    # it takes the first match and asserts that exact line is unique - a Replace of a line that occurs twice
    # would mutate both sites and prove nothing about either.
    $lineRx = '(?m)^[ \t]*HoverNewStop\(\);[^\r\n]*\r?\n'
    $n = ([regex]::Matches($block, $lineRx)).Count
    Check 'the call lines are found exactly twice (top level, and the setip case)' ($n -eq 2) "$n match(es)"
    $line = [regex]::Match($block, $lineRx).Value
    $u = ([regex]::Matches($block, [regex]::Escape($line))).Count
    Check 'the top-level call line is unique, so every mutation below changes that site only' ($u -eq 1) "$u occurrence(s)"
    $indent = '            '
    $nl = if ($line.EndsWith("`r`n")) { "`r`n" } else { "`n" }
    $withoutCall = $block.Replace($line, '')
    $mutations = [ordered]@{
      'the call deleted' = $withoutCall
      'the call wrapped in if (DateTime.Now.Year < 0)' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) HoverNewStop();$nl")
      'the call moved after the loop' = $withoutCall.Substring(0, $withoutCall.LastIndexOf('}')) + "${indent}HoverNewStop();$nl        }"
      'the call wrapped in a braced if' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) { HoverNewStop(); }$nl")
      'an early return ahead of the call' = $block.Replace($line, "${indent}if (reason == null) return;$nl$line")
    }
    foreach ($name in $mutations.Keys) {
      $mutated = $engineSrc.Replace($block, $mutations[$name])
      $changed = $mutated -cne $engineSrc
      $v = Get-HoverStopVerdict $mutated
      Check "CAUGHT: $name" ($changed -and -not (Test-HoverStopVerdictOk $v)) $(if ($changed) { $v.Reason } else { 'the mutation did not change the source' })
    }
    # CONTROL: the untouched block round-trips through the same splice and still passes, so the mutations
    # fail for what they change and not for how they are spliced.
    $v = Get-HoverStopVerdict ($engineSrc.Replace($block, $block))
    Check 'CONTROL: the unmutated source, through the same splice, passes' (Test-HoverStopVerdictOk $v) $v.Reason
  }

  Invoke-CheckSection 'mutation self-test, the setip site (each must be CAUGHT)' {
    $block = Get-CSharpBlock $script:Signature $engineSrc
    $lineRx = '(?m)^[ \t]*HoverNewStop\(\);[^\r\n]*\r?\n'
    $all = [regex]::Matches($block, $lineRx)
    $line = if ($all.Count -ge 2) { $all[1].Value } else { '' }
    $u = if ($line) { ([regex]::Matches($block, [regex]::Escape($line))).Count } else { 0 }
    Check 'the setip call line is found, and is unique' ($u -eq 1) "$u occurrence(s)"
    $nl = if ($line.EndsWith("`r`n")) { "`r`n" } else { "`n" }
    $indent = [regex]::Match($line, '^[ \t]*').Value
    $announceRx = '(?m)^[ \t]*AnnounceStop\(tid, ref ctx, haveCtx, "setip"[^\r\n]*\r?\n'
    $announce = [regex]::Match($block, $announceRx).Value
    $breakRx = '(?m)^[ \t]*break;[^\r\n]*\r?\n'
    $afterSite = $block.Substring($block.IndexOf($line) + $line.Length)
    $nextBreak = [regex]::Match($afterSite, $breakRx).Value
    $mutations = [ordered]@{
      'the setip call deleted' = $block.Replace($line, '')
      'the setip call wrapped in if (DateTime.Now.Year < 0)' = $block.Replace($line, "${indent}if (DateTime.Now.Year < 0) HoverNewStop();$nl")
      'the setip call moved before the AnnounceStop' = $block.Replace($line, '').Replace($announce, "${indent}HoverNewStop();$nl$announce")
      'the setip call moved out of its block, after the break' = $block.Replace($line, '').Replace($block.Replace($line, '').Substring($block.IndexOf($announce)), $block.Replace($line, '').Substring($block.IndexOf($announce)).Replace($nextBreak, "$nextBreak${indent}HoverNewStop();$nl"))
    }
    foreach ($name in $mutations.Keys) {
      $mutated = $engineSrc.Replace($block, $mutations[$name])
      $changed = $mutated -cne $engineSrc
      $v = Get-SetIpHoverVerdict $mutated
      Check "CAUGHT: $name" ($changed -and -not ($v.Found -and $v.Follows)) $(if ($changed) { $v.Reason } else { 'the mutation did not change the source' })
    }
    $v = Get-SetIpHoverVerdict ($engineSrc.Replace($block, $block))
    Check 'CONTROL: the unmutated source passes the setip-site verdict' ($v.Found -and $v.Follows) $v.Reason
  }
}

# Clean: 5 + 2 (the setip site) = 7. -SelfTest adds, for the top-level site, 2 finds + 5 mutations + 1 control
# = 8, and for the setip site 1 find + 4 mutations + 1 control = 6.
$EXPECTED_CHECKS = if ($SelfTest) { 21 } else { 7 }
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
