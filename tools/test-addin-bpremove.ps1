# Regression check: OnGutterBpRemoved trims the pad's staging list only when the engine took the removal.
#
# _pending (what StartSession resends wholesale) and _svc.Breakpoints (the engine's live list) are separate,
# and they can diverge in BOTH directions:
#   - trim too little, and a breakpoint removed mid-session is resurrected at the next start (fixed in 7ff1989);
#   - trim too eagerly, and a removal the engine REFUSED is forgotten by the pad while staying ARMED in the
#     live session. The user then gets a stop with nothing on screen to account for it, and nothing left to
#     retry the removal from.
#
# RemoveBreakpoint returns false for real reasons: IsValidModuleName rejects the module, or SendCommand fails
# because the engine pipe is gone. Neither is visible from the page.
#
# THE ONLY DISCRIMINATING CASE IS A FAILING REMOVAL. When the engine accepts the removal, trimming before the
# call and trimming after it are indistinguishable - a happy-path check passes identically against the old
# ordering and the new one, and so proves nothing. That is why the checks below lean on RemoveBreakpoint
# returning FALSE.
#
# This compiles the REAL OnGutterBpRemoved and SameBp straight out of ClarionDebuggerWebView.cs - extracted by
# brace matching, the same trick tools/test-addin-json.ps1 uses - against stub collaborators, so the ordering
# under test is the shipped ordering and not a paraphrase of it.
#
#   pwsh tools/test-addin-bpremove.ps1 [path\to\ClarionDebuggerWebView.cs]
# Exit code 0 = all checks passed.

param(
  [string] $WebViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs')
)

$ErrorActionPreference = 'Stop'
$web = Get-Content -Raw -LiteralPath $WebViewPath

function Get-Method {
  param([string] $Signature, [string] $From)
  if (-not $From) { $From = $web }
  $i = $From.IndexOf($Signature, [StringComparison]::Ordinal)
  if ($i -lt 0) {
    # Pointed at a version that predates the method under test: say so plainly instead of throwing
    # halfway through, which reads like a broken test rather than the before/after proof it is.
    Write-Host "  FAIL  absent from this version of the add-in: $Signature"
    Write-Host ''
    Write-Host 'This add-in predates the code these checks cover. 1 FAILURE(S)'
    exit 1
  }
  $depth = 0; $started = $false
  for ($j = $i; $j -lt $From.Length; $j++) {
    $c = $From[$j]
    if ($c -eq '{') { $depth++; $started = $true }
    elseif ($c -eq '}') { $depth--; if ($started -and $depth -eq 0) { return $From.Substring($i, $j - $i + 1) } }
  }
  throw "unterminated: $Signature"
}

$methods = @(
  (Get-Method 'private void OnGutterBpRemoved(string module, int line)'),
  (Get-Method 'private static bool SameBp(DebugBreakpoint b, string module, int line)')
) -join "`n"

# The real bodies, reachable from PowerShell. Only the collaborators are stubbed: the stub is named
# DebugBreakpoint so the extracted SameBp compiles verbatim, with nothing rewritten but the access modifier.
$shim = @"
using System;
using System.Collections.Generic;

public class DebugBreakpoint { public string Module; public int RequestedLine; public int Line; }

public class SvcStub {
    public bool IsRunning;
    public bool RemoveResult;            // what the engine answers
    public int RemoveCalls;
    public string LastModule; public int LastLine;
    public bool RemoveBreakpoint(string module, int line) {
        RemoveCalls++; LastModule = module; LastLine = line; return RemoveResult;
    }
}

public class BpRemoveProbe {
    public SvcStub _svc = new SvcStub();
    public List<DebugBreakpoint> _pending = new List<DebugBreakpoint>();
    public int SendBpsCalls;
    private void SendBps() { SendBpsCalls++; }

$($methods -replace 'private void OnGutterBpRemoved', 'public void OnGutterBpRemoved' -replace 'private static bool SameBp', 'public static bool SameBp')
}
"@

Add-Type -TypeDefinition $shim -Language CSharp | Out-Null

$script:failures = 0
function Check {
  param([string] $Label, [bool] $Ok, [string] $Detail)
  $mark = if ($Ok) { '  PASS  ' } else { '  FAIL  '; }
  if (-not $Ok) { $script:failures++ }
  Write-Host ($mark + $Label + $(if ($Detail) { "  ->  $Detail" } else { '' }))
}

function New-Probe {
  param([bool] $Running, [bool] $RemoveSucceeds)
  $p = New-Object BpRemoveProbe
  $p._svc.IsRunning = $Running
  $p._svc.RemoveResult = $RemoveSucceeds
  $bp = New-Object DebugBreakpoint
  $bp.Module = 'MAIN.CLW'; $bp.RequestedLine = 42; $bp.Line = 42
  $p._pending.Add($bp)
  return $p
}

Write-Host 'a removal the engine REFUSED is not forgotten by the pad'
# The whole point of the ordering. Old code trimmed first and would fail every check in this block.
$p = New-Probe $true $false
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'the pending entry survives a failed RemoveBreakpoint' ($p._pending.Count -eq 1) "$($p._pending.Count) entry/entries left"
Check 'the engine was actually asked' ($p._svc.RemoveCalls -eq 1) "$($p._svc.RemoveCalls) call(s)"
Check 'the surviving entry is the one that was asked for' ($p._pending.Count -eq 1 -and $p._pending[0].Module -eq 'MAIN.CLW' -and $p._pending[0].RequestedLine -eq 42) ''
# Still on the list means the user can see it in the pane and remove it again; that retry is the
# recovery path the eager trim destroys.
$p._svc.RemoveResult = $true
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'and a retry after the engine recovers does trim it' ($p._pending.Count -eq 0) "$($p._pending.Count) entry/entries left"

Write-Host ''
Write-Host 'a removal the engine TOOK is trimmed'
$p = New-Probe $true $true
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'the pending entry is gone' ($p._pending.Count -eq 0) "$($p._pending.Count) entry/entries left"
Check 'module and line reached the engine unchanged' ($p._svc.LastModule -eq 'MAIN.CLW' -and $p._svc.LastLine -eq 42) "$($p._svc.LastModule):$($p._svc.LastLine)"

Write-Host ''
Write-Host 'the idle branch still trims unconditionally - there is no engine call that could fail'
$p = New-Probe $false $false     # RemoveResult is irrelevant here and must stay irrelevant
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'the pending entry is gone while idle' ($p._pending.Count -eq 0) "$($p._pending.Count) entry/entries left"
Check 'the engine is not called while idle' ($p._svc.RemoveCalls -eq 0) "$($p._svc.RemoveCalls) call(s)"
Check 'the pane is refreshed while idle' ($p.SendBpsCalls -eq 1) "$($p.SendBpsCalls) SendBps call(s)"

Write-Host ''
Write-Host 'the running branch leaves the refresh to the engine''s echo'
# While running the pane renders from _svc.Breakpoints and is refreshed by OnSvcBreakpointRemoved -> SendBps().
# A SendBps() from here would paint the removal as done before the engine has confirmed it.
$p = New-Probe $true $false
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'no SendBps after a failed removal' ($p.SendBpsCalls -eq 0) "$($p.SendBpsCalls) SendBps call(s)"
$p = New-Probe $true $true
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'no SendBps after a successful removal either' ($p.SendBpsCalls -eq 0) "$($p.SendBpsCalls) SendBps call(s)"

Write-Host ''
Write-Host 'a failed removal does not take an unrelated breakpoint with it'
$p = New-Probe $true $false
$other = New-Object DebugBreakpoint
$other.Module = 'OTHER.CLW'; $other.RequestedLine = 42; $other.Line = 42
$p._pending.Add($other)
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'both entries survive' ($p._pending.Count -eq 2) "$($p._pending.Count) entry/entries left"
$p = New-Probe $true $true
$p._pending.Add($other)
$p.OnGutterBpRemoved('MAIN.CLW', 42)
Check 'a successful removal trims only the matching module' ($p._pending.Count -eq 1 -and $p._pending[0].Module -eq 'OTHER.CLW') "$($p._pending.Count) left"

Write-Host ''
Write-Host 'the ordering is commented as deliberate, so it is not "tidied" back'
# The two lines read fine either way round; without the note the next reader has no way to know the
# order carries a decision. This check is the note's only guard.
$body = Get-Method 'private void OnGutterBpRemoved(string module, int line)'
Check 'OnGutterBpRemoved says the ordering is deliberate' ($body -match '(?i)deliberate') ''

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host 'ALL CHECKS PASSED'
exit 0
