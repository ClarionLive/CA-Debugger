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
  [string] $WebViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs'),
  # SameBp no longer decides a line for itself: it calls the same BpLineMatches that SameBpIdentity and
  # BpDelMatches call, so the service is now part of what this suite compiles. Stubbing that predicate here
  # would let the pad's staging list and the engine-echo list drift apart again while both suites stayed
  # green, which is exactly the shape of contract this project has already been bitten by once.
  [string] $ServicePath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$web = Get-Content -Raw -LiteralPath $WebViewPath
$svc = Get-Content -Raw -LiteralPath $ServicePath

# Get-Method / Check / the null renderer live in lib-extract.ps1 (dot-sourced above). This names the text a
# bare Get-Method reads, which each harness used to bury in its own copy's `if (-not $From)` fallback.
Set-ExtractSource $web


$methods = @(
  (Get-Method 'private void OnGutterBpRemoved(string module, int line)'),
  (Get-Method 'private static bool SameBp(DebugBreakpoint b, string module, int line)')
) -join "`n"

# The real bodies, reachable from PowerShell. Only the collaborators are stubbed - and the breakpoint record
# and the line predicate are now the SHIPPED ones, lifted out of ClarionDebuggerService.cs, so the extracted
# SameBp compiles verbatim with nothing rewritten but the access modifier. The old hand-written stub had no
# RequestedLineOrNull at all, so it could not have told an absent requested line from a present 0 - the
# distinction the whole identity key rests on.
$shim = @"
using System;
using System.Collections.Generic;

$(Get-Method 'public sealed class DebugBreakpoint' $svc)

// Named for the class SameBp calls, so its body needs no rewriting.
public static class ClarionDebuggerService {
$((Get-Method 'internal static bool BpLineMatches(DebugBreakpoint b, int? requestedLine, int plantedLine)' $svc) -replace 'internal static', 'public static')
}

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
Write-Host 'SameBp matches the line the caller ASKED FOR, never one merely planted there'
# b1db9a76 item 2, held back from wave 1 until 05959085 settled which line is the key. SameBp used to be
#     b.RequestedLine == line || b.Line == line
# and that OR let ONE removal trim a DIFFERENT staged entry - one whose SNAPPED line happened to equal the
# removed breakpoint's requested line - losing it silently from the next session's launch spec.
#
# THE OR IS UNREACHABLE THROUGH THE PAD. Every _pending entry is created with Line == RequestedLine and
# nothing writes the engine's snapped line back into _pending, so the two comparisons collapse into one for
# every entry the pad can actually build. That is precisely why it needs a check of its own: every other
# check in this file passes identically with the OR restored, so none of them is testing this.
#
# So the entry below is built DIRECTLY, with the two lines apart, and what is asserted is the predicate's
# contract rather than a path through the pad. A promise no input can currently reach is still a promise,
# and the next writer into _pending is the one who finds out whether it was kept.
$staged = New-Object DebugBreakpoint
$staged.Module = 'MAIN.CLW'; $staged.RequestedLine = 12; $staged.Line = 11   # asked for 12, snapped to 11
Check 'it matches the line the entry asked for' ([BpRemoveProbe]::SameBp($staged, 'MAIN.CLW', 12)) ''
Check 'and NOT the line it was planted on' (-not [BpRemoveProbe]::SameBp($staged, 'MAIN.CLW', 11)) ''
# CONTROL: the same predicate, the same module, a line that is neither. A matcher that had stopped matching
# anything would pass the check above and fail this one's sibling, so both directions are pinned.
Check 'and not an unrelated line' (-not [BpRemoveProbe]::SameBp($staged, 'MAIN.CLW', 99)) ''
Check 'and not another module at the line it did ask for' (-not [BpRemoveProbe]::SameBp($staged, 'OTHER.CLW', 12)) ''
# Module comparison stays case-insensitive here, unlike in the service: one side of THIS comparison is a
# gutter basename from Path.GetFileName, which keeps the file's own case, while both sides of the service's
# are engine-lowercased.
Check 'the module still compares ignoring case, because the gutter keeps the file name''s case' `
  ([BpRemoveProbe]::SameBp($staged, 'main.clw', 12)) ''

Write-Host ''
Write-Host 'and an entry with NO requested line at all still matches on where it was planted'
# Dropping the OR must not drop the documented absent-requested-line fallback with it. An echo from an
# engine build older than the requestedLine protocol change leaves RequestedLineOrNull null, and the planted
# line is then the only thing there is to key on - the same fallback SameBpIdentity and BpDelMatches use.
$legacy = New-Object DebugBreakpoint
$legacy.Module = 'MAIN.CLW'; $legacy.Line = 11; $legacy.RequestedLineOrNull = $null
Check 'a legacy entry matches its planted line' ([BpRemoveProbe]::SameBp($legacy, 'MAIN.CLW', 11)) ''
Check 'and does not match a line it was never planted on' (-not [BpRemoveProbe]::SameBp($legacy, 'MAIN.CLW', 12)) ''
# ISOLATION for the two above: 0 is a REAL requested line (an unresolved raw --rva breakpoint has one), so
# "absent" must not be reachable by writing 0. An entry that asked for 0 is matched at 0, not at its plant.
$raw0 = New-Object DebugBreakpoint
$raw0.Module = 'MAIN.CLW'; $raw0.RequestedLine = 0; $raw0.Line = 13
Check 'a present requested line of 0 is a requested line, not an absent one' `
  (([BpRemoveProbe]::SameBp($raw0, 'MAIN.CLW', 0)) -and -not ([BpRemoveProbe]::SameBp($raw0, 'MAIN.CLW', 13))) ''

Write-Host ''
Write-Host 'the pad decides a line through the same body the service does, not a copy of it'
# Two predicates that happen to read alike drift the moment either is edited. This one calls the service's.
$sameBp = Get-Method 'private static bool SameBp(DebugBreakpoint b, string module, int line)'
Check 'SameBp delegates the line decision to BpLineMatches' ($sameBp -match 'ClarionDebuggerService\.BpLineMatches\(b, line, line\)') ''
Check 'and keeps no comparison of its own' ($sameBp -notmatch 'b\.Line == line' -and $sameBp -notmatch 'b\.RequestedLine ==') ''

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host 'ALL CHECKS PASSED'
exit 0
