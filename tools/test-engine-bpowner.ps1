# Regression check: which IMAGE a breakpoint is armed in, when two loaded DLLs each carry a same-named .clw.
#
# A .clw name on the wire is a bare BASENAME. The old `OwnerOfModule` (removed) answered "the first loaded image carrying it",
# so in a multi-DLL app the user's second gutter dot was folded into the first breakpoint and NEVER ARMED:
# a dot on screen asserting it will stop, and a debugger that silently does not. Task af81c054.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE, stated up front because a green run must not imply more than it is:
#   CAN  - the spec grammar (including that an OLDER engine ignores the new segments), the image-matching
#          rule, and the two identity predicates that decide whether two breakpoints are one.
#   CANNOT - that a breakpoint is actually ARMED and FIRES in both images. That needs a real two-DLL
#          debuggee under the Windows debug API. Nothing here should be read as evidence of it.
#
# Everything below compiles the REAL bodies out of the engine source by brace matching - the same trick
# tools/test-addin-json.ps1 uses - so what is under test is the shipped code, not a paraphrase.
#
#   pwsh tools/test-engine-bpowner.ps1
# Exit code 0 = all checks passed.

param(
  [string] $EnginePath   = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.cs'),
  [string] $EngineBpPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Breakpoints.cs'),
  [string] $ModulesPath  = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Modules.cs')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$eng = Get-Content -Raw -LiteralPath $EnginePath
$bps = Get-Content -Raw -LiteralPath $EngineBpPath
$mod = Get-Content -Raw -LiteralPath $ModulesPath

function Get-Method {
  param([string] $Signature, [string] $From)
  if (-not $From) { $From = $bps }
  $block = Get-CSharpBlock $Signature $From
  if ($null -eq $block) {
    Write-Host "  FAIL  absent from this version of the engine: $Signature"
    Write-Host ''
    Write-Host 'This engine predates the code these checks cover. 1 FAILURE(S)'
    exit 1
  }
  return $block
}

$script:failures = 0
function Check {
  param([string] $Label, [bool] $Ok, [string] $Detail)
  $mark = if ($Ok) { '  PASS  ' } else { '  FAIL  '; }
  if (-not $Ok) { $script:failures++ }
  Write-Host ($mark + $Label + $(if ($Detail) { "  ->  $Detail" } else { '' }))
}
function B64 { param([string] $s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# ---- the shipped bodies, reachable from PowerShell -------------------------------------------------
$specClass = Get-CSharpBlock 'internal sealed class BpSpec' $eng
$predicates = @(
  (Get-Method 'private static bool ImageMatches(LoadedModule m, string spec)' $mod),
  (Get-Method 'private static bool PendingDuplicates(UserBreakpoint b, string module, int line, string image)'),
  (Get-Method 'private static bool RemovalNames(UserBreakpoint b, string image)'),
  (Get-Method 'private static bool Eq(string a, string b)')
) -join "`n"
# The unload rule (af81c054, pipeline run 1) is an instance method over _bps, so it gets its own shim class.
$siblingRule = Get-Method 'internal bool HasArmAllSiblingOutside(UserBreakpoint bp, LoadedModule leaving)' $mod

$shim = @"
using System;
using System.Collections.Generic;

$($specClass -replace 'internal sealed class BpSpec', 'public sealed class BpSpec')

// The two engine records, cut down to the fields the extracted predicates touch. Their field NAMES are
// asserted against the real sources further down, so this cannot quietly drift out of step with them.
public sealed class LoadedModule { public string Path; public string Name; }
public sealed class UserBreakpoint {
    public string Module; public int RequestedLine; public int Line;
    public LoadedModule Owner; public string OwnerSpec; public bool SingleTargetRequested;
}

public static class BpOwner {
$($predicates -replace 'private static', 'public static')
}

public sealed class UnloadRule {
    public List<UserBreakpoint> _bps = new List<UserBreakpoint>();
$($siblingRule -replace 'internal bool', 'public bool')
}
"@
Add-Type -TypeDefinition $shim -Language CSharp | Out-Null

function Img { param($path, $name) $m = New-Object LoadedModule; $m.Path = $path; $m.Name = $name; $m }
function Bp  { param($module, $req, $line, $owner, $spec)
  $b = New-Object UserBreakpoint
  $b.Module = $module; $b.RequestedLine = $req; $b.Line = $line; $b.Owner = $owner; $b.OwnerSpec = $spec; $b
}

$dll1 = Img 'C:\App\Dll1\shared.dll' 'shared.dll'
$dll2 = Img 'C:\App\Dll2\shared.dll' 'shared.dll'   # SAME file name, different folder - the hard case
$other = Img 'C:\App\Dll3\other.dll' 'other.dll'

Write-Host 'the spec grammar carries an image, and an older engine ignores it'
$spec = $null
$ok = [BpSpec]::TryParse(('clbrws011.clw:50|img=' + (B64 'C:\App\Dll2\shared.dll') + '|hm=eq|hv=3'), [ref]$spec)
Check 'a spec with img= parses' $ok ''
Check 'and the module and line are unchanged by its presence' `
  ($ok -and $spec.Module -eq 'clbrws011.clw' -and $spec.Line -eq 50) "$($spec.Module):$($spec.Line)"
Check 'the image round-trips out of base64' ($ok -and $spec.Image -eq 'C:\App\Dll2\shared.dll') $spec.Image
# CONTROL: segments AFTER the new one must still be read, or an unknown segment would eat the rest.
Check 'and the segments after it are still read' ($ok -and $spec.HitMode -eq 'eq' -and $spec.HitValue -eq 3) "$($spec.HitMode)/$($spec.HitValue)"
$bare = $null
[void][BpSpec]::TryParse('clbrws011.clw:50', [ref]$bare)
Check 'a spec with NO img= leaves it null - absent is not an empty image' ($null -eq $bare.Image) ''
Check 'and one= defaults to false, so an old host GETS the fix rather than opting in' (-not $bare.One) ''
$one = $null
[void][BpSpec]::TryParse('clbrws011.clw:50|one=1', [ref]$one)
Check 'one=1 parses as a single-target request' ($one.One) ''

# FAILS CLOSED (af81c054, pipeline run 1): a PRESENT img= that cannot be read used to decode to null and
# so meant "unqualified" - a del aimed at one image removed every copy. Each malformed shape rejects the spec.
$rej = $null
Check 'an img= that is not base64 rejects the whole spec' (-not [BpSpec]::TryParse('m.clw:5|img=%%%notb64', [ref]$rej)) ''
Check 'an EMPTY img= rejects the whole spec' (-not [BpSpec]::TryParse('m.clw:5|img=', [ref]$rej)) ''
Check 'an img= decoding to a control character rejects the whole spec' `
  (-not [BpSpec]::TryParse(('m.clw:5|img=' + (B64 "C:\App`nbp del x.clw:1")), [ref]$rej)) ''
# A long but otherwise VALID printable path, so only the length cap can reject it. An all-'A' string
# decodes to NUL bytes and was rejected by the control-character test instead - found by mutation: removing
# the cap survived that version of this check.
$big = B64 ('C:\' + ('x' * 3100) + '.dll')
Check "CONTROL: the oversized value is itself valid, printable base64 ($($big.Length) chars)" `
  ($big.Length -gt [BpSpec]::MaxImageB64) ''
Check "an img= over MaxImageB64 ($([BpSpec]::MaxImageB64) chars) rejects the whole spec" `
  (-not [BpSpec]::TryParse("m.clw:5|img=$big", [ref]$rej)) ''
Check 'CONTROL: a well-formed img= at the same site still parses' `
  ([BpSpec]::TryParse(('m.clw:5|img=' + (B64 'C:\App\Dll2\shared.dll')), [ref]$rej) -and $rej.Image -eq 'C:\App\Dll2\shared.dll') ''

Write-Host ''
Write-Host 'an image UNLOADING drops an arm-all copy that lives on elsewhere, and keeps the last one'
# Pipeline run 1, debugger gate: a copy returned to pending was re-bound on reload WHILE the surviving
# sibling copied itself in again - two breakpoints in one image, the stale one winning every hit.
function Rule { param([object[]]$bps) $r = New-Object UnloadRule; foreach ($b in $bps) { $r._bps.Add($b) }; $r }
$inA = Bp 'shared.clw' 50 50 $dll1 $null
$inB = Bp 'shared.clw' 50 50 $dll2 $null
$r = Rule @($inA, $inB)
Check 'B leaving, with the same line still armed in A: B''s copy is redundant' ($r.HasArmAllSiblingOutside($inB, $dll2)) ''
$r = Rule @($inB)
Check 'B leaving with NO sibling: kept, so it returns to pending and re-arms on reload' (-not $r.HasArmAllSiblingOutside($inB, $dll2)) ''
$pend = Bp 'SHARED.CLW' 50 50 $null $null
$r = Rule @($inB, $pend)
Check 'a PENDING sibling counts too (it re-arms and copies), and the module name is case-insensitive' ($r.HasArmAllSiblingOutside($inB, $dll2)) ''
$r = Rule @($inB, (Bp 'shared.clw' 60 60 $dll1 $null))
Check 'a different REQUESTED line in another image is not a sibling' (-not $r.HasArmAllSiblingOutside($inB, $dll2)) ''
$named = Bp 'shared.clw' 50 50 $dll2 'C:\App\Dll2\shared.dll'
$r = Rule @($inA, $named)
Check 'a breakpoint that NAMED its image is never dropped - nothing else re-arms it' (-not $r.HasArmAllSiblingOutside($named, $dll2)) ''
$r = Rule @($inA, (Bp 'shared.clw' 50 50 $dll1 'C:\App\Dll1\shared.dll'), $inB)
$r._bps.RemoveAt(0)
Check 'and a NAMED entry elsewhere is not an arm-all sibling - it would not copy itself back into B' (-not $r.HasArmAllSiblingOutside($inB, $dll2)) ''
$one = Bp 'shared.clw' 50 50 $dll2 $null; $one.SingleTargetRequested = $true
$r = Rule @($inA, $one)
Check 'a single-target transient is never dropped by this rule' (-not $r.HasArmAllSiblingOutside($one, $dll2)) ''

Write-Host ''
Write-Host 'THE COMPATIBILITY CLAIM THE WHOLE GRAMMAR RESTS ON, measured against the REAL old parser'
# The argument for putting the image in a |segment rather than anywhere else is that BpSpec.TryParse's
# switch has no `default:`, so an engine that predates the segment skips it and reads the rest. That is a
# claim about code that is no longer in the tree, so it is checked against the version that IS: the parser
# as it stood before this ticket, lifted out of git and compiled under a different type name so it cannot
# alias the new one.
# The parser as of the commit BEFORE this ticket's branch point: c4e1dba, task/bpid's tip, pinned by hash
# so pruning that branch cannot turn this check red.
$baseText = (& git show c4e1dba:src/ClarionDbg.Cli/DebugEngine.cs 2>$null | Out-String)
if ($baseText -and $baseText.Length -gt 100) {
  $oldCls = Get-CSharpBlock 'internal sealed class BpSpec' $baseText
  $oldCls = $oldCls.Replace('internal sealed class BpSpec', 'public sealed class OldBpSpec')
  $oldCls = $oldCls.Replace('public BpSpec(string module, int line)', 'public OldBpSpec(string module, int line)')
  $oldCls = $oldCls.Replace('out BpSpec result', 'out OldBpSpec result')
  $oldCls = $oldCls.Replace('new BpSpec(', 'new OldBpSpec(')
  # DISTINCT TYPE NAME, not a convenience: two versions of one type compiled into one session would alias,
  # and the check would silently test whichever loaded first.
  Add-Type -TypeDefinition ("using System;`n" + $oldCls) -Language CSharp | Out-Null
  $oldSpec = $null
  $oldOk = [OldBpSpec]::TryParse(('clbrws011.clw:50|img=' + (B64 'C:\App\Dll2\shared.dll') + '|hm=eq|hv=3'), [ref]$oldSpec)
  Check 'CONTROL: the extracted parser really is the OLD one (it has no Image field)' `
    ($null -eq ($oldSpec | Get-Member -Name Image)) ''
  Check 'the PRE-CHANGE parser still parses a spec carrying img=' $oldOk ''
  Check 'it reads the right module and line, ignoring the segment it does not know' `
    ($oldOk -and $oldSpec.Module -eq 'clbrws011.clw' -and $oldSpec.Line -eq 50) "$($oldSpec.Module):$($oldSpec.Line)"
  Check 'and the segments AFTER the unknown one still reach it' `
    ($oldOk -and $oldSpec.HitMode -eq 'eq' -and $oldSpec.HitValue -eq 3) "$($oldSpec.HitMode)/$($oldSpec.HitValue)"
} else {
  Check 'the pre-change parser could be read from c4e1dba' $false 'git show failed'
}

Write-Host ''
Write-Host 'which image a spec names: FULL PATH first, then file name'
Check 'an exact full path matches' ([BpOwner]::ImageMatches($dll2, 'C:\App\Dll2\shared.dll')) ''
Check 'and case does not matter, because Windows paths do not' ([BpOwner]::ImageMatches($dll2, 'c:\app\dll2\SHARED.DLL')) ''
# THE POINT OF PREFERRING THE PATH. Both DLLs are called shared.dll; matching on the name alone would put
# us straight back to picking one of two, which is the defect.
Check 'the OTHER image with the same file name does NOT match that path' (-not [BpOwner]::ImageMatches($dll1, 'C:\App\Dll2\shared.dll')) ''
Check 'a bare file name still matches, for a caller that only knows the name' ([BpOwner]::ImageMatches($dll1, 'shared.dll')) ''
Check 'a different file name does not' (-not [BpOwner]::ImageMatches($other, 'shared.dll')) ''
# A null spec must not be a wildcard HERE: "the caller named no image" is a decision for the caller, and
# treating it as a match inside this helper would arm an unqualified breakpoint in whichever image was
# asked about first - which is precisely the bug.
Check 'a NULL spec matches nothing, so unqualified is never decided here' (-not [BpOwner]::ImageMatches($dll1, $null)) ''
Check 'and an empty spec likewise' (-not [BpOwner]::ImageMatches($dll1, '')) ''

Write-Host ''
Write-Host 'the pending dedupe: two pre-launch dots in two DLLs are TWO breakpoints'
# THIS is the site that caused the bug. Before launch nothing is mapped, so every breakpoint arrives here
# and the key was (module, line) alone - both dots folded into one entry before any image resolution ran.
$pendA = Bp 'clbrws011.clw' 50 50 $null 'C:\App\Dll1\shared.dll'
Check 'a pending entry naming Dll1 is NOT a duplicate of a spec naming Dll2' `
  (-not [BpOwner]::PendingDuplicates($pendA, 'clbrws011.clw', 50, 'C:\App\Dll2\shared.dll')) ''
Check 'but it IS a duplicate of a spec naming Dll1 - a re-add is a properties update' `
  ([BpOwner]::PendingDuplicates($pendA, 'clbrws011.clw', 50, 'C:\App\Dll1\shared.dll')) ''
# ISOLATION: the image must be what separates them, not the line or the module. Same image, same line,
# same module must still collapse, or every re-add would pile up a duplicate entry.
$pendNone = Bp 'clbrws011.clw' 50 50 $null $null
Check 'two UNQUALIFIED entries are one breakpoint - there is no second "every image"' `
  ([BpOwner]::PendingDuplicates($pendNone, 'clbrws011.clw', 50, $null)) ''
Check 'an unqualified entry is not a duplicate of one that names an image' `
  (-not [BpOwner]::PendingDuplicates($pendNone, 'clbrws011.clw', 50, 'C:\App\Dll1\shared.dll')) ''
Check 'a different line is still a different breakpoint' `
  (-not [BpOwner]::PendingDuplicates($pendA, 'clbrws011.clw', 51, 'C:\App\Dll1\shared.dll')) ''
Check 'and a different module is too' `
  (-not [BpOwner]::PendingDuplicates($pendA, 'other.clw', 50, 'C:\App\Dll1\shared.dll')) ''

Write-Host ''
Write-Host 'bp del is SYMMETRIC with bp add: unqualified removes what unqualified armed'
$armed1 = Bp 'clbrws011.clw' 50 50 $dll1 $null
$armed2 = Bp 'clbrws011.clw' 50 50 $dll2 $null
Check 'an unqualified del reaches the copy in Dll1' ([BpOwner]::RemovalNames($armed1, $null)) ''
Check 'and the copy in Dll2 - leaving one armed with nothing on screen for it is the same bug reversed' `
  ([BpOwner]::RemovalNames($armed2, $null)) ''
Check 'a del naming Dll2 reaches only that copy' `
  ([BpOwner]::RemovalNames($armed2, 'C:\App\Dll2\shared.dll') -and -not [BpOwner]::RemovalNames($armed1, 'C:\App\Dll2\shared.dll')) ''
# A breakpoint whose image has not mapped yet has no Owner to match on, only the name it ASKED for.
$pendDll2 = Bp 'clbrws011.clw' 50 50 $null 'C:\App\Dll2\shared.dll'
Check 'a del naming Dll2 also reaches the PENDING entry that asked for Dll2' `
  ([BpOwner]::RemovalNames($pendDll2, 'C:\App\Dll2\shared.dll')) ''
Check 'and not the pending entry that asked for Dll1' `
  (-not [BpOwner]::RemovalNames($pendA, 'C:\App\Dll2\shared.dll')) ''

Write-Host ''
Write-Host 'the shipped call sites use these predicates, so the checks above cannot drift from the code'
$add = Get-Method 'private void AddBreakpoint(BpSpec spec)'
Check 'AddBreakpoint takes the whole spec, so a new identity field cannot be dropped from one call site' `
  ($eng -match 'AddBreakpoint\(spec\)' -and $eng -match 'AddBreakpoint\(s\)') ''
Check 'it asks for ALL the images carrying the compiland, not the first' ($add -match 'OwnersOfModule\(module\)') ''
Check 'it narrows to a named image through ImageMatches' ($add -match 'ImageMatches\(m, spec\.Image\)') ''
Check 'it dedupes pending entries through PendingDuplicates' ($add -match 'PendingDuplicates\(') ''
Check 'and a single-target request keeps the first match but SAYS it was ambiguous' `
  ($add -match 'spec\.One && owners\.Count > 1' -and $add -match 'single-target request') ''
$del = Get-Method 'private void RemoveBreakpoint(BpSpec spec)'
Check 'RemoveBreakpoint filters through RemovalNames' ($del -match 'RemovalNames\(b, spec\.Image\)') ''
Check 'and removes EVERY match, not the first' ($del -match 'foreach \(var m in matches\) RemoveOne') ''
# The second job of ResolvePendingFor is what actually fixes the launch case: at launch nothing is mapped,
# so every breakpoint starts pending, the first image to map claims it, and later images get nothing.
$res = Get-Method 'private void ResolvePendingFor(LoadedModule m)'
Check 'ResolvePendingFor gives a later image its own copy of an unqualified breakpoint' `
  ($res -match 'CopyUnqualifiedInto\(m, bp\)') ''
$bind = Get-Method 'private void BindPendingTo(LoadedModule m, UserBreakpoint bp)'
Check 'and a pending bind respects a breakpoint that named a DIFFERENT image' ($bind -match 'ImageMatches\(m, bp\.OwnerSpec\)') ''
Check 'it iterates a SNAPSHOT, so the copies it appends are not re-examined by the same pass' `
  ($res -match '_bps\.ToArray\(\)') ''
# ORDER, pinned by position (af81c054, pipeline run 1): binds BEFORE copies, or an armed sibling copies
# itself into the image before a pending entry for the same line is bound there too - a duplicate.
$iBind = $res.IndexOf('BindPendingTo(m, bp)'); $iCopy = $res.IndexOf('CopyUnqualifiedInto(m, bp)')
Check 'it binds pending entries in a pass BEFORE the copy pass' ($iBind -ge 0 -and $iCopy -gt $iBind) "bind@$iBind copy@$iCopy"
$unl = Get-Method 'private void OnDllUnloaded(uint baseVa)' $mod
$iDrop = $unl.IndexOf('HasArmAllSiblingOutside(bp, m)'); $iNull = $unl.IndexOf('bp.Owner = null')
Check 'OnDllUnloaded asks the sibling rule BEFORE returning a breakpoint to pending' ($iDrop -ge 0 -and $iNull -gt $iDrop) "rule@$iDrop null@$iNull"
$dropBlock = Get-CSharpBlock 'if (HasArmAllSiblingOutside(bp, m))' $unl
Check 'and a dropped copy leaves _bps AND tells the host (bp-del), then skips the pending reset' `
  ($dropBlock -match '_bps\.Remove\(bp\)' -and $dropBlock -match 'Json\.BpDel\(bp\)' -and $dropBlock -match 'continue;') ''
Check 'it walks a snapshot, since it removes from _bps as it goes' ($unl -match 'foreach \(var bp in _bps\.ToArray\(\)\)') ''
$copy = Get-Method 'private void CopyUnqualifiedInto(LoadedModule m, UserBreakpoint bp)'
Check 'the copy is skipped for a single-target breakpoint (run to cursor stays one stop)' ($copy -match 'bp\.SingleTargetRequested') ''
Check 'and for one that named an image' ($copy -match 'IsNullOrEmpty\(bp\.OwnerSpec\)') ''
# REQUESTED line, not planted: a second gutter line that snapped to the same record is a DIFFERENT
# breakpoint and must not suppress this image's copy.
Check 'and the already-covered test is on the REQUESTED line, not the planted one' `
  ($copy -match 'other\.RequestedLine == bp\.RequestedLine' -and $copy -notmatch 'other\.Line == bp\.Line') ''

Write-Host ''
Write-Host 'an ambiguous single-target pick ANNOUNCES itself - it is the one first-match left in the tree'
# |one=1 says "exactly one image". It does NOT say WHICH, so with several carriers the engine takes the
# first - the same arbitrary choice that caused this ticket. That is acceptable ONLY while it is visible,
# so the announcement is a tested behaviour and not a courtesy: a bare Console.WriteLine nobody asserts is
# deleted by the next person tidying output, and the arbitrary pick goes silent again.
Check 'it names HOW MANY images carry the compiland, not just that it was ambiguous' `
  ($add -match 'owners\.Count} loaded images') ''
Check 'and WHICH image it took, so the choice can be checked rather than guessed at' `
  ($add -match 'owners\[0\]\.Name') ''
Check 'and it says the pick came from a single-target request' ($add -match 'single-target request') ''
# ISOLATION: the announcement must be tied to the AMBIGUOUS case. Announcing on every add would be noise
# nobody reads, which is the same as not announcing.
Check 'it fires only when more than one image carries the compiland' ($add -match 'spec\.One && owners\.Count > 1') ''
# ...and it must be the FIRST statement in that block, not merely PRESENT in it. A text check alone
# passes against `if (false) Console.WriteLine(...)` - the announcement still reads as written while
# emitting nothing. Found by mutation: that exact change survived the checks above.
$oneBlock = Get-CSharpBlock 'if (spec.One && owners.Count > 1)' $add
$oneStmts = @($oneBlock -split "`n" | ForEach-Object { $_.Trim() } |
  Where-Object { $_ -and $_ -notmatch '^//' -and $_ -ne '{' -and $_ -notmatch '^if \(spec\.One' })
Check 'and it is the FIRST statement in the block, so it cannot be quietly guarded off' `
  ($oneStmts.Count -gt 0 -and $oneStmts[0] -match '^Console\.WriteLine') ($oneStmts[0]) 

Write-Host ''
Write-Host 'the host SENDS one=1 for run-to-cursor, and for nothing else'
# The engine cannot tell a transient from a persistent add - run-to-cursor is composed host-side as
# `bp add` + `continue` and arrives as an ordinary add - so this is the only thing standing between
# "get me to HERE and stop once" and "stop somewhere on the way".
$webPath = Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs'
$svcPath = Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs'
$web = Get-Content -Raw -LiteralPath $webPath
$svc = Get-Content -Raw -LiteralPath $svcPath
$rtc = Get-CSharpBlock 'public void CmdRunToCursor(string spec)' $web
Check 'CmdRunToCursor asks for a single target' ($rtc -match '_svc\.AddBreakpoint\(module, line, true\)') ''
# EXACTLY ONE site passes true. Counting is the guard: a second one would mean some persistent breakpoint
# had quietly become single-target, which is this ticket's bug reintroduced from the host side.
$trueSites = [regex]::Matches($web, 'AddBreakpoint\([^)]*,\s*true\)')
Check 'and it is the ONLY caller that does - 1 site' ($trueSites.Count -eq 1) "$($trueSites.Count) site(s)"
# The other four call sites are persistent user breakpoints or removals and must NOT be single-target:
# OnGutterBpAdded and CmdBreakOnProcEntry both stage in _pending and survive to the next session, so a
# gutter dot in a second DLL has to arm there too - which is the whole point of the ticket.
$gutterAdd = Get-CSharpBlock 'private void OnGutterBpAdded(string module, int line)' $web
Check 'a gutter dot is NOT single-target, so it arms in every image carrying the .clw' `
  ($gutterAdd -match '_svc\.AddBreakpoint\(module, line\)') ''
# Both break-on-entry paths (the page's id, the editor's position) share BreakOnEntry since e61e4f92.
$procEntry = Get-CSharpBlock 'private void BreakOnEntry(ProcRef proc)' $web
Check 'and neither is break-on-proc-entry, which is a persistent breakpoint despite staging like one' `
  ($procEntry -match '_svc\.AddBreakpoint\(module, line\)') ''
$svcAdd = Get-CSharpBlock 'public bool AddBreakpoint(string module, int line, bool singleTarget)' $svc
Check 'the service writes one=1 only when asked' ($svcAdd -match 'singleTarget \? "\|one=1" : ""') ''
$svcAdd2 = Get-CSharpBlock 'public bool AddBreakpoint(string module, int line)' $svc
Check 'and the 2-argument overload defaults to FALSE, so an unthinking caller gets the fix' `
  ($svcAdd2 -match 'AddBreakpoint\(module, line, false\)') ''
# A properties edit rebuilds the spec through BuildBpSpec. It edits PERSISTENT rows only - run-to-cursor
# transients are filtered out of the pane - so it must never ask for one image. (A host-side
# SingleTargetRequested flag used to be read here and was never set; removed in pipeline run 1.)
$build = Get-CSharpBlock 'public static string BuildBpSpec(DebugBreakpoint bp)' $svc
Check 'BuildBpSpec never sends one=1, so a properties edit keeps the breakpoint in every image' ($build -notmatch 'one=1') ''
Check 'and the dead host-side request flag is gone' ($svc -notmatch 'SingleTargetRequested') ''

Write-Host ''
Write-Host 'the cut-down stubs match the real records'
Check 'UserBreakpoint really has OwnerSpec and SingleTargetRequested' `
  (($eng -match 'public string OwnerSpec;') -and ($eng -match 'public bool SingleTargetRequested;')) ''
# The name is part of the claim: it is a REQUEST from whoever created the breakpoint, not a property of
# the breakpoint. A run-to-cursor and a gutter dot at one module:line are identical down here, which is
# why the request has to travel with it - and why the bare name `SingleTarget` read as a fact it is not.
Check 'and it is named as a REQUEST, not as a fact about the breakpoint' ($eng -notmatch 'public bool SingleTarget;') ''
Check 'BpSpec really has Image and One' (($eng -match 'public string Image;') -and ($eng -match 'public bool One;')) ''
$lm = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\LoadedModule.cs')
Check 'LoadedModule really has Path and Name' (($lm -match 'public string Path;') -and ($lm -match 'public string Name;')) ''
Check 'OwnersOfModule returns every carrier rather than the first' `
  ((Get-Method 'private List<LoadedModule> OwnersOfModule(string clwName)' $mod) -match 'owners\.Add\(m\)') ''

Write-Host ''
Write-Host 'NOT PROVED HERE, and deliberately not implied by a green run:'
Write-Host '  that a breakpoint is actually ARMED and FIRES in both images. That needs a real two-DLL'
Write-Host '  debuggee under the Windows debug API; these checks cover the grammar, the matching rule and'
Write-Host '  the identity predicates that decide whether two breakpoints are one.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host 'ALL CHECKS PASSED'
exit 0
