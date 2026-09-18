# Regression check: the add-in's JSON number reader, which decides WHICH THREAD a reply belongs to.
#
# Two ways this hurts, both silent:
#   - a "tid" read out of a nested array or a string value names the wrong thread, so good replies get
#     dropped as "another thread's" and rows sit on "...";
#   - a real Win32 thread id above Int32.MaxValue read as a signed int comes back null, and null means
#     UNSCOPED - so a reply the engine DID stamp is accepted as if it were for whatever thread is on
#     screen. That is the absent-means-unknown rule broken from the other side, and it would hit roughly
#     one thread id in two.
#
# Neither can be reached from the pad's node suites (they never parse) and neither shows up against a live
# debuggee, whose thread ids are usually small. So this compiles the REAL methods straight out of
# ClarionDebuggerService.cs - extracted by brace matching, the same trick tools/pad-dom.js uses on the
# page - and asserts them directly.
#
#   pwsh tools/test-addin-json.ps1 [path\to\ClarionDebuggerService.cs]
# Exit code 0 = all checks passed.

param(
  [string] $ServicePath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs'),
  [string] $WebViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs'),
  # the ENGINE side of the wire: the breakpoint-identity checks run its real writer into the host's real
  # reader, so both files have to be on hand rather than one side being imagined in a string literal
  [string] $EngineJsonPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\Json.cs'),
  [string] $EnginePath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.cs'),
  [string] $EngineBpPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Breakpoints.cs'),
  # the toolbar/pad controller: the teardown checks run its real NotifyStopped decision table
  [string] $ControllerPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\DebugSessionController.cs')
)

$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw -LiteralPath $ServicePath
$web = Get-Content -Raw -LiteralPath $WebViewPath
$engine = Get-Content -Raw -LiteralPath $EngineJsonPath
$engineSrc = Get-Content -Raw -LiteralPath $EnginePath
$bpSrc = Get-Content -Raw -LiteralPath $EngineBpPath
$ctl = Get-Content -Raw -LiteralPath $ControllerPath

function Get-Method {
  param([string] $Signature, [string] $From)
  if (-not $From) { $From = $src }
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
  (Get-Method 'private static string ScanNumberToken(string json, string key)'),
  (Get-Method 'private static int? GetIntOrNull(string json, string key)'),
  (Get-Method 'private static uint? GetUIntOrNull(string json, string key)'),
  (Get-Method 'private static string TidJson(uint? tid)' $web)
) -join "`n"

# same bodies, reachable from PowerShell
$shim = @"
using System;
using System.Globalization;
public static class PadJsonProbe {
$($methods -replace 'private static', 'public static')
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
function ShowU { param($v) if ($null -eq $v) { 'null' } else { [string] $v } }

Write-Host 'the event''s own tid, and nothing else''s'
$paused = '{"tid":116932,"event":"paused","reason":"breakpoint","proc":"SPLASHSCREEN","regs":{"eax":"0x0"}}'
Check 'tid first, before event, with a nested regs object' ([PadJsonProbe]::GetUIntOrNull($paused, 'tid') -eq 116932) (ShowU ([PadJsonProbe]::GetUIntOrNull($paused, 'tid')))
$stack = '{"event":"stack","frames":[{"frame":0,"tid":1}]}'
Check 'a tid inside the frames array is not the event''s' ($null -eq [PadJsonProbe]::GetUIntOrNull($stack, 'tid')) (ShowU ([PadJsonProbe]::GetUIntOrNull($stack, 'tid')))
$both = '{"frames":[{"tid":1}],"tid":4812}'
Check 'the top-level one wins over a nested one' ([PadJsonProbe]::GetUIntOrNull($both, 'tid') -eq 4812) (ShowU ([PadJsonProbe]::GetUIntOrNull($both, 'tid')))
$instr = '{"value":"x \"tid\":99 y","tid":7}'
Check 'a tid inside a string VALUE is not the event''s' ([PadJsonProbe]::GetUIntOrNull($instr, 'tid') -eq 7) (ShowU ([PadJsonProbe]::GetUIntOrNull($instr, 'tid')))

Write-Host ''
Write-Host 'absent is the only way to say "unknown"'
Check 'an absent tid reads as null' ($null -eq [PadJsonProbe]::GetUIntOrNull('{"event":"watch"}', 'tid')) ''
Check 'a JSON null reads as null' ($null -eq [PadJsonProbe]::GetIntOrNull('{"clarionThread":null}', 'clarionThread')) ''
Check 'a Clarion thread number of 0 is a REAL value, not absent' ([PadJsonProbe]::GetIntOrNull('{"clarionThread":0}', 'clarionThread') -eq 0) ''

Write-Host ''
Write-Host 'a Win32 thread id is a DWORD: a real one is never degraded to "unscoped"'
foreach ($tid in 4294967295, 4294967294, 3221225472, 2147483648, 2147483647, 116932) {
  $json = '{"tid":' + $tid + ',"event":"watch","found":true}'
  $got = [PadJsonProbe]::GetUIntOrNull($json, 'tid')
  Check "tid $tid survives" ($got -eq $tid) (ShowU $got)
}
$overflow = '{"tid":4294967296}'   # past a DWORD: malformed protocol, not a thread we could select
Check 'a value past the DWORD range is refused rather than truncated' ($null -eq [PadJsonProbe]::GetUIntOrNull($overflow, 'tid')) (ShowU ([PadJsonProbe]::GetUIntOrNull($overflow, 'tid')))
Check 'the signed reader still refuses a DWORD it cannot hold' ($null -eq [PadJsonProbe]::GetIntOrNull('{"tid":4294967295}', 'tid')) ''

Write-Host ''
Write-Host 'shapes'
Check 'whitespace around the colon' ([PadJsonProbe]::GetUIntOrNull('{ "tid" : 42 }', 'tid') -eq 42) ''
Check 'empty input' ($null -eq [PadJsonProbe]::GetUIntOrNull('', 'tid')) ''
Check 'a threads ROW parsed on its own' ([PadJsonProbe]::GetUIntOrNull('{"tid":4812,"clarionThread":null}', 'tid') -eq 4812) ''
Check 'a negative tid is not a thread id' ($null -eq [PadJsonProbe]::GetUIntOrNull('{"tid":-3}', 'tid')) ''
Check 'the signed reader still reads a negative' ([PadJsonProbe]::GetIntOrNull('{"line":-3}', 'line') -eq -3) ''

Write-Host ''
Write-Host 'and the WRITER says "unknown" the same way the reader hears it: by leaving the member out'
Check 'an absent tid writes no member at all' ([PadJsonProbe]::TidJson($null) -eq '') "'$([PadJsonProbe]::TidJson($null))'"
Check 'a 0 is a sentinel, not a thread - written as absent too' ([PadJsonProbe]::TidJson(0) -eq '') "'$([PadJsonProbe]::TidJson(0))'"
Check 'a real tid is written' ([PadJsonProbe]::TidJson(116932) -eq ',"tid":116932') ([PadJsonProbe]::TidJson(116932))
Check 'a high DWORD is written whole' ([PadJsonProbe]::TidJson(4294967295) -eq ',"tid":4294967295') ([PadJsonProbe]::TidJson(4294967295))

Write-Host ''
Write-Host 'every watch request goes through the path that ANSWERS a refusal'
# ClarionDebuggerService.Watch refuses a name it cannot put on the line/space-split wire and sends nothing,
# so no reply can ever come and the row that asked waits for the whole session. WatchOrExplain posts the
# miss instead. A call that bypasses it re-opens that silent path, and nothing else would notice.
# EXACTLY one: -le 1 also passes at zero, i.e. it would have passed if someone deleted the call and left
# WatchOrExplain answering nothing.
$bare = [regex]::Matches($web, '_svc\.Watch\(')
Check 'exactly one _svc.Watch( call, the one inside WatchOrExplain' ($bare.Count -eq 1) "$($bare.Count) occurrence(s)"
# SendCommand is PUBLIC, so _svc.SendCommand("watch " + n) would pass a name-based check and skip the
# validation entirely. The pad drives the engine through the service's named methods, never raw commands.
$raw = [regex]::Matches($web, 'SendCommand\s*\(')
Check 'no raw SendCommand( anywhere in the bridge' ($raw.Count -eq 0) "$($raw.Count) occurrence(s)"
Check 'WatchOrExplain exists and posts a miss' ($web -match 'WatchOrExplain' -and $web -match '\\"found\\":false')
$names = [regex]::Matches($web, 'WatchOrExplain\(')
Check 'it is used by the add, the re-read and the pause broadcast' ($names.Count -eq 4) "$($names.Count) site(s) incl. its definition"

Write-Host ''
Write-Host 'breakpoint identity on the wire: two source lines that snap to ONE planted line'
# Task 05959085. The engine may snap two distinct gutter lines onto the same code record, and then they
# share one planted line while staying two logical breakpoints. Everything below runs the REAL writer from
# the engine side (Json.BpSet/BpDel out of Json.cs) into the REAL reader from the host side (ParseBpFields,
# GetIntOrNull, SameBpIdentity, BpDelMatches out of ClarionDebuggerService.cs), so the two sides can
# actually contradict each other. A fixture typed out by hand here could not.
#
# What the list mechanics below do NOT cover: the `case "bp-set"` / `case "bp-del"` arms sit inside one
# very long switch and cannot be brace-matched out, so the add/remove LOOPS are mirrored in PowerShell.
# The KEYS they use are the real methods, and the structural checks at the end of this section pin the
# real arms to those same methods so the mirror cannot drift away from the shipped call sites.

# Pull the real bodies out first: keeping the extraction out of the here-string keeps the C# shim readable.
$wireMethods = @(
  (Get-Method 'public static string Str(string s)' $engine),
  (Get-Method 'public static string BpSet(UserBreakpoint bp)' $engine),
  (Get-Method 'public static string BpDel(UserBreakpoint bp)' $engine),
  (Get-Method 'private static void AppendBpProps(StringBuilder sb, UserBreakpoint bp)' $engine)
) -join "`n"
$hostMethods = @(
  (Get-Method 'private static DebugBreakpoint ParseBpFields(string json, string module)'),
  (Get-Method 'internal static bool SameBpIdentity(DebugBreakpoint a, DebugBreakpoint b)'),
  (Get-Method 'internal static bool BpDelMatches(DebugBreakpoint b, string module, int? requestedLine, int plantedLine)'),
  (Get-Method 'private static string GetStr(string json, string key)'),
  (Get-Method 'private static int GetInt(string json, string key)'),
  (Get-Method 'private static int? GetIntOrNull(string json, string key)'),
  (Get-Method 'private static string ScanNumberToken(string json, string key)')
) -join "`n"
$bpRecord = Get-Method 'public sealed class DebugBreakpoint'

$bpTypes = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

$bpRecord

// The engine's breakpoint, cut down to the fields the real BpSet/BpDel bodies below actually touch. The
// field NAMES are asserted against DebugEngine.cs further down so this cannot quietly drift; and if the
// engine renamed one, the extracted bodies would stop compiling here rather than passing anyway.
public sealed class UserBreakpoint {
    public string Module; public int RequestedLine; public int Line;
    public readonly List<uint> Rvas = new List<uint>();
    public string Condition; public string HitMode; public int HitValue; public string Trace; public int HitCount;
}

public static class BpWire {
$($wireMethods -replace 'private static', 'public static')
}

public static class BpHost {
$($hostMethods -replace 'private static', 'public static' -replace 'internal static', 'public static')
}
"@
Add-Type -TypeDefinition $bpTypes -Language CSharp | Out-Null

function EngineBp { param($mod, $req, $line)
  $b = New-Object UserBreakpoint; $b.Module = $mod; $b.RequestedLine = $req; $b.Line = $line; $b
}
# the host's bp-set arm: parse the echo, then add-or-refresh under the real identity key
function HostBpSet { param($list, $json)
  $bp = [BpHost]::ParseBpFields($json, [BpHost]::GetStr($json, 'module'))
  foreach ($b in $list) { if ([BpHost]::SameBpIdentity($b, $bp)) { $b.Line = $bp.Line; return } }
  [void]$list.Add($bp)
}
# the host's bp-del arm: read both lines off the echo, then drop what the real predicate matches
function HostBpDel { param($list, $json)
  $mod = [BpHost]::GetStr($json, 'module')
  $planted = [BpHost]::GetInt($json, 'line')
  $req = [BpHost]::GetIntOrNull($json, 'requestedLine')
  $keep = New-Object System.Collections.ArrayList
  foreach ($b in $list) { if (-not [BpHost]::BpDelMatches($b, $mod, $req, $planted)) { [void]$keep.Add($b) } }
  , $keep
}
function Lines { param($list) (($list | ForEach-Object { "$($_.RequestedLine)->$($_.Line)" }) -join ' ') }

# requested 10 and requested 12 both snapped to record line 11
$bp10 = EngineBp 'clbrws011.clw' 10 11
$bp12 = EngineBp 'clbrws011.clw' 12 11

$rows = New-Object System.Collections.ArrayList
HostBpSet $rows ([BpWire]::BpSet($bp10))
HostBpSet $rows ([BpWire]::BpSet($bp12))
Check 'two gutter lines sharing one planted line are 2 host rows, not 1' ($rows.Count -eq 2) (Lines $rows)

# the user removes the one at source line 10; the engine echoes the breakpoint it actually dropped
$surv = HostBpDel $rows ([BpWire]::BpDel($bp10))
Check 'removing one of them leaves exactly 1 row' ($surv.Count -eq 1) (Lines $surv)
Check 'and the row left behind is the SURVIVOR, requested line 12' ($surv.Count -eq 1 -and $surv[0].RequestedLine -eq 12) (Lines $surv)
Check 'the survivor keeps the planted line it shares, 11' ($surv.Count -eq 1 -and $surv[0].Line -eq 11) (Lines $surv)

# ...and the same the other way round, so the result is not an artefact of list order
$rowsB = New-Object System.Collections.ArrayList
HostBpSet $rowsB ([BpWire]::BpSet($bp10))
HostBpSet $rowsB ([BpWire]::BpSet($bp12))
$survB = HostBpDel $rowsB ([BpWire]::BpDel($bp12))
Check 'removing the SECOND one instead leaves requested line 10' ($survB.Count -eq 1 -and $survB[0].RequestedLine -eq 10) (Lines $survB)

Write-Host ''
Write-Host 'the writer carries both lines, so a caller cannot send half an identity'
$delJson = [BpWire]::BpDel($bp10)
Check 'bp-del names the requested line the user asked for' ([BpHost]::GetIntOrNull($delJson, 'requestedLine') -eq 10) $delJson
Check 'bp-del still names the planted line as well' ([BpHost]::GetInt($delJson, 'line') -eq 11) $delJson
# The rule lives in the SIGNATURE: BpDel takes the breakpoint, so there is no bare-int overload for a
# caller to reach for and no way to emit a bp-del naming only where the engine snapped it.
Check 'BpDel takes the breakpoint, not a bare line' ($engine -match 'public static string BpDel\(UserBreakpoint bp\)' -and $engine -notmatch 'BpDel\(string module, int line\)') ''
Check 'the cut-down stub matches the real UserBreakpoint field names' ($engineSrc -match 'public int RequestedLine;\s' -and $engineSrc -match 'public int Line;\s' -and $engineSrc -match 'public string Module;\s') ''

Write-Host ''
Write-Host 'an engine that predates requestedLine still deletes something, not nothing'
# Derived from the real writer's output with the one member an older build would not have emitted taken
# back out, so the framing, module and planted line are still exactly what the engine produces today.
$legacy = $delJson -replace ',"requestedLine":\d+', ''
Check 'the legacy echo really has no requestedLine' ($legacy -notmatch 'requestedLine') $legacy
Check 'an absent requestedLine reads as absent, not as line 0' ($null -eq [BpHost]::GetIntOrNull($legacy, 'requestedLine')) ''
$legacySurv = HostBpDel $rows $legacy
Check 'the old planted-line sweep still fires, so the delete is not a no-op' ($legacySurv.Count -lt $rows.Count) (Lines $legacySurv)
# Honest about what the fallback costs: an old engine CANNOT say which of the two went, so the old
# over-broad sweep is what is left. That is the pre-existing behaviour, and it beats deleting nothing.
Check 'against an old engine both rows sharing the planted line still go (known fallback cost)' ($legacySurv.Count -eq 0) (Lines $legacySurv)
# The case that would be an outright regression: a lone breakpoint surviving its own delete.
$solo = New-Object System.Collections.ArrayList
HostBpSet $solo ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 42 44)))
$soloLegacy = ([BpWire]::BpDel((EngineBp 'clbrws011.clw' 42 44))) -replace ',"requestedLine":\d+', ''
Check 'a single breakpoint is still removed by an old engine echo' ((HostBpDel $solo $soloLegacy).Count -eq 0) ''

Write-Host ''
Write-Host 'the real handler arms use these same keys, so the mirror above cannot drift'
Check 'the bp-set arm dedupes through SameBpIdentity' ($src -match 'if \(SameBpIdentity\(b, bp\)\)') ''
Check 'the bp-del arm removes through BpDelMatches' ($src -match 'RemoveAll\(b => BpDelMatches\(b, delMod, delRequested, delLine\)\)') ''
# GetInt answers 0 for an absent field, and 0 is a real RequestedLine for an unresolved raw breakpoint,
# so reading requestedLine with GetInt would turn "old engine" into "delete the raw breakpoints".
Check 'bp-del reads requestedLine with the absent-aware reader' ($src -match 'GetIntOrNull\(json, "requestedLine"\)') ''
Check 'the old planted-line RemoveAll is gone' ($src -notmatch 'RemoveAll\(b => b\.Module == delMod && b\.Line == delLine\)') ''
# The host fix assumes the engine keeps the shared INT3 planted for the survivor. That is the ref-count in
# DebugEngine.Breakpoints.cs; this pins it structurally. It is engine behaviour, NOT exercised here.
Check 'the engine only unplants a shared INT3 when nothing else references it' ($bpSrc -match 'stillReferenced' -and $bpSrc -match 'b\.Owner == found\.Owner && b\.Rvas\.Contains\(rva\)') ''

Write-Host ''
Write-Host 'teardown: "stopped" has to be a check, not a claim'
# Task 51d2f1e4. Stop() used to discard the WaitForExit result, swallow the Kill and set Idle in a finally
# regardless, so a debugger that reported "stopped" could still own a live process. The decision table below
# is the REAL DebugSessionController.NotifyStopped, brace-matched out of the shipped file and run against a
# fake pad; Stop() itself drives a real OS process and is not reachable from here, so what this suite can say
# about it is structural, and the checks below are worded to claim only that.

$ctlMethods = @(
  (Get-Method 'public static void Register(IDebugSessionTarget target)' $ctl),
  (Get-Method 'public static void Unregister(IDebugSessionTarget target)' $ctl),
  (Get-Method 'public static void NotifyStopped(IDebugSessionTarget target)' $ctl),
  (Get-Method 'public static void SetState(IDebugSessionTarget sender, DebugControllerState state)' $ctl)
) -join "`n"

$ctlTypes = @"
using System;

$(Get-Method 'public enum DebugControllerState' $ctl)

$(Get-Method 'public interface IDebugSessionTarget' $ctl)

// A pad that answers IsSessionIdle however the test needs. It implements the REAL interface above, so if
// that interface grows a member this stub stops compiling rather than drifting.
public sealed class FakePad : IDebugSessionTarget {
    public bool Idle; public bool Throws;
    public bool IsReady { get { return true; } }
    public bool IsSessionIdle { get { if (Throws) throw new InvalidOperationException("disposed"); return Idle; } }
    public void CmdStart() { } public void CmdContinue() { } public void CmdPause() { }
    public void CmdStepOver() { } public void CmdStepInto() { } public void CmdStepOut() { }
    public void CmdStop() { } public void CmdRunToCursor(string spec) { }
}

public static class Ctl {
    private static readonly object _gate = new object();
    private static IDebugSessionTarget _target;
    private static DebugControllerState _state = DebugControllerState.Idle;
    public static DebugControllerState State { get { lock (_gate) return _state; } }
    public static void Reset() { lock (_gate) { _target = null; _state = DebugControllerState.Idle; } }
$ctlMethods
}
"@
Add-Type -TypeDefinition $ctlTypes -Language CSharp | Out-Null

function NewPad { param([bool] $idle, [bool] $throws = $false)
  $p = New-Object FakePad; $p.Idle = $idle; $p.Throws = $throws; $p
}
# put the controller in a LIVE state owned by $pad, the way a running session leaves it
function LiveSession { param($pad)
  [Ctl]::Reset(); [Ctl]::Register($pad); [Ctl]::SetState($pad, [DebugControllerState]::Running)
}

# 1. the healthy path: teardown confirmed, nothing else live -> Idle, Start re-enabled
$pad = NewPad $false
LiveSession $pad
$pad.Idle = $true                                  # Stop() confirmed the process dead and published Idle
[Ctl]::NotifyStopped($pad)
Check 'a confirmed teardown returns the controller to Idle' ([Ctl]::State -eq [DebugControllerState]::Idle) ([Ctl]::State)

# 2. THE CASE ONLY THE CALLER-SIDE GUARD CATCHES, which is why it is worth having: the closing pad's Stop()
#    could not confirm its process dead (so it still reads non-idle), AND the user has already reopened a pad,
#    which is idle and perfectly healthy. The current-target guard looks at that FRESH pad, sees idle, and
#    would re-enable Start while the old process is still alive - the close->reopen->restart race. Only
#    looking at the CALLER withholds Idle here. Deleting the caller-side guard fails this check and no other.
$dying = NewPad $false
$reopened = NewPad $true
[Ctl]::Reset(); [Ctl]::Register($dying); [Ctl]::SetState($dying, [DebugControllerState]::Running)
[Ctl]::Register($reopened)                         # user reopened the pad before teardown finished
[Ctl]::NotifyStopped($dying)                       # the old pad's Stop() returned false
Check 'a reopened pad cannot publish Idle for a teardown that never confirmed' ([Ctl]::State -ne [DebugControllerState]::Idle) ([Ctl]::State)

# 3. the same unconfirmed teardown with no reopen. Both guards cover this one, so it is a behaviour check
#    rather than a claim about either guard - it is the ordinary "Stop() failed" close.
$pad = NewPad $false
LiveSession $pad
[Ctl]::NotifyStopped($pad)                         # Stop() returned false: state never went Idle
Check 'an unconfirmed teardown leaves Start disabled on a plain close' ([Ctl]::State -ne [DebugControllerState]::Idle) ([Ctl]::State)

# 4. THE PRE-EXISTING GUARD, on its own, so #2 did not quietly kill it: the caller IS idle (its teardown
#    confirmed), and the only reason to withhold Idle is the fresh pad that is live. Deleting the
#    current-target guard fails this check.
$old = NewPad $true
$fresh = NewPad $false
[Ctl]::Reset(); [Ctl]::Register($old); [Ctl]::Register($fresh)
[Ctl]::SetState($fresh, [DebugControllerState]::Running)
[Ctl]::NotifyStopped($old)
Check 'an old teardown completing does not stomp a freshly started session' ([Ctl]::State -eq [DebugControllerState]::Running) ([Ctl]::State)

# 5. no pad registered at all: nothing can be stranded, so Idle
$gone = NewPad $true
LiveSession $gone
[Ctl]::Unregister($gone)
[Ctl]::NotifyStopped($gone)
Check 'with no registered pad left the controller drops to Idle' ([Ctl]::State -eq [DebugControllerState]::Idle) ([Ctl]::State)

# 6. a disposed pad that throws must not be read as a confirmation either way
$throwing = NewPad $false $true
LiveSession $throwing
[Ctl]::NotifyStopped($throwing)
Check 'a throwing pad is not taken as proof its session ended' ([Ctl]::State -ne [DebugControllerState]::Idle) ([Ctl]::State)

Write-Host ''
Write-Host 'Stop() answers "is it dead?" with a check (structural: it drives a real process)'
$stop = Get-Method 'public bool Stop()'
Check 'Stop reports an outcome instead of returning void' ($src -match 'public bool Stop\(\)' -and $src -notmatch 'public void Stop\(\)') ''
Check 'the teardown ends on a confirmation, not on a finally that always fires' ($stop -notmatch 'finally') ''
Check 'Idle is published only under that confirmation' ($stop -match 'if \(dead\) SetState\(DebugSessionState\.Idle\)') ''
Check 'and the unconfirmed case is reported rather than reported as Idle' ($stop -match 'else LogReceived') ''
# The old code had `try { _proc.Kill(); } catch { }` - a failed kill vanished silently and Idle went out anyway.
Check 'a failed Kill is surfaced, not swallowed by an empty catch' ($stop -notmatch 'catch \{ \}' -and $stop -match 'kill failed') ''
Check 'the WaitForExit after the Kill is bounded' ($stop -match '_proc\.WaitForExit\(3000\)') ''
# "cannot tell" is the case that used to read as success. It must read as NOT dead.
$confirm = Get-Method 'private bool ProcessConfirmedDead()'
Check 'a HasExited that throws answers NOT dead' ($confirm -match 'catch' -and $confirm -match 'return false;') ''
Check 'the confirmation is IsRunning''s own predicate, HasExited' ($confirm -match 'return p\.HasExited;') ''

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host 'ALL CHECKS PASSED'
exit 0
