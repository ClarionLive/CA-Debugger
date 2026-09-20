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
  # the two commands that carry a thread id from the PAD back toward the engine. The direction-of-flow
  # checks at the end of this file read them, because the safety of the tid writers' divergence is a claim
  # about which side may ORIGINATE a thread id, and that is decided in these two methods.
  [string] $EngineThreadsPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Threads.cs'),
  [string] $EngineVarEditPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.VarEdit.cs'),
  # the toolbar/pad controller: the teardown checks run its real NotifyStopped decision table
  [string] $ControllerPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\DebugSessionController.cs'),
  # the inbound reader and the page that builds the payloads it parses
  [string] $ReaderPath  = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\JsonMessageReader.cs'),
  [string] $PagePath    = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\debugger.html'),
  # the disassembly view: its request tags carry the epoch that decides whether a reply is still wanted
  [string] $DisasmViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Disassembly\DisassemblyView.cs'),
  # the owning image, whose one field the cut-down stub near the top of this file claims to match. A
  # PARAMETER like every other source this suite reads (Quinn-2's own finding on his wave-2 code): it was
  # a Join-Path buried at the call site, which works in place and crashes the moment the suite is run from
  # a copy in another directory - which is how he hit it while shadow-testing a handover.
  [string] $LoadedModulePath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\LoadedModule.cs'),
  # the captured host output tools/test-pad-source.js drives the page with. Regenerate with the switch below
  # after a deliberate change to SendSource; the checks at the end of this file fail while it is stale.
  [string] $HostSourceFixture = (Join-Path $PSScriptRoot 'fixtures\host-source-messages.json'),
  [switch] $UpdateHostSourceFixture
)

. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw -LiteralPath $ServicePath
$web = Get-Content -Raw -LiteralPath $WebViewPath
$engine = Get-Content -Raw -LiteralPath $EngineJsonPath
$engineSrc = Get-Content -Raw -LiteralPath $EnginePath
$bpSrc = Get-Content -Raw -LiteralPath $EngineBpPath
$engineThreadsSrc = Get-Content -Raw -LiteralPath $EngineThreadsPath
$engineVarEditSrc = Get-Content -Raw -LiteralPath $EngineVarEditPath
$ctl = Get-Content -Raw -LiteralPath $ControllerPath
$disasmView = Get-Content -Raw -LiteralPath $DisasmViewPath

# Get-Method and Set-ExtractSource come from lib-extract.ps1 (dot-sourced above); Check and ShowVal from
# lib-check.ps1, which lib-extract dot-sources in turn. Naming the right file matters here: this suite
# carried its own ShowVal until 2026-09-20, which SHADOWED the shared one and rendered absence as 'null'
# where lib-check renders '(null)' - in the one suite whose subject is JSON, where that distinction is the
# reason the shared version exists.
# This line names the text a bare Get-Method reads, which each harness used to bury in its own copy's
# `if (-not $From)` fallback.
Set-ExtractSource $src


$methods = @(
  (Get-Method 'private static string ScanNumberToken(string json, string key)'),
  (Get-Method 'private static int? GetIntOrNull(string json, string key)'),
  (Get-Method 'private static uint? GetUIntOrNull(string json, string key)'),
  (Get-Method 'private static string TidJson(uint? tid)' $web),
  (Get-Method 'private static string TidMember(string name, uint? tid)' $web)
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

Write-Host 'the event''s own tid, and nothing else''s'
$paused = '{"tid":116932,"event":"paused","reason":"breakpoint","proc":"SPLASHSCREEN","regs":{"eax":"0x0"}}'
Check 'tid first, before event, with a nested regs object' ([PadJsonProbe]::GetUIntOrNull($paused, 'tid') -eq 116932) (ShowVal ([PadJsonProbe]::GetUIntOrNull($paused, 'tid')))
$stack = '{"event":"stack","frames":[{"frame":0,"tid":1}]}'
Check 'a tid inside the frames array is not the event''s' ($null -eq [PadJsonProbe]::GetUIntOrNull($stack, 'tid')) (ShowVal ([PadJsonProbe]::GetUIntOrNull($stack, 'tid')))
$both = '{"frames":[{"tid":1}],"tid":4812}'
Check 'the top-level one wins over a nested one' ([PadJsonProbe]::GetUIntOrNull($both, 'tid') -eq 4812) (ShowVal ([PadJsonProbe]::GetUIntOrNull($both, 'tid')))
$instr = '{"value":"x \"tid\":99 y","tid":7}'
Check 'a tid inside a string VALUE is not the event''s' ([PadJsonProbe]::GetUIntOrNull($instr, 'tid') -eq 7) (ShowVal ([PadJsonProbe]::GetUIntOrNull($instr, 'tid')))

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
  Check "tid $tid survives" ($got -eq $tid) (ShowVal $got)
}
$overflow = '{"tid":4294967296}'   # past a DWORD: malformed protocol, not a thread we could select
Check 'a value past the DWORD range is refused rather than truncated' ($null -eq [PadJsonProbe]::GetUIntOrNull($overflow, 'tid')) (ShowVal ([PadJsonProbe]::GetUIntOrNull($overflow, 'tid')))
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
  (Get-Method 'private static string OwnerPath(UserBreakpoint bp)' $engine),
  (Get-Method 'public static string BpSet(UserBreakpoint bp)' $engine),
  (Get-Method 'public static string BpDel(UserBreakpoint bp)' $engine),
  (Get-Method 'public static string BpList(List<UserBreakpoint> bps)' $engine),
  (Get-Method 'private static void AppendBpProps(StringBuilder sb, UserBreakpoint bp)' $engine)
) -join "`n"
$hostMethods = @(
  (Get-Method 'private static DebugBreakpoint ParseBpFields(string json, string module)'),
  (Get-Method 'private static List<DebugBreakpoint> ParseBpList(string json)'),
  (Get-Method 'internal static bool SameBpIdentity(DebugBreakpoint a, DebugBreakpoint b)'),
  (Get-Method 'internal static bool BpDelMatches(DebugBreakpoint b, string module, int? requestedLine, int plantedLine, string ownerPath)'),
  (Get-Method 'internal static bool BpLineMatches(DebugBreakpoint b, int? requestedLine, int plantedLine)'),
  (Get-Method 'internal static bool BpOwnerMatches(string a, string b)'),
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
    public LoadedModule Owner;    // null = pending, exactly as in the engine
    public readonly List<uint> Rvas = new List<uint>();
    public string Condition; public string HitMode; public int HitValue; public string Trace; public int HitCount;
}

// The owning image, cut down to the one field the writer reads. Asserted against LoadedModule.cs below.
public sealed class LoadedModule { public string Path; }

public static class BpWire {
$($wireMethods -replace 'private static', 'public static')
}

public static class BpHost {
$($hostMethods -replace 'private static', 'public static' -replace 'internal static', 'public static')
}
"@
Add-Type -TypeDefinition $bpTypes -Language CSharp | Out-Null

function EngineBp { param($mod, $req, $line, $ownerPath)
  $b = New-Object UserBreakpoint; $b.Module = $mod; $b.RequestedLine = $req; $b.Line = $line
  if ($ownerPath) { $o = New-Object LoadedModule; $o.Path = $ownerPath; $b.Owner = $o }
  $b
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
  $owner = [BpHost]::GetStr($json, 'ownerPath')
  $keep = New-Object System.Collections.ArrayList
  foreach ($b in $list) { if (-not [BpHost]::BpDelMatches($b, $mod, $req, $planted, $owner)) { [void]$keep.Add($b) } }
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
Write-Host 'the same absent-vs-zero promise on the bp-set and bp-list paths, not only bp-del'
# bp-del has always taken this care - GetIntOrNull, plus a documented planted-line fallback for an engine
# build older than the protocol change. ParseBpFields, which is what BOTH bp-set and bp-list decode
# through, did not: it read requestedLine with GetInt, and GetInt answers 0 for an absent field. Against an
# engine that omits requestedLine EVERY parsed breakpoint in a module then held RequestedLine 0 and so
# compared EQUAL to every other one under SameBpIdentity - distinct breakpoints collapsed into a single
# host row and the pane disagreed with what the engine had armed.
#
# The legacy echoes below are derived the way the bp-del ones above are: the REAL writer's output with the
# one member an older build would not have emitted taken back out. Framing, module, planted line and every
# property are still exactly what the engine produces today.

function Legacy { param([string] $Json) $Json -replace ',"requestedLine":-?\d+', '' }

$setA = Legacy ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 10 11)))
$setB = Legacy ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 20 22)))
Check 'the legacy bp-set echoes really carry no requestedLine' (($setA -notmatch 'requestedLine') -and ($setB -notmatch 'requestedLine')) $setA
# CONTROL: the rest of the echo is intact, so a pass below cannot come from an unparseable fixture.
Check 'they still carry their module and planted line' ((([BpHost]::GetStr($setA, 'module')) -eq 'clbrws011.clw') -and ([BpHost]::GetInt($setA, 'line') -eq 11)) $setA

$legacyRows = New-Object System.Collections.ArrayList
HostBpSet $legacyRows $setA
HostBpSet $legacyRows $setB
Check 'two distinct breakpoints from an engine with no requestedLine stay 2 host rows' ($legacyRows.Count -eq 2) (Lines $legacyRows)
Check 'and each row keeps the planted line the engine reported (11 and 22)' `
  ($legacyRows.Count -eq 2 -and $legacyRows[0].Line -eq 11 -and $legacyRows[1].Line -eq 22) (Lines $legacyRows)
# The honest cost, stated the same way the bp-del fallback states its own: an engine that cannot name the
# requested line cannot tell two gutter lines that snapped to ONE record apart, so those still merge.
$sharedPlant = New-Object System.Collections.ArrayList
HostBpSet $sharedPlant (Legacy ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 10 11))))
HostBpSet $sharedPlant (Legacy ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 12 11))))
Check 'two legacy echoes that SHARE a planted line still merge (known fallback cost)' ($sharedPlant.Count -eq 1) (Lines $sharedPlant)

# 0 is a REAL requested line - an unresolved raw (--rva) breakpoint has one - which is the entire reason
# bp-del reads this field with GetIntOrNull. So an ABSENT requested line must not compare equal to a
# present 0 either. This case is what a 0/-1 sentinel would get wrong while the case above still passed.
$raw0 = [BpWire]::BpSet((EngineBp 'clbrws011.clw' 0 13))
Check 'the raw-breakpoint echo really carries a present requestedLine of 0' ([BpHost]::GetIntOrNull($raw0, 'requestedLine') -eq 0) $raw0
$mixed = New-Object System.Collections.ArrayList
HostBpSet $mixed $setA      # requestedLine ABSENT, planted 11
HostBpSet $mixed $raw0      # requestedLine 0 PRESENT, planted 13
Check 'an absent requested line is not a requested line of 0' ($mixed.Count -eq 2) (Lines $mixed)

# ...and the SAME mixed case through the OTHER predicate. SameBpIdentity was changed to read the nullable
# carrier explicitly; BpDelMatches - the function it was written to MIRROR - went on reading
# b.RequestedLine, the substituting getter that answers the PLANTED line when the requested one is absent.
# So a bp-del that names a requested line compared it against a planted one, and that is wrong in both
# directions. Both rows below are the REAL writer's output with the one member an older build would not have
# emitted taken back out, the same derivation the fixtures above use.
$legacyRow10 = Legacy ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 8 10)))   # absent requested, planted 10
Check 'CONTROL: the legacy row carries no requested line and a planted line of 10' `
  (($legacyRow10 -notmatch 'requestedLine') -and ([BpHost]::GetInt($legacyRow10, 'line') -eq 10)) $legacyRow10

# DIRECTION 1, the damaging one: a bp-del for a DIFFERENT breakpoint (requested 10, planted 12). Reading the
# substituting getter made the legacy row's planted 10 compare equal to the echo's requested 10, so the row
# vanished from the pane while its breakpoint was still armed in the engine.
$rowsFalsePos = New-Object System.Collections.ArrayList
HostBpSet $rowsFalsePos $legacyRow10
$fpSurv = HostBpDel $rowsFalsePos ([BpWire]::BpDel((EngineBp 'clbrws011.clw' 10 12)))
Check 'a bp-del naming requested 10 does NOT remove a legacy row merely PLANTED on 10' `
  ($fpSurv.Count -eq 1) (Lines $fpSurv)

# DIRECTION 2: the breakpoint the echo really does name (planted 11, as the legacy row is). With no
# requested line on the row there is nothing else to key on, so the documented planted-line fallback is what
# has to fire - the same fallback SameBpIdentity uses, and the same reason: deleting something the engine
# says it deleted beats deleting nothing.
$rowsFalseNeg = New-Object System.Collections.ArrayList
HostBpSet $rowsFalseNeg $setA                                    # absent requested, planted 11
$fnSurv = HostBpDel $rowsFalseNeg ([BpWire]::BpDel((EngineBp 'clbrws011.clw' 10 11)))
Check 'and it DOES remove the legacy row planted where the echo says it deleted (11)' `
  ($fnSurv.Count -eq 0) (Lines $fnSurv)

# ISOLATION: neither direction above may come from the predicate having stopped comparing requested lines at
# all. Both rows here HAVE requested lines, and only the named one goes.
$bothPresent = New-Object System.Collections.ArrayList
HostBpSet $bothPresent ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 10 11)))
HostBpSet $bothPresent ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 12 11)))
$bpSurv = HostBpDel $bothPresent ([BpWire]::BpDel((EngineBp 'clbrws011.clw' 10 11)))
Check 'with requested lines on BOTH sides it still removes only the one named' `
  ($bpSurv.Count -eq 1 -and $bpSurv[0].RequestedLine -eq 12) (Lines $bpSurv)

Write-Host ''
Write-Host 'bp-list decodes through the same reader, so it inherits the same promise'
$ul = New-Object 'System.Collections.Generic.List[UserBreakpoint]'
$ul.Add((EngineBp 'clbrws011.clw' 10 11))
$ul.Add((EngineBp 'clbrws011.clw' 20 22))
$legacyList = Legacy ([BpWire]::BpList($ul))
Check 'the legacy bp-list echo carries no requestedLine for either breakpoint' ($legacyList -notmatch 'requestedLine') $legacyList
$parsedList = [BpHost]::ParseBpList($legacyList)
Check 'a 2-breakpoint legacy bp-list parses as 2 entries' ($parsedList.Count -eq 2) "$($parsedList.Count) entry(ies)"
Check 'the two entries are not the same breakpoint under the identity key' `
  ($parsedList.Count -eq 2 -and -not [BpHost]::SameBpIdentity($parsedList[0], $parsedList[1])) (Lines $parsedList)
# What the pane is handed for the gutter marker. 0 would put the marker on line 0 of the file.
Check 'each entry reports the line it was planted on, never 0' `
  ($parsedList.Count -eq 2 -and $parsedList[0].RequestedLine -eq 11 -and $parsedList[1].RequestedLine -eq 22) (Lines $parsedList)

Write-Host ''
Write-Host 'and the promise is kept in the reader and the identity key themselves'
$parseBody = Get-Method 'private static DebugBreakpoint ParseBpFields(string json, string module)'
Check 'ParseBpFields preserves ABSENCE (GetIntOrNull, never GetInt, for requestedLine)' `
  (($parseBody -match 'GetIntOrNull\(json, "requestedLine"\)') -and ($parseBody -notmatch 'GetInt\(json, "requestedLine"\)')) ''
# The line rule now lives in ONE body that both predicates call, so these check it there. "Structurally
# identical by review" was a property of two bodies that happened to read alike, and the next edit to either
# one ends it silently; one body cannot drift from itself.
$lineBody = Get-Method 'internal static bool BpLineMatches(DebugBreakpoint b, int? requestedLine, int plantedLine)'
Check 'BpLineMatches falls back to the planted line when a requested line is absent' ($lineBody -match 'b\.Line == plantedLine') ''
Check 'and it compares requested lines through the nullable carrier, not the 0-defaulting accessor' `
  (($lineBody -match 'RequestedLineOrNull') -and ($lineBody -notmatch 'b\.RequestedLine ==')) ''
Check 'and it requires a requested line on BOTH sides before comparing them' `
  ($lineBody -match 'requestedLine\.HasValue && rb\.HasValue') ''
# ...and NEITHER predicate may keep a private copy of that rule, which is what would let them disagree again.
$identBody = Get-Method 'internal static bool SameBpIdentity(DebugBreakpoint a, DebugBreakpoint b)'
$delBody = Get-Method 'internal static bool BpDelMatches(DebugBreakpoint b, string module, int? requestedLine, int plantedLine, string ownerPath)'
Check 'SameBpIdentity decides the line through BpLineMatches and holds no copy of the rule' `
  (($identBody -match 'BpLineMatches\(') -and ($identBody -notmatch 'HasValue')) ''
Check 'BpDelMatches decides the line through the same one, and holds no copy either' `
  (($delBody -match 'BpLineMatches\(') -and ($delBody -notmatch 'HasValue')) ''
Check 'and both take the owner half from BpOwnerMatches' `
  (($identBody -match 'BpOwnerMatches\(') -and ($delBody -match 'BpOwnerMatches\(')) ''

Write-Host ''
Write-Host 'the real handler arms use these same keys, so the mirror above cannot drift'
Check 'the bp-set arm dedupes through SameBpIdentity' ($src -match 'if \(SameBpIdentity\(b, bp\)\)') ''
Check 'the bp-del arm removes through BpDelMatches, owner and all' ($src -match 'RemoveAll\(b => BpDelMatches\(b, delMod, delRequested, delLine, delOwner\)\)') ''
# GetInt answers 0 for an absent field, and 0 is a real RequestedLine for an unresolved raw breakpoint,
# so reading requestedLine with GetInt would turn "old engine" into "delete the raw breakpoints".
Check 'bp-del reads requestedLine with the absent-aware reader' ($src -match 'GetIntOrNull\(json, "requestedLine"\)') ''
Check 'the old planted-line RemoveAll is gone' ($src -notmatch 'RemoveAll\(b => b\.Module == delMod && b\.Line == delLine\)') ''
# The host fix assumes the engine keeps the shared INT3 planted for the survivor. That is the ref-count in
# DebugEngine.Breakpoints.cs; this pins it structurally. It is engine behaviour, NOT exercised here.
Check 'the engine only unplants a shared INT3 when nothing else references it' ($bpSrc -match 'stillReferenced' -and $bpSrc -match 'b\.Owner == found\.Owner && b\.Rvas\.Contains\(rva\)') ''

Write-Host ''
Write-Host 'a stop with no source file still TELLS the page so, instead of saying nothing'
# 87c66af6 made the page's 'paused' arm always write the location into the source header. SendSource used to
# return silently when the .clw path could not be resolved, so no `source` message followed that pause and
# the page kept the PREVIOUS stop's file, listing and highlight under the NEW stop's header - and curFile is
# load-bearing, because run-to-cursor is sent as curFile + ':' + line.
#
# The page half is covered behaviourally by tools/test-pad-source.js, which runs the real buildSource. What
# belongs here is the HOST's half: the message the page half is fed. Both were verified independently once -
# this suite counted one Post() CALL SITE and the page suite used a hand-written empty-lines message - and
# two hand-written fixtures on either side of a contract verify nothing, because they cannot contradict each
# other. A host change that put a placeholder line in that array would have shipped with both suites green.
#
# So SendSource is brace-matched out, COMPILED and RUN below, and its real output is what the page suite
# reads. The signature prefix matches the pre-fix arity too, so an older add-in fails these checks rather
# than aborting the suite.
$sendSource = Get-Method 'private void SendSource(' $web
# Named for what it checks: one call site is not the same claim as one message, and it would not catch a
# Post inside a loop. The message COUNT is asserted behaviourally further down, on both paths.
Check 'SendSource has exactly 1 Post() call site' ((([regex]::Matches($sendSource, 'Post\(')).Count) -eq 1) `
  ((([regex]::Matches($sendSource, 'Post\(')).Count).ToString() + ' Post() call(s)')
# THE RULE: no path out of SendSource that skips the message. An early `return;` is exactly how the old one
# left the page holding the last stop's listing.
Check 'and has no early return that would skip it' ($sendSource -notmatch 'return;') ''
Check 'it still reads the file when there is one' ($sendSource -match 'File\.ReadAllLines') ''
# ...and the caller hands it the module, so the message can name the stop when the path does not resolve.
Check 'the pause handler passes the module as well as the path' ($web -match 'SendSource\(p\.Module, p\.ResolvedPath, p\.Proc, p\.Line\)') ''

# ---- the shipped writer, actually run ---------------------------------------------------------------
# Post becomes a recorder, so "how many messages" and "what was in them" are answers from the real method
# rather than inferences from its text. Str comes out of the same file for the same reason.
$sendSourceStatic = $sendSource -replace 'private void SendSource', 'public static void SendSource'
$hostProbeSrc = @"
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
public static class HostSourceProbe {
  public static List<string> Posts = new List<string>();
  private static void Post(string json) { Posts.Add(json); }
  $sendSourceStatic
  $(Get-Method 'private static string Str(string s)' $web)
}
"@
Add-Type -TypeDefinition $hostProbeSrc -Language CSharp | Out-Null

# The no-source case: a module and a line, and no path that resolves.
$noSourceModule = 'clbrws026.clw'
$noSourceLine = 7
[HostSourceProbe]::Posts.Clear()
[HostSourceProbe]::SendSource($noSourceModule, $null, 'MAIN', $noSourceLine)
$noSourceCount = [HostSourceProbe]::Posts.Count
Check 'running it with no readable path posts exactly 1 message' ($noSourceCount -eq 1) `
  ("$noSourceCount message(s)")
$noSource = if ($noSourceCount -ge 1) { [HostSourceProbe]::Posts[0] } else { '' }
# THE RULE, from the writer's own output: no source means NO lines. A placeholder line here is what the page
# would render under the new stop's header, which is the whole failure 4891ed2 set out to close.
Check 'and its lines array is EMPTY, so buildSource is the only thing that can write a listing' `
  ($noSource -match '"lines":\[\]') $noSource
Check 'and `file` carries the MODULE name, the only name the stop has left' `
  ($noSource -match ('"file":"' + [regex]::Escape($noSourceModule) + '"')) $noSource
Check 'and startLine is 0 with current on the stop line' `
  ($noSource -match '"startLine":0' -and $noSource -match ('"current":' + $noSourceLine + '[,}]')) $noSource

# The with-source case, for the other half of the fixture: a real file on disk, deterministic contents so
# the captured message is reproducible.
$withSourceFile = 'clbrws011.clw'
$withSourceLine = 42
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ('host-source-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir | Out-Null
$withSource = ''
try {
  $tmpClw = Join-Path $tmpDir $withSourceFile
  Set-Content -LiteralPath $tmpClw -Encoding ASCII `
    -Value (1..60 | ForEach-Object { '  line ' + $_ + ' of ' + $withSourceFile })
  [HostSourceProbe]::Posts.Clear()
  [HostSourceProbe]::SendSource($withSourceFile, $tmpClw, 'BROWSEPUBLISHERS', $withSourceLine)
  $withCount = [HostSourceProbe]::Posts.Count
  Check 'running it with a readable .clw posts exactly 1 message too' ($withCount -eq 1) "$withCount message(s)"
  $withSource = if ($withCount -ge 1) { [HostSourceProbe]::Posts[0] } else { '' }
} finally {
  Remove-Item -Recurse -Force -LiteralPath $tmpDir -ErrorAction SilentlyContinue
}
# 25 lines centred on the stop (+/-12) is the window the page suite renders and counts.
Check 'and that message carries the 25-line window around the stop' `
  (((([regex]::Matches($withSource, '"  line ')).Count) -eq 25) -and ($withSource -match '"startLine":30')) `
  ((([regex]::Matches($withSource, '"  line ')).Count).ToString() + ' line(s)')

# ---- and the page suite is fed exactly these two strings --------------------------------------------
# This is the cross-boundary pin. tools/test-pad-source.js reads this file and hands the strings to the real
# page functions; this check says the file still holds what the shipped writer produces. Change the writer
# and this fails until the fixture is regenerated (-UpdateHostSourceFixture), and regenerating it is what
# makes the page suite see the change. Neither side can be edited into agreement on its own.
function Format-JsonString {
  param([string] $S)
  if ($S -match '[\x00-\x1f]') { throw 'a captured message contains a control character; the fixture writer would have to escape it' }
  '"' + (($S -replace '\\', '\\') -replace '"', '\"') + '"'
}
if ($UpdateHostSourceFixture) {
  $fixtureDir = Split-Path -Parent $HostSourceFixture
  if (-not (Test-Path -LiteralPath $fixtureDir)) { New-Item -ItemType Directory -Path $fixtureDir | Out-Null }
  $note = 'GENERATED by tools/test-addin-json.ps1 -UpdateHostSourceFixture from the REAL SendSource in ' +
          'src/ClarionDebugger.Addin/Terminal/ClarionDebuggerWebView.cs. Do not hand-edit: ' +
          'test-addin-json.ps1 re-runs the shipped writer and fails when these strings are not what it ' +
          'produces, and tools/test-pad-source.js feeds them to the real page functions.'
  $body = "{" + [Environment]::NewLine +
          '  "note": ' + (Format-JsonString $note) + ',' + [Environment]::NewLine +
          '  "noSource": ' + (Format-JsonString $noSource) + ',' + [Environment]::NewLine +
          '  "withSource": ' + (Format-JsonString $withSource) + [Environment]::NewLine +
          "}" + [Environment]::NewLine
  Set-Content -LiteralPath $HostSourceFixture -Value $body -Encoding ASCII -NoNewline
  Write-Host ("  ....  wrote " + $HostSourceFixture)
}
if (-not (Test-Path -LiteralPath $HostSourceFixture)) {
  Check 'the page suite fixture holds the host output captured above' $false `
    ("missing: $HostSourceFixture - regenerate with -UpdateHostSourceFixture")
} else {
  $fx = Get-Content -Raw -LiteralPath $HostSourceFixture | ConvertFrom-Json
  Check 'the page suite is fed the no-source message this writer really produces' `
    ($fx.noSource -ceq $noSource) ("fixture: " + $fx.noSource)
  Check 'and the with-source message this writer really produces' `
    ($fx.withSource -ceq $withSource) ("fixture: " + $fx.withSource)
}

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
Write-Host 'the INBOUND reader, on payloads built by the page''s own sender'
# ae5b678a stage 1. JsonVal used to search for "key": with no idea where strings start or end, and the page
# worked around that by ORDERING its payloads - untrusted content last - with the doc comment instructing
# every future payload to do the same.
#
# WHAT THAT WORKAROUND ACTUALLY BOUGHT, measured rather than assumed: against the page's real senders the
# OLD extractor reads every fixture below CORRECTLY. JSON.stringify escapes each quote in a value, so a
# procedure name carrying "line":9999 arrives as \"line\":9999 and never matches the search; and no sender
# hand-builds JSON, they all either stringify or send a delimiter-separated string. Quote injection through
# today's senders was NOT reachable. The cases the old extractor genuinely got wrong are in the next block.
#
# So this block is regression coverage, not an exploit: whatever a hostile debuggee puts in a procedure
# name, the page encodes it and the host must read back exactly what was sent. The debuggee is untrusted -
# those names come out of the target's TSWD debug info and return here when the user right-clicks a
# Procedures row - and stage 2 adds more senders to this path, which is why the order dependence goes now,
# while there are still few enough senders to check.
#
# The fixtures are not written here. They are produced by running debugger.html's REAL send() and its REAL
# breakonprocentry handler - both lifted out of the page - under node, with the page objects they touch
# stubbed. Two suites built on each side's imagination of the other cannot contradict each other, and this
# project has already shipped exactly that failure.

$page = Get-Content -Raw -LiteralPath $PagePath
$reader = Get-Content -Raw -LiteralPath $ReaderPath

# The real reader, lifted whole: ReadField is what the add-in calls, and everything it leans on comes with it.
Add-Type -Language CSharp -TypeDefinition (
  "using System;`nusing System.Globalization;`nusing System.Text;`n" +
  ((Get-Method 'internal static class JsonMessageReader' $reader) -replace 'internal static class', 'public static class')
) | Out-Null

$sendFn  = Get-Method 'function send(action,data)' $page
$handler = Get-Method "`$('miBpEntry').onclick=" $page

$js = @'
// Just enough of the page for the real handler to run.
const els = {};
function $(id){ if(!els[id]) els[id] = { classList:{remove(){},add(){}}, style:{}, dataset:{}, addEventListener(){} }; return els[id]; }
let procCtx = null, wire = null;
const wv = { postMessage(s){ wire = s; } };

'@ + $sendFn + "`n" + $handler + ";`n" + @'

// Every name here is what a HOSTILE debuggee could put in its own debug info. The page escapes them
// correctly - JSON.stringify does - so these are well-formed messages whose VALUES look like structure.
const names = [
  ['a closing brace inside the name',        'Proc}'],
  ['a quote inside the name',                'say "hi" now'],
  ['an escaped quote inside the name',       'esc \\" here'],
  ['a backslash inside the name',            'back\\slash'],
  ['a whole fake field inside the name',     'X","line":9999,"module":"EVIL.CLW'],
  ['a fake field that also closes the object', 'X"},{"line":9999'],
  ['a newline inside the name',              'two\nlines'],
  ['a brace and a quote together',           '{"line":1}'],
];

const out = [];
for (const [label, name] of names) {
  procCtx = { module: 'MAIN.CLW', line: 42, name: name };
  wire = null;
  els['miBpEntry'].onclick();
  out.push({ label, wire, name });
}

// The same real send(), with the members in an order the page does not use today. The retired rule forbade
// exactly this - untrusted content anywhere but last - so it is the case that proves the rule is gone.
wire = null;
send('breakonprocentry', JSON.stringify({ name: 'X","line":9999', module: 'MAIN.CLW', line: 42 }));
out.push({ label: 'untrusted name FIRST, which the retired field-order rule forbade', wire, name: 'X","line":9999' });

console.log(JSON.stringify(out));
'@

$jsFile = Join-Path ([System.IO.Path]::GetTempPath()) ("cajson-" + [Guid]::NewGuid().ToString('N') + ".js")
Set-Content -LiteralPath $jsFile -Value $js -Encoding UTF8
try {
  $raw = & node $jsFile 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL  could not run the page's sender under node"; $raw | ForEach-Object { Write-Host "        $_" }; $script:failures++ }
  $fixtures = $raw | ConvertFrom-Json
} finally {
  Remove-Item -LiteralPath $jsFile -ErrorAction SilentlyContinue
}

function Read1 { param($json, $key) [JsonMessageReader]::ReadField($json, $key) }

foreach ($f in $fixtures) {
  # Exactly the host's own two steps: read the envelope, then read the payload inside data.
  $action = Read1 $f.wire 'action'
  $data   = Read1 $f.wire 'data'
  $module = Read1 $data 'module'
  $line   = Read1 $data 'line'
  $name   = Read1 $data 'name'
  $ok = ($action -eq 'breakonprocentry') -and ($module -eq 'MAIN.CLW') -and ($line -eq '42') -and ($name -eq $f.name)
  Check $f.label $ok "module=$module line=$line name=$name"
}

Write-Host ''
Write-Host 'and the shapes the old extractor genuinely got wrong'
# Each of these was checked against the old JsonVal, compiled out of main; the value it returned is noted.
# These are the real gains of the swap - not the injection story, which the escaping already covered.
#
# A key that only LOOKS top-level because it sits inside a nested container. No inbound payload nests one
# today, which is exactly why this would have gone unnoticed until the first one did.
# old JsonVal returned '9'
Check 'a key inside a nested object is not the top-level one' `
  ((Read1 '{"outer":{"line":9},"line":42}' 'line') -eq '42') (Read1 '{"outer":{"line":9},"line":42}' 'line')
# old JsonVal returned '9'
Check 'a key inside an array is not the top-level one' `
  ((Read1 '{"rows":[{"line":9}],"line":42}' 'line') -eq '42') (Read1 '{"rows":[{"line":9}],"line":42}' 'line')
# old JsonVal returned '9' - a value from a different object entirely
Check 'a key that exists ONLY nested reads as absent, not as the nested value' `
  ($null -eq (Read1 '{"outer":{"line":9}}' 'line')) (Read1 '{"outer":{"line":9}}' 'line')
Check 'a brace inside a string value does not end the object' `
  ((Read1 '{"name":"a}b","line":42}' 'line') -eq '42') (Read1 '{"name":"a}b","line":42}' 'line')
Check 'an escaped quote does not end the string' `
  ((Read1 '{"name":"a\"b","line":42}' 'name') -eq 'a"b') (Read1 '{"name":"a\"b","line":42}' 'name')
Check 'a key name that is a prefix of another is not confused with it' `
  ((Read1 '{"lineNumber":9,"line":42}' 'line') -eq '42') (Read1 '{"lineNumber":9,"line":42}' 'line')
Check 'whitespace and newlines around members' `
  ((Read1 "{ `"line`" : 42 ,`n `"name`" : `"x`" }" 'line') -eq '42') ''
# old JsonVal returned 'au0042c' - it appended the escape letter and then the digits verbatim.
# AND THAT STRING IS THE CLUE TO HOW THIS CHECK WENT VACUOUS. Until 2026-09-20 the input here held a bare
# B where the escape belongs - no backslash, no u, nothing to decode - so the check asserted that an escape
# is decoded while handing the reader a plain letter. Quinn-2 proved it by disabling the reader's ENTIRE
# escape branch and watching this line stay GREEN.
# 'au0042c' is exactly what you get when the backslash is dropped and the digits pass through, which is
# the same collapse that mangled this very line twice in chat while it was being handed over. So the
# literal was most likely mangled at AUTHORING time in 011ea32 by that class of transform: a
# transmission defect with a three-month latency, not a typo. Re-landed by copying bytes, never retyping.
Check 'a \u escape is decoded' ((Read1 '{"name":"a\u0042c"}' 'name') -ceq 'aBc') (Read1 '{"name":"a\u0042c"}' 'name')

Write-Host ''
Write-Host 'absent, null and malformed all read as "not there" - and nothing throws'
# This runs on the WebView message path, where a throw kills the command outright. Every one of these used
# to be a potential exception or a wrong answer.
Check 'an absent field' ($null -eq (Read1 '{"a":1}' 'b')) ''
Check 'a JSON null' ($null -eq (Read1 '{"a":null}' 'a')) ''
Check 'null input' ($null -eq (Read1 $null 'a')) ''
Check 'empty input' ($null -eq (Read1 '' 'a')) ''
Check 'not an object at all' ($null -eq (Read1 '[1,2,3]' 'a')) ''
# old JsonVal returned 'oops' - the partial contents of a string that never closed
Check 'an unterminated string' ($null -eq (Read1 '{"a":"oops' 'a')) ''
Check 'an unterminated object' ($null -eq (Read1 '{"a":1' 'b')) ''
Check 'an unterminated nested container' ($null -eq (Read1 '{"a":{"b":1,"c":42}' 'c')) ''
Check 'a truncated \u escape' ($null -eq (Read1 '{"a":"x\u00"}' 'a')) ''
# old JsonVal returned '{"b":1' - a truncated blob a caller would have used as a string
Check 'an object VALUE is not returned as text' ($null -eq (Read1 '{"a":{"b":1}}' 'a')) (Read1 '{"a":{"b":1}}' 'a')
Check 'a number still reads as its literal text' ((Read1 '{"a":-3}' 'a') -eq '-3') (Read1 '{"a":-3}' 'a')
Check 'a bool still reads as its literal text' ((Read1 '{"a":true}' 'a') -eq 'true') (Read1 '{"a":true}' 'a')

Write-Host ''
Write-Host 'the retired rule is not lying around waiting to be followed again'
# The doc comment used to codify the field-ORDER workaround AS THE CONTRACT - "any new payload must do the
# same". That instruction is the defect propagating itself into code not yet written, so retiring it is part
# of the fix. This is the guard that keeps it retired.
$jsonVal = Get-Method 'private static string JsonVal(string json, string key)' $web
Check 'JsonVal delegates to the real reader instead of scanning' ($jsonVal -match 'JsonMessageReader\.ReadField') ''
Check 'no IndexOf scan left in JsonVal' ($jsonVal -notmatch 'IndexOf') ''
$doc = $web.Substring(0, $web.IndexOf('private static string JsonVal(string json, string key)', [StringComparison]::Ordinal))
$doc = $doc.Substring([Math]::Max(0, $doc.Length - 1600))
Check 'its doc comment no longer instructs new payloads to order their fields' `
  ($doc -notmatch 'must do the same' -and $doc -notmatch 'goes LAST') ''
Check 'and says plainly that field order no longer matters' ($doc -match '(?i)no longer .*field order|field order.*no longer|order.*irrelevant') ''

Write-Host ''
Write-Host 'breakpoint identity across TWO LOADED DLLS that each hold a same-named .clw'
# A Check's DETAIL argument is evaluated BEFORE Check runs, so an index into a list that a broken build
# left EMPTY throws and kills the suite mid-run - hiding every failure after it, in the one situation
# where those failures are what you came for. This reports the owners the list actually has.
function OwnerOf { param($list) if ($list.Count -eq 0) { '(no rows)' } else { ($list | ForEach-Object { ShowVal $_.OwnerPath }) -join ' ' } }
# Task e80072f1. `module` on the wire is a BARE BASENAME (clbrws011.clw), so in a multi-DLL app two loaded
# images can each carry a compiland of that name. Keyed on (module, requestedLine) alone those are ONE
# breakpoint: the pane shows a single row for two, the row can carry the other file's path, and one bp-del
# takes both out. The owning IMAGE is what tells them apart, and it now crosses the wire on all three
# breakpoint echoes. Everything below runs the REAL writer into the REAL reader, as the section above does.
$dll1 = 'C:\App\Dll1\dll1.dll'
$dll2 = 'C:\App\Dll2\dll2.dll'
$bpD1 = EngineBp 'clbrws011.clw' 50 50 $dll1
$bpD2 = EngineBp 'clbrws011.clw' 50 50 $dll2

# The one-of-three-paths trap, checked as three paths rather than trusted as a promise: requestedLine was
# implemented on bp-del only and shipped that way, and ownerPath has exactly the same three emitters.
$setD1 = [BpWire]::BpSet($bpD1)
$delD1 = [BpWire]::BpDel($bpD1)
$ulOwn = New-Object 'System.Collections.Generic.List[UserBreakpoint]'
$ulOwn.Add($bpD1)
$listD1 = [BpWire]::BpList($ulOwn)
$emitters = @($setD1, $delD1, $listD1)
$carrying = @($emitters | Where-Object { [BpHost]::GetStr($_, 'ownerPath') }).Count
Check 'all 3 breakpoint echoes carry ownerPath (bp-set, bp-del, bp-list)' ($carrying -eq 3) "$carrying of 3"

$dllRows = New-Object System.Collections.ArrayList
HostBpSet $dllRows $setD1
HostBpSet $dllRows ([BpWire]::BpSet($bpD2))
Check 'two DLLs holding clbrws011.clw:50 are 2 host rows, not 1' ($dllRows.Count -eq 2) (Lines $dllRows)
# ISOLATION. The 2 above must come from the OWNER differing and nothing else: same module, same requested
# line, same planted line. Give the two echoes the SAME owner and they are one breakpoint again, so a pass
# above cannot be the identity key having quietly stopped merging anything.
$sameOwner = New-Object System.Collections.ArrayList
HostBpSet $sameOwner ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 50 50 $dll1)))
HostBpSet $sameOwner ([BpWire]::BpSet((EngineBp 'clbrws011.clw' 50 50 $dll1)))
Check 'and two echoes from the SAME image at that line are still 1 row' ($sameOwner.Count -eq 1) (Lines $sameOwner)

# ...and the removal half: the "x" on one must not take the other out of the pane.
$dllSurv = HostBpDel $dllRows $delD1
Check 'removing the Dll1 breakpoint leaves exactly 1 row' ($dllSurv.Count -eq 1) (Lines $dllSurv)
Check 'and the row left behind is the Dll2 one' `
  ($dllSurv.Count -eq 1 -and $dllSurv[0].OwnerPath -match 'dll2') (OwnerOf $dllSurv)

# What the owner IS, stated so nobody later treats it as a file to open: the IMAGE path, in the wire's
# escaped form, because GetStr returns the raw JSON text and does not unescape. Both sides of every
# comparison come off that same wire, so equality is exact - but File.Exists on it would not be.
Check 'the owner reads back as the escaped wire form, an identity token rather than a usable path' `
  ($dllRows.Count -ge 1 -and $dllRows[0].OwnerPath -eq 'C:\\App\\Dll1\\dll1.dll') (OwnerOf $dllRows)

Write-Host ''
Write-Host 'an engine that predates ownerPath behaves EXACTLY as it did before, on every path that reads it'
# Derived the way every legacy echo in this file is: the REAL writer's output with the one member an older
# build would not have emitted taken back out. Module, both lines and every property are untouched.
function LegacyOwner { param([string] $Json) $Json -replace ',"ownerPath":("[^"]*"|null)', '' }

$legacySetD1 = LegacyOwner $setD1
$legacySetD2 = LegacyOwner ([BpWire]::BpSet($bpD2))
Check 'the legacy bp-set echoes really carry no ownerPath' `
  (($legacySetD1 -notmatch 'ownerPath') -and ($legacySetD2 -notmatch 'ownerPath')) $legacySetD1
# CONTROL: the rest of the echo survived the derivation, so a pass below is not an unparseable fixture.
Check 'they still carry module, requested line and planted line' `
  ((([BpHost]::GetStr($legacySetD1, 'module')) -eq 'clbrws011.clw') -and `
   ([BpHost]::GetIntOrNull($legacySetD1, 'requestedLine') -eq 50) -and ([BpHost]::GetInt($legacySetD1, 'line') -eq 50)) $legacySetD1
Check 'an absent ownerPath reads as absent, not as an empty owner' ($null -eq [BpHost]::GetStr($legacySetD1, 'ownerPath')) ''

$legacyDllRows = New-Object System.Collections.ArrayList
HostBpSet $legacyDllRows $legacySetD1
HostBpSet $legacyDllRows $legacySetD2
# The honest cost, stated the way the requestedLine fallback states its own: an engine that cannot name the
# owning image cannot tell the two DLLs apart, so they merge - which is TODAY's behaviour, unchanged. What
# matters is that it is today's behaviour and not a new failure.
Check 'two legacy echoes from two DLLs still merge into 1 row (known fallback cost, = old behaviour)' `
  ($legacyDllRows.Count -eq 1) (Lines $legacyDllRows)
# The outright regression this fallback exists to prevent: a delete that matches nothing at all.
$legacySolo = New-Object System.Collections.ArrayList
HostBpSet $legacySolo $legacySetD1
Check 'a legacy bp-del still removes the legacy row, rather than becoming a no-op' `
  ((HostBpDel $legacySolo (LegacyOwner $delD1)).Count -eq 0) ''
# ...and the MIXED case, which is what a 0/"" sentinel would get wrong while both cases above still passed:
# a host row with no owner (legacy, or host-built) against an echo that names one. Unknown matches anything,
# so the delete still lands - the alternative is a new host silently matching nothing an old engine says.
$mixedOwner = New-Object System.Collections.ArrayList
HostBpSet $mixedOwner $legacySetD1
Check 'an owner-bearing bp-del still removes a row whose owner is unknown' `
  ((HostBpDel $mixedOwner $delD1).Count -eq 0) ''
# A still-PENDING breakpoint is the same shape and is not derived at all: the real writer emits JSON null
# for it, because no image carries its compiland yet.
$pendingSet = [BpWire]::BpSet((EngineBp 'clbrws011.clw' 50 50))
Check 'a pending breakpoint writes ownerPath as JSON null, which reads as unknown too' `
  (($pendingSet -match '"ownerPath":null') -and ($null -eq [BpHost]::GetStr($pendingSet, 'ownerPath'))) $pendingSet

Write-Host ''
Write-Host 'the two identity predicates AGREE - enumerated, not asserted'
# SameBpIdentity and BpDelMatches were structurally identical by review in wave 1. That is a property of two
# bodies that happen to read alike, and it ends the moment either one is edited - which is what this ticket
# does to both. They now share their two halves, and this enumerates the space to prove the sharing holds:
# for every pair, "is b already in the list?" must answer the same as "does b's bp-del remove a?".
$mods = @('clbrws011.clw', 'other.clw')
$reqs = @($null, 0, 10, 11)
$lines = @(10, 11)
$owners = @($null, $dll1, $dll2)
$space = New-Object System.Collections.ArrayList
foreach ($m in $mods) { foreach ($r in $reqs) { foreach ($l in $lines) { foreach ($o in $owners) {
  $b = New-Object DebugBreakpoint
  $b.Module = $m; $b.RequestedLineOrNull = $r; $b.Line = $l; $b.OwnerPath = $o
  [void]$space.Add($b)
} } } }
$pairs = 0; $agree = 0; $trueCount = 0; $asym = 0
foreach ($a in $space) { foreach ($b in $space) {
  $pairs++
  $ident = [BpHost]::SameBpIdentity($a, $b)
  $del   = [BpHost]::BpDelMatches($a, $b.Module, $b.RequestedLineOrNull, $b.Line, $b.OwnerPath)
  if ($ident -eq $del) { $agree++ }
  if ($ident) { $trueCount++ }
  if ($ident -ne [BpHost]::SameBpIdentity($b, $a)) { $asym++ }
} }
Check "all $pairs (a,b) pairs answer the same under both predicates" ($agree -eq $pairs) "$agree of $pairs agreed"
# NOT VACUOUS: a predicate that answered false for everything would agree with itself perfectly. Both
# outcomes have to occur, and the count is checkable rather than "some".
Check 'and the space actually reaches both answers, so agreement is not two constant falses' `
  ($trueCount -gt 0 -and $trueCount -lt $pairs) "$trueCount of $pairs matched"
# Identity is used as a dedupe key in a loop over an unordered list, so it must not depend on which entry
# the loop reached first.
Check 'SameBpIdentity is symmetric, so a dedupe cannot depend on list order' ($asym -eq 0) "$asym asymmetric pair(s)"

# The cut-down engine stub gained an Owner; pin the field names it borrows, as the section above does for
# the line fields, so a rename in the engine fails here instead of passing against a stale imitation.
$lm = Get-Content -Raw -LiteralPath $LoadedModulePath
Check 'the cut-down stubs match the real UserBreakpoint.Owner and LoadedModule.Path' `
  (($engineSrc -match 'public LoadedModule Owner;') -and ($lm -match 'public string Path;')) ''
# ONE writer for the owner on all three echoes, so a fourth emitter cannot carry it on some and not others.
$ownerBody = Get-Method 'private static string OwnerPath(UserBreakpoint bp)' $engine
Check 'the engine writes the owner from one function that treats a pending breakpoint as null' `
  ($ownerBody -match 'bp\.Owner == null') ''
Check 'and no breakpoint echo hand-writes the member instead' `
  ((([regex]::Matches($engine, '\\"ownerPath\\":')).Count) -eq 3) `
  ((([regex]::Matches($engine, '\\"ownerPath\\":')).Count).ToString() + ' site(s), all 3 via OwnerPath(bp)')
# The host reads it in the ONE place bp-set and bp-list share, which is what keeps the promise off the
# one-of-three path requestedLine took.
Check 'the host reads ownerPath in ParseBpFields, the single decoder both bp-set and bp-list use' `
  ($parseBody -match 'GetStr\(json, "ownerPath"\)') ''
Check 'and the bp-del arm reads it too, rather than leaving that path owner-blind' `
  ($src -match 'GetStr\(json, "ownerPath"\)') ''

Write-Host ''
Write-Host 'the host says "unknown thread" by leaving the member out, whatever the member is called'
# Task 3b043dfc, host half. The `threads` message carries three thread-id-valued members - a per-row `tid`
# plus a top-level `stopped` and `selected` - and only the one CALLED tid went through a writer. The other
# two were appended unconditionally, so an unknown id went out as "thread 0", which downstream reads as a
# real thread. All three now go through TidMember.
Check 'an unknown stopped writes no member at all' ([PadJsonProbe]::TidMember('stopped', $null) -eq '') "'$([PadJsonProbe]::TidMember('stopped', $null))'"
Check 'a 0 is a sentinel for selected as much as for tid - written as absent too' `
  ([PadJsonProbe]::TidMember('selected', 0) -eq '') "'$([PadJsonProbe]::TidMember('selected', 0))'"
Check 'a known stopped is written under its own name' `
  ([PadJsonProbe]::TidMember('stopped', 116932) -eq ',"stopped":116932') ([PadJsonProbe]::TidMember('stopped', 116932))
Check 'and TidJson is that same writer, not a second copy of the rule' `
  ((Get-Method 'private static string TidJson(uint? tid)' $web) -match 'TidMember\("tid", tid\)') ''
# ALL THREE, counted rather than asserted as "every": a fourth member added without the writer is what the
# count catches. The per-row tid is written inline in OnThreads and is the third.
$onThreads = Get-Method 'private void OnThreads(DebugThreadList list)' $web
Check 'both top-level thread-id members in OnThreads go through it' `
  ((([regex]::Matches($onThreads, 'TidMember\(')).Count) -eq 2) `
  ((([regex]::Matches($onThreads, 'TidMember\(')).Count).ToString() + ' of 2')
Check 'and neither is appended as a bare number any more' `
  (($onThreads -notmatch '\\"stopped\\":\\"\).Append\(list') -and ($onThreads -notmatch 'Append\(list\.StoppedTid\)')) ''
# The reader half: absent must survive arrival. Substituting 0u on the way in undoes the wire rule in the
# one place a host can undo it unilaterally, and no writer discipline downstream can get it back.
$parseThreads = Get-Method 'private static DebugThreadList ParseThreads(string json)'
Check 'ParseThreads keeps an absent stopped/selected absent, with no 0 substituted on arrival' `
  (($parseThreads -match 'GetUIntOrNull\(head, "stopped"\)') -and ($parseThreads -notmatch 'GetUIntOrNull\(head, "stopped"\) \?\? 0u') -and `
   ($parseThreads -match 'GetUIntOrNull\(head, "selected"\)') -and ($parseThreads -notmatch 'GetUIntOrNull\(head, "selected"\) \?\? 0u')) ''
Check 'and the list carries them as nullable, so "unknown" has somewhere to live' `
  ((Get-Method 'public sealed class DebugThreadList') -match 'public uint\? StoppedTid;') ''
Write-Host ''
Write-Host 'the two tid writers disagree about one value, and this is the direction of flow that makes it safe'
#
# TICKET 3b043dfc, HOLE 3. The engine's writer treats uint.MaxValue as UNKNOWN - it is the (uint)-1 an int
# cast produces, and the protocol names -1 forbidden - and omits the member. The add-in's TidJson does not:
# it writes a high DWORD whole, which the check above asserts and which still passes. Two writers on one
# wire holding two different rules.
#
# THE QUESTION IS NOT "WHICH VALUE IS RIGHT". It is WHICH SIDE MAY ORIGINATE A THREAD ID, because that is
# what decides whether the permissive writer is ever the one a bad value meets first. The answer, read off
# the code below rather than asserted:
#
#   THE ENGINE IS THE SOLE ORIGINATOR. Every thread id in this system came out of a Win32 debug event the
#   engine received. The host and the page only ever ECHO one back: the page sends `selectthread` with a
#   tid it took from a row the engine sent, and `setval` with the tid the row was read on.
#
#   AND BOTH ECHO PATHS FAIL CLOSED AT THE ENGINE. `thread <tid>` is refused unless the tid is in the
#   engine's own live thread set, and `setval`'s trailing tid must equal the selected one or the write is
#   refused rather than applied to another thread's memory. So a tid the page invents cannot become a
#   selection and cannot steer a write - it can only produce a refusal.
#
# THE DIVERGENCE IS THEREFORE SAFE TODAY, and safe for a reason that is CHECKABLE rather than a fact about
# nobody having written the feature yet: TidJson can only be handed a tid that arrived from the engine, and
# the engine cannot emit uint.MaxValue. The load-bearing assertion is that second clause, so it is the one
# made here, against the engine's own predicate. If TidIsKnown ever stops rejecting uint.MaxValue, the
# add-in's permissiveness becomes live on the same day, and this fails on that day rather than later.
#
# THE DECISION, stated so the next person does not have to re-derive it: the add-in writer SHOULD adopt the
# engine's rule and treat uint.MaxValue as unknown too. Not because a 0xFFFFFFFF thread id is likely, but
# because the alternative makes one writer's correctness depend on a property of the OTHER side plus the
# absence of a feature - which is the exact "safe by construction, not by guard" shape this ticket exists
# to remove, and leaving it in place while fixing the engine's version of it would be inconsistent. It is
# one clause in TidJson. It is NOT made here because ClarionDebuggerWebView.cs belongs to another helper
# this wave; it is recorded on 3b043dfc for them, and the assertions below pin the current state exactly so
# the change shows up as a deliberate edit to this file rather than a silent drift.
#
# IF YOU ARE ADDING A PAD-ORIGINATED TID PATH - a tid typed into a box, restored from a saved session,
# computed from an int that could go negative - THE RULES INVERT AND THIS SECTION IS THE ASSUMPTION YOU
# ARE BREAKING. The add-in becomes the writer on the permissive side of a boundary it was never told it
# was on. Make TidJson adopt the rule first.

# Check prints its Detail on a PASS as well as a FAIL, so a consequence spelled out as Detail would read
# like something that HAD happened. These consequences are worth spelling out, so they are attached only
# when the check is actually failing.
function CheckWhy {
  param([string] $Label, [bool] $Ok, [string] $Why)
  Check $Label $Ok $(if ($Ok) { '' } else { $Why })
}

$tidIsKnown = Get-CSharpStatement 'private static bool TidIsKnown(uint tid)' $engineSrc
Check 'the engine still has one predicate deciding whether a tid is known' ($null -ne $tidIsKnown) ''
# The precondition the divergence rests on. Read as text because TidIsKnown is not reachable from here,
# and named rather than pattern-guessed so a rewrite that drops the clause cannot pass by looking similar.
CheckWhy 'THE PRECONDITION: the engine cannot originate uint.MaxValue, so TidJson never meets one' `
  ($null -ne $tidIsKnown -and $tidIsKnown -match 'uint\.MaxValue') `
  'TidIsKnown no longer rejects uint.MaxValue - the add-in writer is NOW the permissive side of a live boundary and must adopt the rule (3b043dfc hole 3)'
CheckWhy 'and it still rejects 0, which is the half both writers already agree on' `
  ($null -ne $tidIsKnown -and $tidIsKnown -match 'tid\s*!=\s*0') `
  'the engine writer no longer treats 0 as unknown - the rule the whole protocol rests on is gone'

# The divergence itself, pinned. This asserts CURRENT behaviour on purpose: it is the "documented" half of
# the decision above, and it names its own successor so nobody reads it as approval.
CheckWhy 'the divergence, stated: TidJson writes uint.MaxValue whole where the engine would omit it' `
  ([PadJsonProbe]::TidJson(4294967295) -eq ',"tid":4294967295') `
  'TidJson has adopted the engine rule - good; delete this check and update the note above, on 3b043dfc'
CheckWhy 'the two writers DO agree on 0, so this is a one-value divergence and not two rules' `
  ([PadJsonProbe]::TidJson(0) -eq '') `
  'TidJson now writes a 0 - the page would read it as a real thread and start dropping good replies'

# The echo paths, fail-closed, read off the engine. These are what make "the engine is the sole
# originator" a property of the code rather than a description of current habits.
$selCmd = Get-CSharpBlock 'private void HandleThreadSelectCommand(' $engineThreadsSrc
Check 'the engine still owns thread selection' ($null -ne $selCmd) ''
CheckWhy 'a pad-sent tid must be one the ENGINE knows is live, or the selection is refused' `
  ($null -ne $selCmd -and $selCmd -match '_threads\.Contains\(\s*tid\s*\)') `
  'HandleThreadSelectCommand no longer validates against the engine live thread set - the page can now name a thread the engine never offered, so it ORIGINATES one'
$setVal = Get-CSharpBlock 'private void HandleSetValCommand(' $engineVarEditSrc
Check 'the engine still owns the edit-write thread check' ($null -ne $setVal) ''
CheckWhy 'a pad-sent tid on a WRITE must equal the selected thread, or the write is refused' `
  ($null -ne $setVal -and $setVal -match 'wantTid\s*!=\s*selectedTid') `
  'HandleSetValCommand no longer compares the requested thread with the selected one - a stale edit could write another thread''s memory in the user''s own program'
# And the host's own send-side gate, so "echo only" is not resting on the engine alone.
$svcSelect = Get-Method 'public bool SelectThread(uint tid)'
CheckWhy 'the host refuses to forward a 0 as a thread selection' ($svcSelect -match 'tid\s*>\s*0') `
  'SelectThread would now send `thread 0` - the engine refuses it, but the host stopped holding its own half of the rule'
Write-Host ''
Write-Host 'a member with NO value at all is decided by the loop, and the loop always ends'
# ec45805f item 4. A "did the value scan advance?" guard used to sit between ReadValue and the malformed
# check: `if (i <= before && i >= json.Length) return null;`. It could not fire - ReadValue sets i = -1
# when i is already at or past the end, so `i >= json.Length` needs a scan that advanced to exactly the
# end, which contradicts `i <= before`. Verified as well as reasoned: the shipped reader was compiled
# twice, once with that line instrumented and once with it removed, and fuzzed over 1.8M calls; the guard
# never fired and the two builds never disagreed. It is gone.
#
# What was NOT covered here is the input that made it look necessary: a member whose value is empty, so
# the number scan stops where it started. These pin the cases the removed line appeared to be about -
# the answer, and that the loop TERMINATES rather than spinning on a value that never advances.
Check 'an empty value reads as absent, and the members after it still read' `
  (($null -eq (Read1 '{"a":,"b":1}' 'a')) -and ((Read1 '{"a":,"b":1}' 'b') -eq '1')) `
  ("a=" + (Read1 '{"a":,"b":1}' 'a') + " b=" + (Read1 '{"a":,"b":1}' 'b'))
Check 'an empty value as the LAST member reads as absent' ($null -eq (Read1 '{"a":}' 'a')) ''
Check 'a stray closing bracket where a value belongs stops the walk' ($null -eq (Read1 '{"a":]}' 'b')) ''
Check 'whitespace where a value belongs is still no value' ($null -eq (Read1 '{"a": ,"b":2}' 'a')) ''
Check '...and the member after THAT one is still found' ((Read1 '{"a": ,"b":2}' 'b') -eq '2') (Read1 '{"a": ,"b":2}' 'b')
# The removed guard's only plausible job was ending a loop that cannot advance, so termination is the
# part worth sweeping. Every shape here asks for a key that is NOT present, which is the case that walks
# the whole object instead of returning at the first match.
#
# STATED PLAINLY: this detects a walk that ends in the wrong PLACE, not one that never ends. A reader
# that truly spins hangs this suite rather than failing it - and hangs the WebView message pump in the
# product, which is worse. A bounded join was tried and is not worth its machinery here: PowerShell
# cannot hand a script block to a foreign thread with no runspace, and the four checks above already
# return from the value-less shapes that could reach the loop at all.
$sweep = @('{"a":,"b":1}', '{"a":}', '{"a":]}', '{"a": }', '{"a":,}', '{"a":,,}', '{"a":', '{"a":-}')
$walked = 0
foreach ($s in $sweep) { [void](Read1 $s 'zzz'); $walked++ }
Check "every value-less shape finishes its walk and reports absence ($walked shapes)" `
  (($walked -eq $sweep.Count) -and -not ($sweep | Where-Object { $null -ne (Read1 $_ 'zzz') })) ''
Write-Host ''
Write-Host 'the Disassembly view keeps THREE tag-keyed requests in flight, and a tag is not a thread'
# The view asks for a window (win), a forward extension (winf) and a backward one (winb), each keyed only
# by its kind. Across a thread switch that is not enough to tell a reply asked for BEFORE the switch from
# one asked for after: same kind, same shape, different thread. The tag now carries the EPOCH that asked,
# and the engine echoes a tag verbatim, so the match is made with no protocol change.
#
# What a stale reply actually costs is narrower than "the wrong code" — instruction bytes are process
# memory, shared by every thread. It re-seats the window on a thread you are no longer viewing and flags
# that thread's instruction as current. Still wrong, and silent.
$fmtTag = Get-Method 'private static string FormatTag(string kind, int epoch)' $disasmView
$parseTag = Get-Method 'private static bool ParseTag(string tag, out string kind, out int epoch)' $disasmView
$tidMatch = Get-Method 'private static bool TidMatches(uint? tid, uint selTid)' $disasmView
# TidMatches now READS the view's single uint? -> uint conversion instead of restating the rule, so the
# probe needs it too. That is the POINT of the change (Owen2, 6505439): the view had four conversions
# under two disagreeing definitions of "unstamped", and `tid ?? _selTid` seated a literal 0 while the gate
# treated 0 as a sentinel - so the view was never marked painted. One definition now, read by both.
$tidOf = Get-Method 'private static uint TidOf(uint? t)' $disasmView
$tagShim = @"
using System;
using System.Globalization;
public static class DisasmTagProbe {
  public const string WinTag = "win";
  public const string FwdTag = "winf";
  public const string BwdTag = "winb";
$(($fmtTag, $parseTag, $tidMatch, $tidOf -join "`n") -replace 'private static', 'public static')
}
"@
Add-Type -TypeDefinition $tagShim -Language CSharp | Out-Null

# CONTROL FIRST: a gate that rejected everything would pass every rejection below for the wrong reason.
foreach ($kind in 'win', 'winf', 'winb') {
  $k = ''; $e = 0
  $tag = [DisasmTagProbe]::FormatTag($kind, 7)
  $ok = [DisasmTagProbe]::ParseTag($tag, [ref] $k, [ref] $e)
  Check "control: a $kind tag this view built round-trips" ($ok -and $k -eq $kind -and $e -eq 7) "$tag -> kind=$k epoch=$e"
}

# THE RULE: a reply from a superseded epoch is distinguishable, which is the whole gate.
$k = ''; $e = 0
[DisasmTagProbe]::ParseTag([DisasmTagProbe]::FormatTag('winf', 3), [ref] $k, [ref] $e) | Out-Null
Check 'a winf asked for under epoch 3 does not read as the current epoch 4' ($e -ne 4) "epoch=$e"
Check 'and it is still recognised as OURS, so it is dropped deliberately rather than ignored as foreign' ($k -eq 'winf') "kind=$k"

# A BARE kind is the OLD format. It carries no epoch, so it cannot be shown to belong to the thread on
# screen — rejecting it is the safe reading, and it is what an engine replaying an old tag would send.
foreach ($bare in 'win', 'winf', 'winb') {
  $k = ''; $e = 0
  Check "a bare '$bare' tag with no epoch is not accepted" (-not [DisasmTagProbe]::ParseTag($bare, [ref] $k, [ref] $e)) ''
}
foreach ($bad in 'other#1', '#4', 'win#', 'win#x', 'winx#1', '', 'win#1#2') {
  $k = ''; $e = 0
  $got = [DisasmTagProbe]::ParseTag($bad, [ref] $k, [ref] $e)
  Check "a malformed or foreign tag '$bad' is not ours" (-not $got) ''
}

# THE POSITIONAL HAZARD: RequestDisasmAt sends the tag in its own space-separated slot, ahead of `before`.
# A tag containing a space would push `before` into the wrong argument and silently change the request.
foreach ($kind in 'win', 'winf', 'winb') {
  $tag = [DisasmTagProbe]::FormatTag($kind, 12345)
  Check "a $kind tag never contains a space" (-not $tag.Contains(' ')) $tag
}

# The engine echoes the tag through Json.Str, so a tag needing JSON escaping would survive but is a smell.
$tag = [DisasmTagProbe]::FormatTag('win', 0)
Check 'a tag needs no JSON escaping' ($tag -notmatch '["\\]') $tag

Write-Host ''
Write-Host 'and the view really uses that tag everywhere, so no request can escape the gate'
# A single RequestDisasmAt left sending a bare constant would be a hole the round-trip checks cannot see.
# Per LINE, not per regex-across-arguments: a nested HexVa(...) closes a paren before the tag does, so an
# [^)]* scan silently stops early and undercounts. That is how this check first passed at 3 of 7.
$callLines = @($disasmView -split "`n" | Where-Object { $_ -match 'RequestDisasmAt\(' })
$viaMakeTag = @($callLines | Where-Object { $_ -match 'MakeTag\(' })
$bareTag = @($callLines | Where-Object { $_ -match ',\s*(WinTag|FwdTag|BwdTag)\s*[,)]' })
# RUN 2 (Owen2): the absolute count was 7 and is now 6 - the two blind late-open seats (OnHandleCreated,
# OnActiveChanged) were consolidated into SeatOnLateOpen. A magic number breaks on every legitimate
# refactor while saying nothing about what actually matters, which is that no request escapes the gate and
# no seat is made blind. Both of those are pinned by the checks that follow, so this one only has to
# establish that there is something to check at all.
Check 'the view still issues disasm requests at all' ($callLines.Count -ge 1) "$($callLines.Count) call site(s)"
Check 'no RequestDisasmAt still passes a bare tag constant' ($bareTag.Count -eq 0) "$($bareTag.Count) bare call(s)"
Check 'every disasm request goes out through MakeTag' ($viaMakeTag.Count -eq $callLines.Count) "$($viaMakeTag.Count) of $($callLines.Count)"

# THE LATE-OPEN SEAT MUST ASK WHOSE THREAD IT IS (Owen2, run-2 item 1). `_svc.CurrentVa` is the STOPPED
# thread's address while the engine decodes the SELECTED one, so seating there blind paints one thread's
# address range labelled as another's, with no current row and no banner. The inventory is the only thing
# that reports a selection made before this view existed - and nothing used to request it, so the
# "window-opened-late" case the code documented was unreachable.
$lateOpen = Get-Method 'private void SeatOnLateOpen()' $disasmView
Check 'the late-open seat asks for the thread inventory' ($lateOpen -match 'RequestThreads') ''
# ...and neither entry point may seat on its own again, which is what stops the blind seat coming back.
$onHandle = Get-Method 'protected override void OnHandleCreated(EventArgs e)' $disasmView
$onActive = Get-Method 'private void OnActiveChanged()' $disasmView
Check 'OnHandleCreated seats only through SeatOnLateOpen' `
  (($onHandle -match 'SeatOnLateOpen') -and ($onHandle -notmatch 'RequestDisasmAt')) ''
Check 'OnActiveChanged seats only through SeatOnLateOpen' `
  (($onActive -match 'SeatOnLateOpen') -and ($onActive -notmatch 'RequestDisasmAt')) ''
# BOTH epoch checks, counted — not merely "one is present". OnDisasm tests the epoch TWICE on purpose:
# once on the reader thread, and again INSIDE the UI marshal, because the epoch can move between the two
# and that is precisely the window a thread switch lands in. A `-match` here passed while the inner check
# was deleted, because the outer one still satisfied it: the check claimed "gates on the epoch" and only
# verified half of what that means. Found by mutation, and the count is the fix.
$onDisasm = Get-Method 'private void OnDisasm(string tag, List<DebugDisasmInstr> instrs, uint? tid)' $disasmView
$epochGates = [regex]::Matches($onDisasm, 'epoch\s*!=\s*_epoch')
Check 'OnDisasm gates on the epoch on BOTH sides of the UI marshal' ($epochGates.Count -eq 2) "$($epochGates.Count) epoch gate(s)"
# ...and the marshal-side gates really are inside the lambda, not stacked ahead of it.
$marshalBody = if ($onDisasm -match '(?s)UI\(\(\)\s*=>\s*\{(.*)') { $Matches[1] } else { '' }
Check 'the second epoch gate is INSIDE the marshal, where the race is' `
  ($marshalBody -match 'epoch\s*!=\s*_epoch') ''
Check 'and the tid gate is inside it too, on the same side of the race' `
  ($marshalBody -match 'TidMatchesView\(tid\)') ''
# The pending flags are cleared by NewEpoch, not by the replies: the dropped ones never arrive to clear
# them, and a stuck _pendFwd would freeze forward extension for the rest of the session.
Check 'NewEpoch clears the in-flight flags as well as retiring the replies' `
  ((Get-Method 'private void NewEpoch()' $disasmView) -match '_pendFwd\s*=\s*_pendBwd\s*=\s*false') ''

Write-Host ''
Write-Host 'TWO gates, and each is asserted with the OTHER one intact'
# The epoch answers "is this reply still wanted"; the tid answers "whose code is this". They are not
# redundant: the tid catches a reply decoded for a thread we did not expect even when nothing superseded
# it, and the epoch catches a superseded reply even when the engine would have decoded the same thread
# either side of the move. A reply must pass BOTH, and neither overrides the other — if they disagree,
# the only safe reading of "one of my two checks says this is not what I think it is" is to not paint it.
#
# Isolating each matters, because a second gate that never decides anything is exactly the dead guard
# deleted earlier in this ticket. These cases are constructed so that ONE gate is the sole decider.

# --- the TID gate alone: same epoch throughout, so the epoch gate can never be what dropped anything ---
$k = ''; $e = 0
$sameEpochTag = [DisasmTagProbe]::FormatTag('win', 9)
[DisasmTagProbe]::ParseTag($sameEpochTag, [ref] $k, [ref] $e) | Out-Null
Check 'isolating the tid gate: the epoch is current, so only the tid can decide' ($e -eq 9) "epoch=$e"
Check 'a reply stamped for ANOTHER thread is dropped though its epoch is current' `
  (-not [DisasmTagProbe]::TidMatches([uint] 4812, [uint] 116932)) 'reply tid 4812, view on 116932'
Check 'CONTROL: the same reply stamped for the thread on screen is accepted' `
  ([DisasmTagProbe]::TidMatches([uint] 116932, [uint] 116932)) 'reply tid 116932, view on 116932'

# --- the EPOCH gate alone: tid identical on both, so the tid gate can never be what dropped anything ---
Check 'isolating the epoch gate: the tid matches, so only the epoch can decide' `
  ([DisasmTagProbe]::TidMatches([uint] 116932, [uint] 116932)) ''
$k2 = ''; $e2 = 0
[DisasmTagProbe]::ParseTag([DisasmTagProbe]::FormatTag('winf', 5), [ref] $k2, [ref] $e2) | Out-Null
Check 'a superseded reply is dropped though it names the RIGHT thread' ($e2 -ne 6) "asked under 5, now 6"
# This is the case the tid gate provably cannot see, and the reason the epoch is not redundant: a thread
# switch away and back leaves the tid matching again, while the in-flight winf is still stale.
Check 'and that holds even when the selection returned to the SAME thread meanwhile' `
  (($e2 -ne 6) -and [DisasmTagProbe]::TidMatches([uint] 116932, [uint] 116932)) 'tid agrees, epoch does not'

# --- absent is UNKNOWN, not a mismatch: an engine that does not stamp disasm still works ---
Check 'an UNSTAMPED reply is not treated as a mismatch (pre-381aabd7 engine keeps working)' `
  ([DisasmTagProbe]::TidMatches($null, [uint] 116932)) 'tid=null'
Check 'a 0 tid is a sentinel, not thread 0, so it is not a mismatch either' `
  ([DisasmTagProbe]::TidMatches([uint] 0, [uint] 116932)) 'tid=0'
# ONE definition of "unstamped", now that TidMatches reads TidOf instead of restating the rule (Owen2,
# 6505439). The view had FOUR uint? -> uint conversions under two disagreeing definitions: the gate treated
# a stamped literal 0 as a sentinel while the seat assignment `tid ?? _selTid` seated it as thread 0, so
# the view was never marked painted.
#
# WHAT THESE TWO DO AND DO NOT COVER. Stated from mutations that were RUN, because an earlier version of
# this note generalised from the single mutation the handover supplied and understated its own coverage -
# a limitation note that overstates the limitation talks the next reader out of a probe that works, which
# is the same species of error as one that overstates the coverage.
# Measured against TidOf's two halves separately:
#   `return t ?? 0u;`                  (the suggested mutation)  does NOT red - EXACTLY EQUIVALENT to the
#                                      shipped body over null/0/1/4812/uint.MaxValue.
#   `return t == null ? 0u : t.Value;` (zero clause dropped)     does NOT red - unwrapping 0 gives 0 for
#                                      free, so the 0-is-a-sentinel half is not falsifiable HERE.
#   `return t == null ? 1u : t.Value;` (null arm changed)        DOES red. The null arm is load-bearing.
# So these two are not merely a contract restatement: they discriminate on the null arm. What they cannot
# see is the zero half - and that is the half the defect turned on, because the disagreement was between
# TidOf and callers writing `tid ?? _selTid`. Hence the third check below, which pins the CALL SITES.
Check 'a stamped 0 is unstamped, exactly as an absent tid is' `
  ([DisasmTagProbe]::TidOf([uint] 0) -eq 0 -and [DisasmTagProbe]::TidOf($null) -eq 0) ''
# CONTROL: a TidOf that answered 0 for everything would satisfy the line above and erase every real tid.
Check 'CONTROL: a real tid survives TidOf unchanged' ([DisasmTagProbe]::TidOf([uint] 4812) -eq 4812) ''
# THE ONE THAT CATCHES THE DEFECT CLASS. `?? _selTid` is the exact idiom the seat used to disagree with the
# gate on: it makes a stamped literal 0 seat as the SELECTED thread instead of reading as unstamped. Named
# rather than counted - no magic bound on how many `.Value` unwraps a file may contain, which would break
# on every legitimate refactor while saying nothing (the same objection that retired the hardcoded
# request-site count earlier in this run).
# COMMENTS STRIPPED FIRST. The raw scan found TWO hits here and both were comments saying "not
# `tid ?? _selTid`" - the better the comment, the more likely it quotes the exact idiom being banned. Third
# time this trap has caught a check in this repo, so the walker now lives in lib-extract.ps1.
$disasmCode = Get-CSharpCodeOnly $disasmView
$seatIdiom = [regex]::Matches($disasmCode, '\?\?\s*_selTid\b')
Check 'no tid is unwrapped with `?? _selTid`, the idiom the seat and the gate disagreed on' `
  ($seatIdiom.Count -eq 0) "$($seatIdiom.Count) site(s) in code"
# CONTROL: the scan can see that idiom at all - otherwise the zero above is a zero nobody looked for.
Check 'CONTROL: the idiom scan matches it in code' `
  ([regex]::Matches((Get-CSharpCodeOnly 'uint x = tid ?? _selTid;'), '\?\?\s*_selTid\b').Count -eq 1) ''
# ...and the stripper is what makes the zero mean something: the same idiom in a COMMENT must not count,
# which is precisely the two hits the raw scan produced.
Check 'CONTROL: ...and does NOT match it in a comment' `
  ([regex]::Matches((Get-CSharpCodeOnly '// not `tid ?? _selTid` here'), '\?\?\s*_selTid\b').Count -eq 0) ''

# ---- an empty WinTag reply releases the painted flag, BEFORE it erases what that flag described ------
#
# THIS PINS THE SHAPE, NOT THE BEHAVIOUR, and that limit is the point of the comment rather than an
# apology for it. The behavioural seam three gates asked for is NOT CONSTRUCTIBLE today: these are
# instance methods on a WinForms Control and three of them wrap their whole body in UI(...), which returns
# immediately without a created handle, so the code under test never runs. Owen2 established that rather
# than estimating it; it is blocked on ticket 8f352618.
# WHEN 8f352618 LANDS, REPLACE THIS CHECK - do not keep both. Two checks on one mechanism, one structural
# and one behavioural, is how a suite starts disagreeing with itself about what it is guarding.
#
# THE DEFECT: thread A painted, a seat for B comes back EMPTY. The screen is about to be erased by the
# cache replacement, so a _seatedTid still naming A outlives the paint it described - the banner claims A
# while nothing is on screen, and the already-painted guard then refuses to reseat A.
# POSITION, not text. The clear being PRESENT but moved AFTER the cache replacement is exactly the
# regression, and a `-match '_seatedTid = 0'` would pass against it happily.
$winCode = Get-CSharpCodeOnly $onDisasm
$winAt = $winCode.IndexOf('if (kind == WinTag)')
$emptyArm = if ($winAt -ge 0) { $winCode.Substring($winAt) } else { '' }
$clearAt = $emptyArm.IndexOf('_seatedTid = 0;')
$replaceAt = $emptyArm.IndexOf('_instrs = SortedUnique(instrs);')
Check 'the empty WinTag branch releases the painted flag' ($clearAt -ge 0) `
  $(if ($clearAt -ge 0) { '' } else { 'no _seatedTid clear in the WinTag handling' })
# CONTROL: the anchor this is measured against must itself be found, or "before" compares against -1 and
# passes for free.
Check 'CONTROL: the cache replacement is located, so BEFORE means something' ($replaceAt -ge 0) `
  $(if ($replaceAt -ge 0) { '' } else { 'SortedUnique replacement not found' })
Check '...and it is ordered BEFORE the replacement that erases what it described' `
  ($clearAt -ge 0 -and $replaceAt -ge 0 -and $clearAt -lt $replaceAt) "clear@$clearAt replace@$replaceAt"
# INVERTED BY RUN 2 ITEM 1 (Owen2) - this assertion used to ENCODE the defect, which is why it could not
# simply be deleted. It asserted the view ACCEPTS a stamped reply while it does not know its own thread,
# which the cross-model adversary reported as HIGH: that is not an absence of information, it is
# information the view DISCARDS in order to paint something it cannot label. The two fail-open cases are
# not symmetric - an absent tid means the ENGINE said nothing; an unknown _selTid means WE have not asked
# yet, and the fix for not having asked is to ask (SeatOnLateOpen now calls RequestThreads), not to accept
# whatever turns up meanwhile.
Check 'a STAMPED reply is DROPPED while the view does not know its own thread' `
  (-not [DisasmTagProbe]::TidMatches([uint] 4812, [uint] 0)) 'view selTid=0'
# ...and the fail-open cases must not swallow the real mismatch they sit next to.
Check 'CONTROL: fail-open does not extend to a genuine disagreement' `
  (-not [DisasmTagProbe]::TidMatches([uint] 1, [uint] 2)) ''

Check 'OnDisasm applies the tid gate as well as the epoch' ($onDisasm -match 'TidMatchesView\(tid\)') ''
# NEITHER GATE MAY REPLACE THE OTHER. A tid check written in place of the marshal-side epoch check reads
# like a strengthening and is a silent regression: it restores the exact race the second epoch check
# exists to close, and the tid cannot see it (a switch away and back leaves the tid agreeing again).
Check 'the tid gate was ADDED to the marshal, not substituted for the epoch check there' `
  (($marshalBody -match 'epoch\s*!=\s*_epoch') -and ($marshalBody -match 'TidMatchesView\(tid\)')) ''
# The service is the only place the engine's stamp can enter: an invoke that drops it leaves the view
# gating on its own bookkeeping alone, which is what it did before this pass.
Check 'the service passes the engine stamp to DisasmReceived, not just the tag' `
  ($src -match 'DisasmReceived\?\.Invoke\(GetStr\(json,\s*"tag"\),\s*dlist,\s*GetUIntOrNull\(json,\s*"tid"\)\)') ''
Check 'and the event is declared wide enough to carry it' `
  ($src -match 'event\s+Action<string,\s*List<DebugDisasmInstr>,\s*uint\?>\s+DisasmReceived') ''
# The tag is POSITIONAL in the stdin command, ahead of `before`. Now that tags are generated rather than
# literal, the writer validates them so a space cannot shift `before` into the wrong argument.
Check 'RequestDisasmAt validates the tag it is handed' `
  ((Get-Method 'public bool RequestDisasmAt(string vaHex, int count, string tag = null, int before = 0)') -match 'Regex\.IsMatch\(tag') ''

# THE COUNT, ASSERTED AND PRINTED. This suite ran 222 checks and said only "ALL CHECKS PASSED" - a
# sentence that is true of 222 checks and equally true of 69, which is what a skipped block actually
# leaves. cb9324f2 fixed that class in Invoke-CheckSection, and this file - the largest consumer, 192
# Check calls - never opted in, so every "ALL CHECKS PASSED" it printed was as unfalsifiable as before.
#
# WHAT THIS CLOSES AND WHAT IT DOES NOT, because the distinction is the whole lesson of cb9324f2:
#   CLOSES  a block that is skipped, or returns early, while execution CONTINUES - the total is short and
#           this says so, naming the number instead of asserting an adjective.
#   DOES NOT CLOSE  a top-level `break`, which terminates the script HERE: nothing below it runs, this
#           assertion included. Measured: a top-level break left 69 of 222 checks reported, NO summary
#           line, and EXIT=0. Closing that needs the script body inside Invoke-CheckSection, where the
#           `finally` can still fire - filed as its own job rather than pretended away here.
$EXPECTED_CHECKS = 225
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
