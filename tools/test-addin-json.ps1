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
  # identify-thread-by-window (f6e547ce): the hover event's real writer
  [string] $EngineHoverPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Hover.cs'),
  # the toolbar/pad controller: the teardown checks run its real NotifyStopped decision table
  [string] $ControllerPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\DebugSessionController.cs'),
  # the inbound reader and the page that builds the payloads it parses
  [string] $ReaderPath  = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Wire\JsonMessageReader.cs'),
  # the host's wire rules (TidIsKnown, TryUInt, IsHexAddr), in their own file beside the reader (730ef328)
  [string] $WireRulesPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Wire\WireRules.cs'),
  # the typed request DTOs and the host-issued id/grant tables the bridge checks page requests against
  [string] $PageMessagesPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\PageMessages.cs'),
  # the attach picker's listed process, which the pid table in PageMessages.cs holds (moved to Wire, 40a252d0)
  [string] $AttachableProcessPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Wire\AttachableProcess.cs'),
  # the host-issued id and grant tables, split out of PageMessages.cs (6ac29815 #4)
  [string] $HostGrantsPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\HostGrants.cs'),
  # the engine's Variables-row writer, whose edit members the host grants on the way out
  [string] $EngineLocalsPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Locals.cs'),
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
# GetStr reads through the bridge's JsonMessageReader since 079ff431, so every probe that compiles it needs the
# real reader beside it.
$readerEarly = Get-Content -Raw -LiteralPath $ReaderPath
# The host's absent-tid rule lives in WireRules.TidIsKnown since 6ac29815, so every probe compiling a tid
# reader or writer (TidMember, TidOf) carries the real class beside it.
$wireRulesText = Get-Content -Raw -LiteralPath $WireRulesPath
$wireRules = (Get-Method 'internal static class WireRules' $wireRulesText) -replace 'internal static class', 'public static class'

# Get-Method and Set-ExtractSource come from lib-extract.ps1 (dot-sourced above); Check and ShowVal from
# lib-check.ps1, which lib-extract dot-sources in turn. Naming the right file matters here: this suite
# carried its own ShowVal until 2026-09-20, which SHADOWED the shared one and rendered absence as 'null'
# where lib-check renders '(null)' - in the one suite whose subject is JSON, where that distinction is the
# reason the shared version exists.
# This line names the text a bare Get-Method reads, which each harness used to bury in its own copy's
# `if (-not $From)` fallback.
Set-ExtractSource $src


$tidNameDecls = @('private const string TidMemberTid', 'private const string TidMemberStopped', 'private const string TidMemberSelected',
  'private static readonly string[] TidValuedMemberNames') | ForEach-Object { Get-Statement $_ $web }
$tidNameDecls = $tidNameDecls -join "`n"
$methods = @(
  (Get-Method 'private static string ScanNumberToken(string json, string key)'),
  (Get-Method 'private static int? GetIntOrNull(string json, string key)'),
  (Get-Method 'private static uint? GetUIntOrNull(string json, string key)'),
  (Get-Method 'private static string TidJson(uint? tid)' $web),
  (Get-Method 'private static string TidMember(string name, uint? tid)' $web),
  $wireRules,
  # the declared names the writer checks against (c299aced), lifted rather than retyped
  $tidNameDecls
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
Check 'a real tid is written' ([PadJsonProbe]::TidJson(116932) -ceq ',"tid":116932') ([PadJsonProbe]::TidJson(116932))
Check 'a high DWORD is written whole' ([PadJsonProbe]::TidJson(4294967295) -ceq ',"tid":4294967295') ([PadJsonProbe]::TidJson(4294967295))

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
using BpReader;

namespace BpReader {
$((Get-Method 'internal static class JsonMessageReader' $readerEarly) -replace 'internal static class', 'public static class')
}

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
function Lines { param($list) (($list | ForEach-Object { "$($_.DisplayLine)->$($_.Line)" }) -join ' ') }

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
Check 'and the row left behind is the SURVIVOR, requested line 12' ($surv.Count -eq 1 -and $surv[0].DisplayLine -eq 12) (Lines $surv)
Check 'the survivor keeps the planted line it shares, 11' ($surv.Count -eq 1 -and $surv[0].Line -eq 11) (Lines $surv)

# ...and the same the other way round, so the result is not an artefact of list order
$rowsB = New-Object System.Collections.ArrayList
HostBpSet $rowsB ([BpWire]::BpSet($bp10))
HostBpSet $rowsB ([BpWire]::BpSet($bp12))
$survB = HostBpDel $rowsB ([BpWire]::BpDel($bp12))
Check 'removing the SECOND one instead leaves requested line 10' ($survB.Count -eq 1 -and $survB[0].DisplayLine -eq 10) (Lines $survB)

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
  ($bpSurv.Count -eq 1 -and $bpSurv[0].DisplayLine -eq 12) (Lines $bpSurv)

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
  ($parsedList.Count -eq 2 -and $parsedList[0].DisplayLine -eq 11 -and $parsedList[1].DisplayLine -eq 22) (Lines $parsedList)

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
Write-Host 'the read side is DisplayLine, get-only, and RequestedLineOrNull is the only writer (f367a04f)'
$bpClass = Get-CSharpCodeOnly $bpRecord
$displayProp = Get-CSharpBlock 'public int DisplayLine' $bpClass
Check 'DisplayLine exists and has no setter, and no RequestedLine member is left to write through' `
  (($null -ne $displayProp) -and ($displayProp -notmatch '\bset\b') -and ($bpClass -notmatch '\bpublic int RequestedLine\b')) ''
Check 'BuildBpSpec writes DisplayLine, with no second spelling of its fallback' `
  (((Get-Method 'public static string BuildBpSpec(DebugBreakpoint bp)') -match 'Append\(bp\.DisplayLine\)') -and `
   ((Get-CSharpCodeOnly (Get-Method 'public static string BuildBpSpec(DebugBreakpoint bp)')) -notmatch '> 0 \?')) ''
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
  ($noSource -cmatch '"lines":\[\]') $noSource
Check 'and `file` carries the MODULE name, the only name the stop has left' `
  ($noSource -cmatch ('"file":"' + [regex]::Escape($noSourceModule) + '"')) $noSource
Check 'and startLine is 0 with current on the stop line' `
  ($noSource -cmatch '"startLine":0' -and $noSource -cmatch ('"current":' + $noSourceLine + '[,}]')) $noSource

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
Write-Host 'the source pane follows the SELECTED thread (0955b29f)'
# SendSource used to run only at a stop, so after a thread switch the pane and its header kept the STOPPED
# thread's location. The page re-reads the stack on every switch; the host now takes the selected thread's
# location from that tid-stamped reply. RUN below: the real OnStack, FollowSelectedThread, SourceFrameOf,
# NoteStopSource and SendSource, with Post as a recorder. The stop itself (OnPaused) is too large to run here,
# so what it contributes - remembering the stop just before sending its source - is pinned by position.
# Hoisted out of the here-string: an unbalanced '(' in a signature breaks $() inside @"..."@.
$followParts = @(
  (Get-Method 'private void SendSource(' $web) -replace '^private void', 'public void'
  (Get-Method 'private void OnStack(List<DebugStackFrame> frames, uint? tid, string reqId)' $web) -replace '^private void', 'public void'
  (Get-Statement 'private DebugPause _stopSource' $web) -replace '^private', 'public'
  Get-Statement 'private uint? _stopTid' $web
  Get-Statement 'private uint? _sourceTid' $web
  (Get-Method 'private void NoteStopSource(DebugPause p)' $web) -replace '^private void', 'public void'
  Get-Method 'private void FollowSelectedThread(List<DebugStackFrame> frames, uint? tid)' $web
  (Get-Method 'internal static DebugStackFrame SourceFrameOf(List<DebugStackFrame> frames)' $web) -replace '^internal static', 'public static'
  Get-Method 'private static string Str(string s)' $web
  Get-Method 'private static string TidJson(uint? tid)' $web
  Get-Method 'private static string TidMember(string name, uint? tid)' $web
  $wireRules
  $tidNameDecls
) -join "`n"
$followTypes = (Get-Method 'public sealed class DebugStackFrame') + "`n" + (Get-Method 'public sealed class DebugPause')
$followSrc = @"
using System;
using System.IO;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
namespace ClarionDebugger.Terminal {
$followTypes
// OnStack also OFFERS its frames to the grant table (49538b78 wave 5). The real EditGrants is compiled into
// the bridge probe below, and one type cannot be defined twice, so here a recorder takes its place.
public sealed class FrameOfferRecorder {
  public int Calls; public uint? Tid; public string ReqId; public List<string> Frames = new List<string>();
  public bool OfferFrames(uint? tid, string reqId, IEnumerable<KeyValuePair<string, string>> vaEbp) {
    Calls++; Tid = tid; ReqId = reqId; Frames.Clear(); foreach (var f in vaEbp) Frames.Add(f.Key + "|" + f.Value);
    return true;
  }
}
public class SourceFollowProbe {
  public List<string> Posts = new List<string>();
  public FrameOfferRecorder _editGrants = new FrameOfferRecorder();
  private void Post(string json) { Posts.Add(json); }
$followParts
}
}
"@
Add-Type -TypeDefinition $followSrc -Language CSharp | Out-Null

function SFrame { param([int] $n, $proc, $module, [int] $line, $ebp = '0x19FF00')
  $f = New-Object ClarionDebugger.Terminal.DebugStackFrame; $f.Frame = $n; $f.Proc = $proc; $f.Module = $module; $f.Line = $line; $f.Ebp = $ebp; $f
}
function Frames { param([object[]] $fs) $l = New-Object 'System.Collections.Generic.List[ClarionDebugger.Terminal.DebugStackFrame]'; foreach ($f in $fs) { $l.Add($f) }; ,$l }
# The source messages one stack reply produced (the stack post itself is always first).
function SourcesAfter { param($probe, $frames, $tid)
  $probe.Posts.Clear(); $probe.OnStack($frames, $tid, [NullString]::Value)
  ,@($probe.Posts | Where-Object { $_ -like '{"type":"source"*' })
}
$follow = New-Object ClarionDebugger.Terminal.SourceFollowProbe
$stop = New-Object ClarionDebugger.Terminal.DebugPause
$stop.Module = 'stopmod.clw'; $stop.Proc = 'STOPPROC'; $stop.Line = 42; $stop.Tid = 100
$follow.NoteStopSource($stop)
$stoppedStack = Frames @((SFrame 0 'STOPPROC' 'stopmod.clw' 42))
# Thread 200 is inside the runtime: frame 0 has no line, frame 1 has one but an unknown ebp, frame 2 is real.
$runtimeStack = Frames @((SFrame 0 $null $null 0 '0x0'), (SFrame 1 'WORKER' 'worker.clw' 17 '0x0'), (SFrame 2 'MAIN' 'main.clw' 88))

$s = SourcesAfter $follow $stoppedStack 100
Check 'CONTROL: the stopped thread''s own stack reply sends no second source' ($s.Count -eq 0) ($s -join ' | ')
$s = SourcesAfter $follow $runtimeStack 200
Check 'a switch to another thread sends ITS location: the first real Clarion frame with a line (MAIN, main.clw:88)' `
  (($s.Count -eq 1) -and ($s[0] -cmatch '"file":"main\.clw","proc":"MAIN"') -and ($s[0] -cmatch '"current":88[,}]')) ($s -join ' | ')
Check 'and a frame whose ebp is unknown ("0x0") is passed over (not WORKER, worker.clw:17)' `
  (($s -join ' ') -notmatch 'worker\.clw') ($s -join ' | ')
$s = SourcesAfter $follow $runtimeStack 200
Check 'a repeated reply for the thread already shown sends nothing' ($s.Count -eq 0) ($s -join ' | ')
$s = SourcesAfter $follow $runtimeStack 100
Check 'switching BACK restores the stop''s own source and marker (stopmod.clw:42, STOPPROC), not a frame''s' `
  (($s.Count -eq 1) -and ($s[0] -cmatch '"file":"stopmod\.clw","proc":"STOPPROC"') -and ($s[0] -cmatch '"current":42[,}]')) ($s -join ' | ')
$s = SourcesAfter $follow (Frames @((SFrame 0 'OTHER' 'other.clw' 5 '0x0'), (SFrame 1 'MAIN' 'main.clw' 88))) 300
Check 'frame 0 with a line is the thread''s location, whatever its ebp (OTHER, other.clw:5)' `
  (($s.Count -eq 1) -and ($s[0] -cmatch '"file":"other\.clw","proc":"OTHER"') -and ($s[0] -cmatch '"current":5[,}]')) ($s -join ' | ')
$s = SourcesAfter $follow (Frames @((SFrame 0 $null $null 0 '0x0'))) 400
Check 'a thread with no frame that has a line still gets a source message, with NO lines and no file' `
  (($s.Count -eq 1) -and ($s[0] -cmatch '"file":null') -and ($s[0] -cmatch '"lines":\[\]')) ($s -join ' | ')
$s = SourcesAfter $follow $stoppedStack $null
Check 'a reply that names no thread moves nothing' ($s.Count -eq 0) ($s -join ' | ')
$follow._stopSource = $null
$s = SourcesAfter $follow $runtimeStack 200
Check 'with no stop to return to (resumed), a reply moves nothing' ($s.Count -eq 0) ($s -join ' | ')
$noTid = New-Object ClarionDebugger.Terminal.SourceFollowProbe
$stop.Tid = $null; $noTid.NoteStopSource($stop)
$s = SourcesAfter $noTid $runtimeStack 200
Check 'a stop that named no thread never follows: its own stack reply cannot be told from a switch' ($s.Count -eq 0) ($s -join ' | ')
# The two wires into the session, by position: the stop is remembered IMMEDIATELY before its source is sent,
# resume forgets it, and OnStack follows only after posting the stack (the page must hold the frames first).
$onPausedCode = Get-CSharpCodeOnly (Get-Method 'private void OnPaused(DebugPause p)' $web)
Check 'OnPaused remembers the stop as the statement right before it sends the stop''s source' `
  ($onPausedCode -match 'NoteStopSource\(p\);\s*SendSource\(p\.Module, p\.ResolvedPath, p\.Proc, p\.Line\);') ''
Check 'OnSvcResumed forgets the stop' ((Get-Method 'private void OnSvcResumed(' $web) -match '_stopSource = null;') ''
Check 'OnStack follows as its LAST statement, after the stack is posted' `
  ((Get-CSharpCodeOnly (Get-Method 'private void OnStack(List<DebugStackFrame> frames, uint? tid, string reqId)' $web)) -match 'Post\(sb\.ToString\(\)\);\s*FollowSelectedThread\(frames, tid\);\s*\}\s*$') ''

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
  (Get-Method 'public static void SetState(IDebugSessionTarget sender, DebugControllerState state)' $ctl),
  # the forwarders and the ONE marshal they share (fc8d63f5, e61e4f92)
  (Get-Method 'public static void RunToCursor() {' $ctl),
  (Get-Method 'public static void BreakOnProcEntry(string filePath, int line)' $ctl),
  (Get-Method 'private static bool IsPaused(DebugControllerState s)' $ctl),
  (Get-Method 'private static void Invoke(Action<IDebugSessionTarget> action, bool requireReady = true, Func<DebugControllerState, bool> allowed = null)' $ctl),
  (Get-Method 'private static bool SafeIsReady(IDebugSessionTarget t)' $ctl)
) -join "`n"

$ctlTypes = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;

$(Get-Method 'public enum DebugControllerState' $ctl)

$(Get-Method 'public interface IDebugSessionTarget' $ctl)

// A pad that answers IsSessionIdle however the test needs. It implements the REAL interface above, so if
// that interface grows a member this stub stops compiling rather than drifting.
//
// It is deliberately NOT a WinForms Control: since fc8d63f5 the interface requires ISynchronizeInvoke, and
// this is the implementation the old `t as Control` marshal would have run on the caller's thread.
// OffThread makes it report "you are on the wrong thread"; its BeginInvoke runs the posted delegate as if
// on its own thread, and every command records which of the two it ran under.
public sealed class FakePad : IDebugSessionTarget {
    public bool Idle; public bool Throws;
    public bool OffThread; public int Posts; public List<string> Ran = new List<string>();
    private bool _onOwnThread;
    public bool IsReady { get { return true; } }
    public bool IsSessionIdle { get { if (Throws) throw new InvalidOperationException("disposed"); return Idle; } }
    public bool InvokeRequired { get { return OffThread && !_onOwnThread; } }
    public IAsyncResult BeginInvoke(Delegate method, object[] args) {
        Posts++; _onOwnThread = true;
        try { method.DynamicInvoke(args); } finally { _onOwnThread = false; }
        return null;
    }
    public object EndInvoke(IAsyncResult result) { return null; }
    public object Invoke(Delegate method, object[] args) { return method.DynamicInvoke(args); }
    private string Where() { return OffThread ? (_onOwnThread ? "posted" : "CALLER") : "inline"; }
    public void CmdStart() { } public void CmdContinue() { } public void CmdPause() { }
    public void CmdStepOver() { } public void CmdStepInto() { } public void CmdStepOut() { }
    public void CmdStop() { }
    public void CmdRunToCursor(string spec) { Ran.Add("rtc|" + Where()); }
    public void CmdBreakOnProcEntryAt(string filePath, int line) { Ran.Add("boe|" + filePath + "|" + line + "|" + Where()); }
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
Write-Host 'every command reaches its target on the TARGET''s thread, Control or not (fc8d63f5, e61e4f92)'
# The REAL Invoke and forwarders, driven with FakePad - which is NOT a WinForms Control. Before fc8d63f5 the
# marshal was `t as Control`, so this target's commands ran on whatever thread the caller was on; the
# interface now requires ISynchronizeInvoke and Invoke posts through it. test-addin-hooks.ps1 drives the
# same Invoke against a real Control on a real message loop; this is the non-Control half.
function Ran { param($pad) if ($pad.Ran.Count) { $pad.Ran -join ' ; ' } else { '(nothing ran)' } }
$np = NewPad $true
[Ctl]::Reset(); [Ctl]::Register($np); [Ctl]::SetState($np, [DebugControllerState]::Paused)
$np.OffThread = $true
[Ctl]::RunToCursor()
Check 'an off-thread call to a NON-Control target is posted through its own marshal, not run on the caller''s thread' `
  (($np.Posts -eq 1) -and ($np.Ran.Count -eq 1) -and ($np.Ran[0] -ceq 'rtc|posted')) (Ran $np)
[Ctl]::BreakOnProcEntry('C:\src\clbrws011.clw', 50)
Check 'BreakOnProcEntry is marshalled the same way, arguments intact' `
  (($np.Posts -eq 2) -and ($np.Ran.Count -eq 2) -and ($np.Ran[1] -ceq 'boe|C:\src\clbrws011.clw|50|posted')) (Ran $np)
$on = NewPad $true
[Ctl]::Reset(); [Ctl]::Register($on); [Ctl]::SetState($on, [DebugControllerState]::Paused)
[Ctl]::RunToCursor()
Check 'CONTROL: an on-thread caller runs inline, with no post' `
  (($on.Posts -eq 0) -and ($on.Ran.Count -eq 1) -and ($on.Ran[0] -ceq 'rtc|inline')) (Ran $on)
# Break on entry means something while idle (the pad stages it); run to cursor does not.
$idl = NewPad $true
[Ctl]::Reset(); [Ctl]::Register($idl)
[Ctl]::BreakOnProcEntry('C:\src\clbrws011.clw', 50); [Ctl]::RunToCursor()
Check 'BreakOnProcEntry is honoured while IDLE, where RunToCursor is not' `
  (($idl.Ran.Count -eq 1) -and ($idl.Ran[0] -like 'boe|*')) (Ran $idl)
[Ctl]::Reset()
# The reflection contract ClarionAssistant binds, pinned by exact signature. PM decision 7: it binds this one
# OPTIONALLY, so the pair it REQUIRES must not move either.
Check 'the new entry point is public static void BreakOnProcEntry(string filePath, int line)' `
  ($ctl -cmatch 'public static void BreakOnProcEntry\(string filePath, int line\)') ''
Check 'and the two members ClarionAssistant already requires are untouched' `
  (($ctl -cmatch 'public static DebugControllerState State\s*\r?\n\s*\{') -and ($ctl -cmatch 'public static void RunToCursor\(\) \{')) ''
Check 'the interface itself requires the marshal' `
  ($ctl -cmatch 'public interface IDebugSessionTarget : System\.ComponentModel\.ISynchronizeInvoke') ''

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
# So this block is regression coverage, not an exploit: whatever a hostile debuggee gets into text the page
# sends, the page encodes it and the host must read back exactly what was sent. The debuggee is untrusted -
# its names come out of the target's TSWD debug info, and a user pastes them into breakpoint conditions.
#
# The fixtures are not written here. They are produced by running debugger.html's REAL send() and its REAL
# breakpoint-properties editor - both lifted out of the page - under node, with the page objects they touch
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
$bpEditor = Get-Method 'function buildBpEditor(b, locked){' $page

# afbc68c7 moved these fixtures. They used to run through the Procedures pane's break-on-entry sender, which
# carried the procedure NAME - but that request now carries only a host-issued id (see the break-on-entry
# section below), so a hostile name no longer reaches the host by that route at all. The real sender that
# still carries free text the host reads back is the Breakpoints pane's properties editor: its condition and
# trace are typed by the user, and a condition is exactly where someone pastes a name out of the debuggee.
$js = @'
// Just enough of the page for the real editor to run. Every element answers querySelector with a stable
// child per selector, which is all buildBpEditor asks of the DOM.
function mkEl(tag){ return { tag, _q:{}, children:[], dataset:{}, style:{}, value:'', disabled:false, title:'', innerHTML:'',
  classList:{add(){},remove(){},toggle(){},contains(){return false;}}, addEventListener(){},
  appendChild(c){ this.children.push(c); return c; },
  querySelector(sel){ return this._q[sel] || (this._q[sel]=mkEl(sel)); } }; }
const document = { createElement: mkEl };
let wire = null;
const wv = { postMessage(s){ wire = s; } };

'@ + $sendFn + "`n" + $bpEditor + "`n" + @'

// Every value here is what a HOSTILE debuggee could get into a condition - a name out of its own symbols,
// pasted in. The page escapes it correctly (JSON.stringify does), so these are well-formed messages whose
// VALUES look like structure.
const names = [
  ['a closing brace inside the value',        'Proc}'],
  ['a quote inside the value',                'say "hi" now'],
  ['an escaped quote inside the value',       'esc \\" here'],
  ['a backslash inside the value',            'back\\slash'],
  ['a whole fake field inside the value',     'X","line":9999,"module":"EVIL.CLW'],
  ['a fake field that also closes the object', 'X"},{"line":9999'],
  ['a newline inside the value',              'two\nlines'],
  ['a brace and a quote together',            '{"line":1}'],
];

const out = [];
for (const [label, name] of names) {
  const ed = buildBpEditor({ module: 'MAIN.CLW', line: 42, requested: 42 }, false);
  ed.querySelector('.bp-cond').value = name;
  ed.querySelector('.bp-trace').value = name;
  ed.querySelector('.bp-hm').value = '';
  wire = null;
  ed.querySelector('.bp-save').onclick({ stopPropagation(){} });
  // the editor trims what the user typed, so that is what the host must read back
  out.push({ label, wire, name: name.trim() });
}

// The same real send(), with the members in an order the page does not use today. The retired rule forbade
// exactly this - untrusted content anywhere but last - so it is the case that proves the rule is gone.
wire = null;
send('bpprops', JSON.stringify({ condition: 'X","line":9999', trace: 'X","line":9999', module: 'MAIN.CLW', line: 42, hitMode: '', hitValue: 0 }));
out.push({ label: 'untrusted text FIRST, which the retired field-order rule forbade', wire, name: 'X","line":9999' });

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
  $cond   = Read1 $data 'condition'
  $trace  = Read1 $data 'trace'
  # Case-sensitive for the wire's own tokens and the user's text; case-BLIND for the module, a Windows file
  # name the host itself compares OrdinalIgnoreCase (09207c17: converting it would contradict shipped behaviour).
  $ok = ($action -ceq 'bpprops') -and ($module -eq 'MAIN.CLW') -and ($line -ceq '42') -and ($cond -ceq $f.name) -and ($trace -ceq $f.name)
  Check $f.label $ok "module=$module line=$line condition=$cond"
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
  ((Read1 '{"name":"a\"b","line":42}' 'name') -ceq 'a"b') (Read1 '{"name":"a\"b","line":42}' 'name')
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
Check 'a bool still reads as its literal text' ((Read1 '{"a":true}' 'a') -ceq 'true') (Read1 '{"a":true}' 'a')

Write-Host ''
Write-Host 'the retired rule is not lying around waiting to be followed again'
# The doc comment used to codify the field-ORDER workaround AS THE CONTRACT - "any new payload must do the
# same". That instruction is the defect propagating itself into code not yet written, so retiring it is part
# of the fix. This is the guard that keeps it retired.
# afbc68c7 retired JsonVal itself. Every inbound field is now read by the typed request DTOs in
# PageMessages.cs, one Parse per request, and the retirement notice moved there with the readers.
$pageMsgs = Get-Content -Raw -LiteralPath $PageMessagesPath
$hostGrants = Get-Content -Raw -LiteralPath $HostGrantsPath
$jsonValCalls = [regex]::Matches((Get-CSharpCodeOnly $web), '\bJsonVal\(')
Check 'no JsonVal( is left in the bridge; the DTOs read every field' ($jsonValCalls.Count -eq 0) "$($jsonValCalls.Count) call(s)"
# CONTROL: the scan sees a call when there is one, so the zero above is a zero somebody looked for.
Check 'CONTROL: that scan finds a JsonVal( call in code' `
  ([regex]::Matches((Get-CSharpCodeOnly 'string m = JsonVal(data, "module");'), '\bJsonVal\(').Count -eq 1) ''
Check 'the bridge reads its envelope through the DTO' ($web -match 'PageEnvelope\.Parse\(e\.TryGetWebMessageAsString\(\)\)') ''
Check 'the DTOs read JSON through the real reader, with no quote-search of their own' `
  (($pageMsgs -match 'JsonMessageReader\.ReadField') -and ((Get-CSharpCodeOnly $pageMsgs) -notmatch 'IndexOf\("\\"')) ''
Check 'the DTO header does not instruct payloads to order their fields' `
  ($pageMsgs -notmatch 'must do the same' -and $pageMsgs -notmatch 'goes LAST') ''
Check 'and says plainly that there is no rule about field order' ($pageMsgs -match 'NO RULE ABOUT FIELD ORDER') ''

Write-Host ''
Write-Host 'the page hands back only what the host ISSUED: procedure ids and edit tuples (afbc68c7)'
# Bridge hardening stage 2. Two requests used to carry the host's own decisions back as page data:
#   breakonprocentry  {module, line, name}  -> any module:line the page named became a persistent breakpoint
#   editvar           {va, typeCode, size, places, tid, value} -> forwarded to SetVariable as sent, so any
#                     address in the debuggee could be written under any type the message named
# Now a Procedures row goes out with an opaque id and the host resolves it; an edit is honoured only when its
# tuple is one the host itself sent for a row that is still current.
#
# END TO END, EVERY HOP REAL. The host writers (PushProcedures, OnWatch, OnSvcModuleData) are compiled out of
# the WebView and RUN; what they post is fed to the page's own functions (buildProcs, the Procedures
# right-click, the break-on-entry handler, setEditMeta, editAttrs, beginEdit) under node; what THOSE send is
# fed to the host's real checkers (CmdBreakOnProcEntry, EditVar). No hop is a hand-written string, so a host
# and a page that disagree about a member name or a number's type fail here.
#
# THE ONE HAND-WRITTEN HOP is the engine's Variables row, because its writer is a large instance method over
# live process memory. It is written in the writer's shape, and the writer's four edit members are pinned by
# name below so a rename on the engine side fails here rather than passing against a stale imitation.
#
# ONE SUBSTITUTION in the code under test, stated: PushProcedures queues its parse on the thread pool, and
# the probe runs that work item inline (ThreadPool.QueueUserWorkItem -> RunNow). Nothing else is edited.

$pageMsgsBody = ($pageMsgs -replace '(?m)^using [^;]+;\r?\n', '') -replace '\binternal (sealed |static )?class\b', 'public $1class'
$hostGrantsBody = ($hostGrants -replace '(?m)^using [^;]+;\r?\n', '') -replace '\binternal (sealed |static )?class\b', 'public $1class'
$readerBody = ($reader -replace '(?m)^using [^;]+;\r?\n', '') -replace 'internal static class', 'public static class'
$wireRulesBody = ($wireRulesText -replace '(?m)^using [^;]+;\r?\n', '') -replace 'internal static class', 'public static class'
$attachableBody = (Get-Content -Raw -LiteralPath $AttachableProcessPath) -replace '(?m)^using [^;]+;\r?\n', ''
# Expression-bodied handlers (`=> UI(() => { ... });`) brace-match to their lambda's closing brace; the
# `);` that closes UI( is put back here.
function Get-ArrowHandler { param([string] $Sig) (Get-Method $Sig $web) + ');' }
$pushProcs = (Get-Method 'private void PushProcedures(string exe)' $web) -replace 'System\.Threading\.ThreadPool\.QueueUserWorkItem\(', 'RunNow('
$arrowHandlers = @('private void OnSvcVariableSet(', 'private void OnSvcModuleData(', 'private void OnSvcThreadSelected(', 'private void OnSvcExpanded(', 'private void OnSvcFrameLocals(',
  'private void OnSvcSelectionChanged(' |
  ForEach-Object { (Get-ArrowHandler $_) -replace '^private void', 'public void' }) -join "`n"

$selectionTypes = (Get-Method 'public enum ThreadSelectionCause') + "`n" + (Get-Method 'public sealed class ThreadSelection')
$bridgeSrc = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ClarionDebugger.Wire;
$readerBody
$wireRulesBody
$attachableBody
$pageMsgsBody
$hostGrantsBody
namespace ClarionDebugger.Terminal {
$(Get-Method 'public enum DebugSessionState')
$bpRecord
$(Get-Method 'public sealed class DebugWatch')
$(Get-Method 'public sealed class DebugProcedure')
public sealed class ClarionDebuggerService {
  public static List<DebugProcedure> Listed = new List<DebugProcedure>();
  public static List<DebugProcedure> GetProcedures(string exe) { return new List<DebugProcedure>(Listed); }
  $((Get-Method 'internal static DebugProcedure ProcedureFromSymbol(string obj)') -replace '^internal static', 'public static')
  $(Get-Method 'private static string GetStr(string json, string key)')
  $(Get-Method 'private static int GetInt(string json, string key)')
  $(Get-Method 'private static int? GetIntOrNull(string json, string key)')
  $(Get-Method 'private static string ScanNumberToken(string json, string key)')
  $(Get-Method 'public static bool IsValidModuleName(string module)')
  $((Get-Method 'internal static bool BpLineMatches(DebugBreakpoint b, int? requestedLine, int plantedLine)') -replace 'internal static', 'public static')
}
public sealed class FakeSvc {
  public DebugSessionState State = DebugSessionState.Paused;
  public bool IsRunning = true; public bool Accept = true; public bool AcceptSet = true;
  public List<string> Adds = new List<string>();
  public List<string> Sets = new List<string>();
  public List<string> Expands = new List<string>();
  public bool AcceptExpand = true;
  public List<string> FrameLocalsSent = new List<string>();
  public bool AcceptFrameLocals = true;
  public bool RequestFrameLocals(int reqId, string va, string ebp) { FrameLocalsSent.Add(reqId + "|" + va + "|" + ebp); return AcceptFrameLocals; }
  public bool RequestExpand(int reqId, string module, uint typeRef, string addr) { Expands.Add(reqId + "|" + module + "|" + typeRef + "|" + addr); return AcceptExpand; }
  public void PrimeTarget(string exe) { }
  public bool AddBreakpoint(string module, int line) { Adds.Add(module + ":" + line); return Accept; }
  public bool SetVariable(string va, string typeCode, int size, int places, string value, uint? tid) {
    Sets.Add(va + "|" + typeCode + "|" + size + "|" + places + "|" + (tid.HasValue ? tid.Value.ToString() : "-") + "|" + value);
    return AcceptSet;
  }
}
$selectionTypes
// The service's selection, as EditGrants reads it: a Func over the current snapshot (49538b78 8b). The service's
// real writer (MoveSelection) is run in tools/test-addin-selection.ps1; here each step a test takes names the
// change the service would have made before raising the event the test then delivers.
public sealed class SelectionSource {
  public ThreadSelection Current = ThreadSelection.None;
  public readonly EditGrants Grants;
  public SelectionSource() { Grants = new EditGrants(() => Current); }
  public void Stop(uint tid) { Current = new ThreadSelection(tid, tid, Current.Epoch + 1, ThreadSelectionCause.Stop); }
  public void Switch(uint tid) { Current = new ThreadSelection(tid, Current.StoppedTid, Current.Epoch + 1, ThreadSelectionCause.Switch); }
}
public sealed class BridgePad {
  public FakeSvc _svc = new FakeSvc();
  public List<DebugBreakpoint> _pending = new List<DebugBreakpoint>();
  public ProcedureIds _procIds = new ProcedureIds();
  public SelectionSource _sel = new SelectionSource();
  public EditGrants _editGrants { get { return _sel.Grants; } }
  public List<string> Lines = new List<string>();
  public List<string> Posts = new List<string>();
  public int BpPushes;
  private int _procGen;
  private void Console(string level, string text) { Lines.Add(level + "|" + text); }
  private void Post(string json) { Posts.Add(json); }
  private void SendBps() { BpPushes++; }
  private void UI(Action a) { a(); }
  // The thread-pool work item runs inline - or is HELD, so a test can act while a refresh is mid-parse.
  public bool HoldWork; public List<Action<object>> Held = new List<Action<object>>();
  private void RunNow(Action<object> work) { if (HoldWork) Held.Add(work); else work(null); }
  public void ReleaseHeld(bool newestFirst) {
    var h = new List<Action<object>>(Held); Held.Clear(); if (newestFirst) h.Reverse();
    foreach (var w in h) w(null);
  }
  $(Get-Method 'private static string Str(string s)' $web)
  $(Get-Method 'private static string TidJson(uint? tid)' $web)
  $(Get-Method 'private static string TidMember(string name, uint? tid)' $web)
  $tidNameDecls
  $(Get-Method 'private static bool SameBp(DebugBreakpoint b, string module, int line)' $web)
  $pushProcs
  $((Get-Method 'public void CmdBreakOnProcEntry(string data)' $web) -replace '^public void', 'public void')
  $(Get-Method 'public void CmdBreakOnProcEntryAt(string filePath, int line)' $web)
  $(Get-Method 'private void BreakOnEntry(ProcRef proc)' $web)
  $((Get-Method 'private void OnWatch(DebugWatch w)' $web) -replace '^private void', 'public void')
  $((Get-Method 'private void EditVar(string data)' $web) -replace '^private void', 'public void')
  $((Get-Method 'private void Expand(string data)' $web) -replace '^private void', 'public void')
  $(Get-Method 'private void RefuseExpand(int reqId, string why)' $web)
  $((Get-Method 'private void FrameLocals(string data)' $web) -replace '^private void', 'public void')
  $(Get-Method 'private void RefuseFrameLocals(int reqId, string why)' $web)
  $(Get-Method 'private void PostVarSet(string va, bool ok, string value, string error)' $web)
  $arrowHandlers
  public void RunPushProcedures(string exe) { PushProcedures(exe); }
}
}
"@
Add-Type -TypeDefinition $bridgeSrc -Language CSharp | Out-Null

function Errs { param($pad) @($pad.Lines | Where-Object { $_ -like 'err|*' }) }
# An accepted switch, as the service delivers it: its selection moves first, then ThreadSelected is raised.
function Switched { param($pad, [uint32] $tid) $pad._sel.Switch($tid); $pad.OnSvcThreadSelected($tid, $true, $null) }
function Proc { param($name, $module, $line, $kind = 'procedure', $endLine = 0, [switch] $ExtentUnknown)
  $p = New-Object ClarionDebugger.Terminal.DebugProcedure; $p.Name = $name; $p.Module = $module; $p.Line = $line; $p.Kind = $kind; $p.EndLine = $endLine
  $p.ExtentUnknown = [bool] $ExtentUnknown; $p
}

# ---- host writers, run --------------------------------------------------------------------------------
$pad = New-Object ClarionDebugger.Terminal.BridgePad
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'SPLASH' 'clbrws001.clw' 17))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'MAIN' 'clbrws011.clw' 42))
$pad.RunPushProcedures('C:\App\app.exe')
$procMsg = if ($pad.Posts.Count -ge 1) { $pad.Posts[$pad.Posts.Count - 1] } else { '' }
Check 'CONTROL: PushProcedures posts an empty "loading" list, then the list' `
  (($pad.Posts.Count -eq 2) -and ($pad.Posts[0] -cmatch '"procs":\[\],"loading":true') -and ($procMsg -cmatch '"name":"MAIN"')) "$($pad.Posts.Count) post(s)"
# A launch and an attach load the list (and the globals) through ONE method (70860d6b C7), so a change to
# either reaches both kinds of session.
$webCode = Get-CSharpCodeOnly $web
Check 'StartSession and AttachSession both load symbols through LoadStaticSymbols, the one reader of the globals' `
  (((Get-CSharpCodeOnly (Get-Method 'private void StartSession()' $web)) -match 'LoadStaticSymbols\(_exe\);') -and `
   ((Get-CSharpCodeOnly (Get-Method 'private void AttachSession(AttachableProcess target)' $web)) -match 'LoadStaticSymbols\(exe\);') -and `
   ([regex]::Matches($webCode, 'GetGlobalsJson\(').Count -eq 1)) ''

$watch = New-Object ClarionDebugger.Terminal.DebugWatch
$watch.Name = 'GLO:Count'; $watch.Found = $true; $watch.Value = '5'; $watch.TypeName = 'LONG'
$watch.Va = '0x4A10F0'; $watch.TypeCode = '0x03'; $watch.Size = 4; $watch.Places = 0; $watch.Tid = 4812
$pad.OnWatch($watch)
$watchMsg = $pad.Posts[$pad.Posts.Count - 1]

# The engine's Variables row: a GROUP whose one editable member sits in `children`, so the grant has to be
# found below the top level. Shape pinned against the writer just below.
$engineRows = '{"name":"G:REC","type":"GROUP","value":"","children":[{"name":"G:X","type":"DECIMAL(7,2)","value":"1.50","va":"0x4A2200","typeCode":"0x0A","size":4,"places":2},{"name":"G:PTR","type":"","value":"0x4B0000","ref":true,"addr":"0x4B0000","module":"clbrws011.clw","typeRef":77}]}'
$engineLocals = Get-Content -Raw -LiteralPath $EngineLocalsPath
Check 'the engine row writer still emits va, typeCode, size and places under those names' `
  (($engineLocals -match '\\"va\\":\\"0x') -and ($engineLocals -match '\\"typeCode\\":\\"0x') -and `
   ($engineLocals -match '\\"size\\":') -and ($engineLocals -match '\\"places\\":')) ''
$pad.OnSvcModuleData('clbrws011.clw', $engineRows, 4812)
$moduleMsg = $pad.Posts[$pad.Posts.Count - 1]
Check 'CONTROL: the nested row was granted and the group itself was not' ($pad._editGrants.Count -eq 2) "$($pad._editGrants.Count) grant(s) incl. the watch"

# The engine's answer to that edit, as the host posts it: the real OnSvcVariableSet, on a scratch pad.
$vsPad = New-Object ClarionDebugger.Terminal.BridgePad
$vsPad.OnSvcVariableSet('0x4A10F0', $true, '7', $null)
$varsetMsg = $vsPad.Posts[$vsPad.Posts.Count - 1]

# A call stack as the real OnStack posts it (the follow probe above), and the frames it OFFERED on the way.
$flProbe = New-Object ClarionDebugger.Terminal.SourceFollowProbe
$flFrames = Frames @((SFrame 0 'MAIN' 'main.clw' 88 '0x19FF00'), (SFrame 1 'CALLER' 'main.clw' 12 '0x19FF40'), (SFrame 2 'LOST' $null 0 '0x0'))
$flFrames[0].Va = '0x401000'; $flFrames[1].Va = '0x402000'; $flFrames[2].Va = '0x403000'
$flProbe.OnStack($flFrames, 4812, '5')
$stackMsg = $flProbe.Posts[0]

# ---- the page, run ------------------------------------------------------------------------------------
$pageJs = @(
  (Get-Method 'function send(action,data)' $page),
  (Get-CSharpStatement 'const isProcKind' $page),
  (Get-Method 'function buildProcs(procs){' $page),
  ((Get-Method "`$('procList').addEventListener('contextmenu'," $page) + ');'),
  ((Get-Method "`$('miBpEntry').onclick=" $page) + ';'),
  (Get-Method 'function esc(s){' $page),
  (Get-Method 'function editAttrs(v){' $page),
  (Get-Method 'function setEditMeta(cell, meta){' $page),
  (Get-Method 'function stripEditQuotes(s){' $page),
  (Get-Method 'function beginEdit(cell){' $page),
  (Get-Method 'function requestExpand(v, cb){' $page),
  (Get-Method 'function requestFrameLocals(f, cb){' $page),
  (Get-Method 'function onVarSet(m){' $page)
) -join "`n"
$inputFile = Join-Path ([IO.Path]::GetTempPath()) ('cabridge-in-' + [Guid]::NewGuid().ToString('N') + '.json')
@{ procs = $procMsg; watch = $watchMsg; moduledata = $moduleMsg; varset = $varsetMsg; stack = $stackMsg } | ConvertTo-Json -Compress | Set-Content -LiteralPath $inputFile -Encoding UTF8
$bridgeJs = @'
const fs = require('fs');
const INPUT = JSON.parse(fs.readFileSync(process.argv[2], 'utf8').replace(/^\uFEFF/, ''));
function mkEl(tag){ return { tag, _q:{}, children:[], dataset:{}, style:{}, value:'', title:'', textContent:'', innerHTML:'',
  classList:{add(){},remove(){},toggle(){},contains(){return false;}}, listeners:{},
  addEventListener(t,f){ this.listeners[t]=f; }, appendChild(c){ this.children.push(c); return c; },
  focus(){}, select(){}, querySelector(sel){ return this._q[sel] || (this._q[sel]=mkEl(sel)); } }; }
const els = {};
function $(id){ return els[id] || (els[id]=mkEl(id)); }
const document = { createElement: mkEl, createDocumentFragment(){ return mkEl('#frag'); } };
const window = { innerWidth: 1000 };
let wire = null; const wv = { postMessage(s){ wire = s; } };
let allProcs = [], procIndex = null, bps = [], procCtx = null;
function buildBps(){} function filterProcs(){}
let isPaused = true, activeEdit = null, selTid = null;
let _expandSeq = 0; const _expandCbs = {};
let _flSeq = 0; const _flCbs = {};
function editThreadSuffix(){ return ''; } function viewingOtherThread(){ return false; } function toast(){}
'@ + "`n" + $pageJs + "`n" + @'

const out = {};
// Procedures: the list the host posted, rendered by the real buildProcs, right-clicked on MAIN, broken on.
buildProcs(JSON.parse(INPUT.procs).procs);
const rows = $('procList').children[0].children;
const main = rows.find(r => r.dataset.name === 'MAIN');
$('procList').listeners.contextmenu({ target:{ closest(){ return main; } }, preventDefault(){}, clientX:0, clientY:0 });
wire = null; $('miBpEntry').onclick(); out.bpe = wire;

// An edit on the Watch row the host posted: the page's own case 'watch' hands setEditMeta these four.
function commit(cell, value){ beginEdit(cell); const inp = cell.children[cell.children.length - 1];
  inp.value = value; wire = null; inp.onkeydown({ key:'Enter', preventDefault(){} }); return wire; }
const wm = JSON.parse(INPUT.watch);
const wcell = mkEl('span'); setEditMeta(wcell, { va:wm.va, typeCode:wm.typeCode, size:wm.size, places:wm.places });
selTid = wm.tid;
out.watchEdit = commit(wcell, 'X","va":"0x1","value":"7');
// The engine answers; the page's real onVarSet repaints the cell. Then the user edits the SAME row again.
document.querySelectorAll = function(){ return [wcell]; };
function dtApply(){}
onVarSet(JSON.parse(INPUT.varset));
out.watchEdit2 = commit(wcell, 'second');

// An edit on the NESTED Variables row: editAttrs writes the attributes the tree row is built with.
const child = JSON.parse(INPUT.moduledata).items[0].children[0];
const tcell = mkEl('span'); const attrs = editAttrs(child); let m; const re = / data-(\w+)="([^"]*)"/g;
while ((m = re.exec(attrs))) tcell.dataset[m[1]] = m[2];
out.treeEdit = commit(tcell, '2.25');

// Opening the reference row the host posted: the page's own expand request for it.
const refRow = JSON.parse(INPUT.moduledata).items[0].children[1];
wire = null; requestExpand(refRow, function(){}); out.expand = wire;

// Opening the CALLER frame (frame 1) of the stack the host posted: the page's own framelocals request.
const callerFrame = JSON.parse(INPUT.stack).frames[1];
wire = null; requestFrameLocals(callerFrame, function(){}); out.framelocals = wire;
console.log(JSON.stringify(out));
'@
$bridgeFile = Join-Path ([IO.Path]::GetTempPath()) ('cabridge-' + [Guid]::NewGuid().ToString('N') + '.js')
Set-Content -LiteralPath $bridgeFile -Value $bridgeJs -Encoding UTF8
$pageOut = $null
try {
  $raw = & node $bridgeFile $inputFile 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL  could not run the page half of the bridge under node"; $raw | ForEach-Object { Write-Host "        $_" }; $script:failures++ }
  else { $pageOut = ($raw -join "`n") | ConvertFrom-Json }
} finally {
  Remove-Item -LiteralPath $bridgeFile, $inputFile -ErrorAction SilentlyContinue
}
function DataOf { param($wire) Read1 $wire 'data' }

# ---- break on entry, through the real page ------------------------------------------------------------
$bpeData = if ($pageOut) { DataOf $pageOut.bpe } else { '' }
Check 'the page sends the row''s host-issued id' ((Read1 $bpeData 'id') -cmatch '^p\d+\.\d+$') $bpeData
Check 'and neither a module nor a line: the host looks those up' `
  (($null -eq (Read1 $bpeData 'module')) -and ($null -eq (Read1 $bpeData 'line'))) $bpeData
$pad.CmdBreakOnProcEntry($bpeData)
Check 'the host arms the breakpoint the id stands for - MAIN at clbrws011.clw:42' `
  (($pad._svc.Adds.Count -eq 1) -and ($pad._svc.Adds[0] -ceq 'clbrws011.clw:42')) ($pad._svc.Adds -join ',')

# A list replaced since the page was sent it: the old id resolves to nothing, not to whatever row now has
# that index.
$pad.RunPushProcedures('C:\App\app.exe')
$pad._svc.Adds.Clear(); $pad.Lines.Clear()
$pad.CmdBreakOnProcEntry($bpeData)
Check 'an id from a list the host has since replaced arms nothing' ($pad._svc.Adds.Count -eq 0) ($pad._svc.Adds -join ',')
Check 'and says why' (@(Errs $pad).Count -eq 1) ($pad.Lines -join ' / ')
# The payload the page USED to send names a module and line, and no id. It must arm nothing at all.
$pad._svc.Adds.Clear(); $pad.Lines.Clear()
$pad.CmdBreakOnProcEntry('{"module":"EVIL.CLW","line":1,"name":"X"}')
Check 'the old {module,line} payload is not honoured' ($pad._svc.Adds.Count -eq 0) ($pad._svc.Adds -join ',')

# ---- an id is bound to its GENERATION (codex adversary gate) ------------------------------------------
# The parse is asynchronous. The table used to be swapped only when it finished, so for the whole parse the
# PREVIOUS exe's ids still resolved. Held here, so "mid-refresh" is a state the test is IN, not a race.
function ProcIdAt { param($json, $i) if ($json -match ('"id":"(p\d+\.' + $i + ')"')) { $Matches[1] } else { '' } }
$gp = New-Object ClarionDebugger.Terminal.BridgePad
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'MAIN' 'clbrws011.clw' 42))
$gp.RunPushProcedures('C:\App\app.exe')
$oldId = ProcIdAt $gp.Posts[$gp.Posts.Count - 1] 0
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'NEWMAIN' 'newapp.clw' 7))
$gp.HoldWork = $true
$gp.RunPushProcedures('C:\Other\new.exe')      # the new target's parse starts, and is held
Check 'a refresh tells the page to drop its ids at once' ($gp.Posts[$gp.Posts.Count - 1] -cmatch '"procs":\[\],"loading":true') $gp.Posts[$gp.Posts.Count - 1]
$gp.CmdBreakOnProcEntry('{"id":"' + $oldId + '"}')
Check 'an id from the previous list is refused WHILE the new one is being parsed' `
  (($gp._svc.Adds.Count -eq 0) -and (@(Errs $gp).Count -eq 1)) "id=$oldId adds=$($gp._svc.Adds -join ',')"
$gp.ReleaseHeld($false)
$gp.Lines.Clear()
$gp.CmdBreakOnProcEntry('{"id":"' + $oldId + '"}')
Check 'and after it arrives' (($gp._svc.Adds.Count -eq 0) -and (@(Errs $gp).Count -eq 1)) ($gp._svc.Adds -join ',')
# The synchronous clear, ISOLATED: a position lookup uses no id, so the generation check cannot be what
# refuses it - only the table having been emptied at the start of the refresh can.
$gh = New-Object ClarionDebugger.Terminal.BridgePad
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
# WITH an extent, so the only thing that can refuse the lookup below is the table having been cleared.
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'MAIN' 'clbrws011.clw' 42 'procedure' 100))
$gh.RunPushProcedures('C:\App\app.exe')
$gh.HoldWork = $true
$gh.RunPushProcedures('C:\Other\new.exe')
$gh.CmdBreakOnProcEntryAt('C:\Src\clbrws011.clw', 50)
Check 'mid-refresh, a POSITION in the old list resolves to nothing either' `
  (($gh._svc.Adds.Count -eq 0) -and (@(Errs $gh)[0] -match 'no listed procedure is in')) (($gh._svc.Adds -join ',') + ' / ' + ($gh.Lines -join ' / '))
# The generation check and the install gate, ISOLATED on the table itself.
$ids = New-Object ClarionDebugger.Terminal.ProcedureIds
$ids.Begin(2)
$foreign = [ClarionDebugger.Terminal.ProcedureIds]::NewTable()
$ref = New-Object ClarionDebugger.Terminal.ProcRef; $ref.Module = 'x.clw'; $ref.Line = 1
$foreign['p1.0'] = $ref
[void]$ids.Replace(2, $foreign)
Check 'an id of another generation does not resolve, even if a table somehow holds it' ($null -eq $ids.Resolve('p1.0')) ''
Check 'a table for a generation that is no longer current is not installed' (-not $ids.Replace(1, $foreign)) ''
$newId = ProcIdAt $gp.Posts[$gp.Posts.Count - 1] 0
$gp.CmdBreakOnProcEntry('{"id":"' + $newId + '"}')
Check 'CONTROL: the new list''s id arms the new row' (($gp._svc.Adds.Count -eq 1) -and ($gp._svc.Adds[0] -ceq 'newapp.clw:7')) "id=$newId adds=$($gp._svc.Adds -join ',')"
# Two refreshes in flight, the OLDER parse finishing LAST: it must not install its table over the newer one.
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'FIRST' 'first.clw' 3))
$gp.RunPushProcedures('C:\A\a.exe')
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'SECOND' 'second.clw' 5))
$gp.RunPushProcedures('C:\B\b.exe')
$gp.ReleaseHeld($true)                           # newest parse first, then the stale one
$lastList = $gp.Posts[$gp.Posts.Count - 1]
Check 'a slower, older parse cannot replace a newer list' (($lastList -cmatch '"name":"SECOND"') -and ($lastList -cnotmatch '"name":"FIRST"')) $lastList
$gp._svc.Adds.Clear()
$gp.CmdBreakOnProcEntry('{"id":"' + (ProcIdAt $lastList 0) + '"}')
Check 'and the newer list''s ids are the ones that resolve' (($gp._svc.Adds.Count -eq 1) -and ($gp._svc.Adds[0] -ceq 'second.clw:5')) ($gp._svc.Adds -join ',')

# The cheap half of the ticket, which the id rework must not lose: a live add the engine never took is said.
$freshId = if ($pad.Posts[$pad.Posts.Count - 1] -match '"id":"(p\d+\.1)"') { $Matches[1] } else { '' }
$pad._svc.Accept = $false; $pad._svc.Adds.Clear(); $pad.Lines.Clear()
$pad.CmdBreakOnProcEntry('{"id":"' + $freshId + '"}')
Check 'CONTROL: a current id reaches the engine' ($pad._svc.Adds.Count -eq 1) "id=$freshId adds=$($pad._svc.Adds -join ',')"
Check 'a refused live add writes an error line naming the breakpoint' `
  ((@(Errs $pad).Count -eq 1) -and (@(Errs $pad)[0] -match 'clbrws011\.clw:42')) ($pad.Lines -join ' / ')
$pad._svc.Accept = $true; $pad._svc.Adds.Clear(); $pad.Lines.Clear()
$pad.CmdBreakOnProcEntry('{"id":"' + $freshId + '"}')
Check 'CONTROL: an accepted live add writes no error' (@(Errs $pad).Count -eq 0) ($pad.Lines -join ' / ')

# The idle branch validates the module before staging it. With ids, the only modules that can arrive are the
# ones the host listed, so an unusable one is planted in the LIST here to prove the check is still live.
$idle = New-Object ClarionDebugger.Terminal.BridgePad
$idle._svc.IsRunning = $false
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'BAD' '..\evil clw' 5))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'GOOD' 'clbrws011.clw' 42))
$idle.RunPushProcedures('C:\App\app.exe')
$idleList = $idle.Posts[$idle.Posts.Count - 1]
$badId = if ($idleList -match '"id":"(p\d+\.0)"') { $Matches[1] } else { '' }
$goodId = if ($idleList -match '"id":"(p\d+\.1)"') { $Matches[1] } else { '' }
$idle.CmdBreakOnProcEntry('{"id":"' + $badId + '"}')
Check 'an idle request for an unusable module stages nothing' ($idle._pending.Count -eq 0) "$($idle._pending.Count) staged"
Check 'and says why' (@(Errs $idle).Count -eq 1) ($idle.Lines -join ' / ')
$idle.CmdBreakOnProcEntry('{"id":"' + $goodId + '"}')
Check 'CONTROL: an idle request for a good module is staged once' `
  (($idle._pending.Count -eq 1) -and ($idle.BpPushes -eq 1)) "$($idle._pending.Count) staged"

# ---- break on entry by POSITION: the editor's cursor (e61e4f92) ---------------------------------------
# ClarionAssistant has a file and a line, not an id. The position is only a key into the SAME host-issued
# list, and it must be CONTAINED by a procedure (PM ruling, codex adversary gate) - never "the nearest one
# above". Containment needs the procedure's END, which the bundled engine sends as endLine since e049e07; a
# procedure with no end is refused (pipeline run 2), never bounded by the next procedure's start. WHY it is
# refused depends on what the engine sent (f1a98318): no extent member at all is an engine/host version
# mismatch, while "extent":"unknown" is a same-build engine that could not bound it from the debug info.
# clbrws011.clw: MAIN 42..70 with a routine inside it at 45, OTHER 80..120. clbrws003.clw: LAST 20, no end.
# clbrws004.clw: BOUNDED 10..30, AFTERDATA 60. clbrws005.clw: the adversary's case, A 10 with NO end and
# B 50..70. clbrws006.clw: UNBOUNDED 10, extent unknown, and NEXTP 50..70.
$posPad = New-Object ClarionDebugger.Terminal.BridgePad
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Clear()
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'MAIN' 'clbrws011.clw' 42 'procedure' 70))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'MAIN::DOIT' 'clbrws011.clw' 45 'routine'))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'OTHER' 'clbrws011.clw' 80 'procedure' 120))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'ELSEWHERE' 'clbrws002.clw' 10))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'LAST' 'clbrws003.clw' 20))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'BOUNDED' 'clbrws004.clw' 10 'procedure' 30))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'AFTERDATA' 'clbrws004.clw' 60))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'A' 'clbrws005.clw' 10))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'B' 'clbrws005.clw' 50 'procedure' 70))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'UNBOUNDED' 'clbrws006.clw' 10 -ExtentUnknown))
[ClarionDebugger.Terminal.ClarionDebuggerService]::Listed.Add((Proc 'NEXTP' 'clbrws006.clw' 50 'procedure' 70))
$posPad.RunPushProcedures('C:\App\app.exe')
function PosAdd { param($path, $line) $posPad._svc.Adds.Clear(); $posPad.Lines.Clear(); $posPad.CmdBreakOnProcEntryAt($path, $line); $posPad._svc.Adds -join ',' }
function PosRefused { param($path, $line, $reason)
  $a = PosAdd $path $line
  ($a -eq '') -and (@(Errs $posPad).Count -eq 1) -and ((@(Errs $posPad)[0]) -match $reason)
}
Check 'a cursor inside MAIN, below one of its ROUTINEs, breaks on MAIN''s entry (42), not the routine''s' `
  ((PosAdd 'C:\Src\CLBRWS011.CLW' 50) -ceq 'clbrws011.clw:42') ($posPad._svc.Adds -join ',')
Check 'a cursor inside a procedure with a known extent resolves (OTHER, 80..120)' `
  ((PosAdd 'C:\Src\clbrws011.clw' 90) -ceq 'clbrws011.clw:80') ($posPad._svc.Adds -join ',')
Check 'a cursor ON the definition line counts as inside it' ((PosAdd 'C:\Src\clbrws011.clw' 42) -ceq 'clbrws011.clw:42') ($posPad._svc.Adds -join ',')
Check 'REFUSED: a cursor above the first procedure' (PosRefused 'C:\Src\clbrws011.clw' 10 'above the first') ($posPad.Lines -join ' / ')
Check 'REFUSED: a cursor BETWEEN procedures, in module data past a known end (clbrws004 31..59)' `
  (PosRefused 'C:\Src\clbrws004.clw' 45 'past the end of BOUNDED') ($posPad.Lines -join ' / ')
Check 'REFUSED: a cursor below a procedure''s known end, with nothing after it (OTHER ends at 120)' `
  (PosRefused 'C:\Src\clbrws011.clw' 130 'past the end of OTHER') ($posPad.Lines -join ' / ')
Check 'REFUSED: a cursor below the LAST procedure in a module whose end is unknown' `
  (PosRefused 'C:\Src\clbrws003.clw' 25 'engine/host version mismatch') ($posPad.Lines -join ' / ')
# THE ADVERSARY'S CASE (pipeline run 2): A starts at 10 with NO end and B at 50. Line 40 may be module data
# between them; the next-start fallback armed A there. With no end it is REFUSED, naming the mismatch.
Check 'REFUSED: A(10, no end), B(50), cursor 40 - an unknown end is a version mismatch, not a guess' `
  (PosRefused 'C:\Src\clbrws005.clw' 40 'engine/host version mismatch') ($posPad.Lines -join ' / ')
Check 'CONTROL: a procedure WITH an end still resolves in the same module (B 50..70, cursor 60)' `
  ((PosAdd 'C:\Src\clbrws005.clw' 60) -ceq 'clbrws005.clw:50') ($posPad._svc.Adds -join ',')
Check 'with an end of 30, cursor 20 resolves (BOUNDED 10..30)' ((PosAdd 'C:\Src\clbrws004.clw' 20) -ceq 'clbrws004.clw:10') ($posPad._svc.Adds -join ',')
Check 'and cursor 40, past that end, is refused' (PosRefused 'C:\Src\clbrws004.clw' 40 'past the end of BOUNDED') ($posPad.Lines -join ' / ')
Check 'REFUSED: a file the list does not cover' (PosRefused 'C:\Src\unlisted.clw' 50 'no listed procedure is in') ($posPad.Lines -join ' / ')
# f1a98318: the SAME refusal, worded by its cause. A procedure the engine said it could not bound is not a
# broken install, so its message names the debug info and never the version mismatch.
Check 'REFUSED: UNBOUNDED(10, extent unknown), cursor 20 - the debug info does not bound it' `
  (PosRefused 'C:\Src\clbrws006.clw' 20 'the debug info does not say where UNBOUNDED ends') ($posPad.Lines -join ' / ')
Check 'and that refusal does not blame an engine/host version mismatch' `
  (($posPad.Lines -join ' / ') -notmatch 'mismatch|reinstall') ($posPad.Lines -join ' / ')
Check 'CONTROL: NEXTP, bounded, still resolves beside it (50..70, cursor 60)' `
  ((PosAdd 'C:\Src\clbrws006.clw' 60) -ceq 'clbrws006.clw:50') ($posPad._svc.Adds -join ',')
Check 'and the version-mismatch refusal (A, no extent member at all) does not claim the debug info is at fault' `
  ((PosRefused 'C:\Src\clbrws005.clw' 40 'engine/host version mismatch') -and (($posPad.Lines -join ' / ') -notmatch 'debug info')) ($posPad.Lines -join ' / ')
# The service's reading of an engine row, RUN on rows in the engine's shape (Json.Symbols): the three cases
# the host tells apart.
$symRow = { param($extra) '{"name":"P","raw":"P","kind":"procedure","rva":"0x1000","line":10' + $extra + ',"moduleIdx":1,"module":"m.clw"}' }
$withEnd = [ClarionDebugger.Terminal.ClarionDebuggerService]::ProcedureFromSymbol((& $symRow ',"endLine":20'))
$unknownEnd = [ClarionDebugger.Terminal.ClarionDebuggerService]::ProcedureFromSymbol((& $symRow ',"extent":"unknown"'))
$oldEngine = [ClarionDebugger.Terminal.ClarionDebuggerService]::ProcedureFromSymbol((& $symRow ''))
Check 'a row WITH endLine reads as bounded, not unknown' (($withEnd.EndLine -eq 20) -and -not $withEnd.ExtentUnknown) "end=$($withEnd.EndLine) unknown=$($withEnd.ExtentUnknown)"
Check 'a row with "extent":"unknown" reads as unbounded BY THE ENGINE' (($unknownEnd.EndLine -eq 0) -and $unknownEnd.ExtentUnknown) "end=$($unknownEnd.EndLine) unknown=$($unknownEnd.ExtentUnknown)"
Check 'a row with neither reads as an old engine (no end, not said unknown)' (($oldEngine.EndLine -eq 0) -and -not $oldEngine.ExtentUnknown) "end=$($oldEngine.EndLine) unknown=$($oldEngine.ExtentUnknown)"
Check 'CONTROL: a routine row is read, a data row is skipped' `
  (($null -ne [ClarionDebugger.Terminal.ClarionDebuggerService]::ProcedureFromSymbol('{"name":"R","kind":"routine","line":12,"module":"m.clw"}')) -and `
   ($null -eq [ClarionDebugger.Terminal.ClarionDebuggerService]::ProcedureFromSymbol('{"name":"D","kind":"other","line":12,"module":"m.clw"}'))) ''
Check 'the list hands the engine''s "unknown" through to the id table (PushProcedures copies ExtentUnknown)' `
  ((Get-Method 'private void PushProcedures(string exe)' $web) -match 'ExtentUnknown = p\.ExtentUnknown') ''
Check 'the service reads an engine endLine when there is one, and treats one before the start as unknown' `
  (((Get-Method 'internal static DebugProcedure ProcedureFromSymbol(string obj)') -match 'GetIntOrNull\(obj, "endLine"\)') -and `
   ((Get-Method 'internal static DebugProcedure ProcedureFromSymbol(string obj)') -match 'end\.HasValue && end\.Value >= line\) \? end\.Value : 0')) ''
Check 'GetProcedures reads each row through ProcedureFromSymbol, the reader run above' `
  ((Get-Method 'public static List<DebugProcedure> GetProcedures(string targetExe)') -match 'ProcedureFromSymbol\(m\.Value\)') ''

# ---- edits, through the real page ---------------------------------------------------------------------
function Sets { param($pad) ($pad._svc.Sets -join ' ; ') }
$watchData = if ($pageOut) { DataOf $pageOut.watchEdit } else { '' }
$treeData  = if ($pageOut) { DataOf $pageOut.treeEdit } else { '' }
$pad._svc.Sets.Clear()
$pad.EditVar($watchData)
Check 'an edit on the Watch row the host sent is written' ($pad._svc.Sets.Count -eq 1) (Sets $pad)
Check 'with the tuple the host issued and the user''s value, untouched by the text inside it' `
  (($pad._svc.Sets.Count -eq 1) -and ($pad._svc.Sets[0] -ceq '0x4A10F0|0x03|4|0|4812|X","va":"0x1","value":"7')) (Sets $pad)

# CONSUMED (codex security gate): the write SPENDS its grant, so the identical request replayed is refused -
# a grant used to stay good for the whole pause.
$pad._svc.Sets.Clear()
$pad.EditVar($watchData)
Check 'the identical edit replayed is refused: the grant was spent by the first write' ($pad._svc.Sets.Count -eq 0) (Sets $pad)
# ...and the ENGINE's reply re-issues it, so the user can still edit the same row twice in one pause. The
# second request is the one the page really sends after its own onVarSet has repainted the cell.
$watchData2 = if ($pageOut) { DataOf $pageOut.watchEdit2 } else { '' }
$pad.OnSvcVariableSet('0x4A10F0', $true, '7', $null)
$pad._svc.Sets.Clear()
$pad.EditVar($watchData2)
Check 'edit, engine reply, edit again: the second edit through the pad is written' `
  (($pad._svc.Sets.Count -eq 1) -and ($pad._svc.Sets[0] -ceq '0x4A10F0|0x03|4|0|4812|second')) (Sets $pad)
# A refusal the HOST makes re-issues nothing: it spent nothing. Replay, refused, then replay again.
$pad.EditVar($watchData2); $pad._svc.Sets.Clear(); $pad.EditVar($watchData2)
Check 'a host refusal does not re-issue the grant (only the engine''s reply does)' ($pad._svc.Sets.Count -eq 0) (Sets $pad)
$pad.OnSvcVariableSet('0x4A10F0', $true, 'second', $null)   # the engine answers the second write
$pad._svc.Sets.Clear()
$pad.EditVar($treeData)
Check 'an edit on the NESTED Variables row is written - the grant reached inside children' `
  (($pad._svc.Sets.Count -eq 1) -and ($pad._svc.Sets[0] -ceq '0x4A2200|0x0A|4|2|4812|2.25')) (Sets $pad)

# Each part of the tuple is checked, one at a time, against the same real payload.
$tamper = @(
  @('an address the host never issued',         'va',       '"0x4A10F4"'),
  @('a type code the host never issued',        'typeCode', '"0x12"'),
  @('a size the host never issued',             'size',     '400'),
  @('a scale the host never issued',            'places',   '3'),
  @('a thread the row was not read on',         'tid',      '999')
)
foreach ($c in $tamper) {
  $d = $watchData -replace ('"' + $c[1] + '":("[^"]*"|\d+)'), ('"' + $c[1] + '":' + $c[2])
  $pad._svc.Sets.Clear(); $pad.Posts.Clear()
  $pad.EditVar($d)
  Check "refused: $($c[0])" (($d -cne $watchData) -and ($pad._svc.Sets.Count -eq 0)) (Sets $pad)
}
# A refusal is answered in the shape the engine's own refusal takes, so the page treats it as one.
Check 'and a refusal is answered with a failed varset naming the address' `
  (($pad.Posts.Count -ge 1) -and ($pad.Posts[0] -cmatch '"type":"varset","va":"0x4A10F0","ok":false')) ($pad.Posts -join ' / ')

# CURRENT: a thread switch retires every grant, and a failed switch retires none.
$pad.OnSvcThreadSelected(9001, $false, 'no such thread')
$pad._svc.Sets.Clear()
$pad.EditVar($watchData)
Check 'CONTROL: a switch the engine REFUSED leaves the grants alone' ($pad._svc.Sets.Count -eq 1) (Sets $pad)
Switched $pad 9001
$pad._svc.Sets.Clear()
$pad.EditVar($watchData)
Check 'after a thread switch the same edit is refused until the row is re-read' ($pad._svc.Sets.Count -eq 0) (Sets $pad)
# The write made just before that switch is answered AFTER it: the reply must not resurrect a grant for a row
# that is no longer current (the clear drops spent grants too).
$pad.OnSvcVariableSet('0x4A10F0', $true, '7', $null)
$pad._svc.Sets.Clear()
$pad.EditVar($watchData)
Check 'a reply arriving after the rows went stale re-issues nothing' ($pad._svc.Sets.Count -eq 0) (Sets $pad)

# A request the service would not send is said, not dropped: no varset would ever have come.
$pad.OnWatch($watch)
$pad._svc.AcceptSet = $false; $pad.Posts.Clear()
$pad.EditVar($watchData)
Check 'a write SetVariable refused is answered with a failed varset too' `
  (($pad.Posts.Count -ge 1) -and ($pad.Posts[0] -cmatch '"ok":false') -and ($pad.Posts[0] -cmatch 'did not take')) ($pad.Posts -join ' / ')
# That write never left, so no reply will come to re-issue its grant: it is re-issued at once.
$pad._svc.AcceptSet = $true; $pad._svc.Sets.Clear()
$pad.EditVar($watchData)
Check 'and a write that never left keeps its grant, so a retry goes through' ($pad._svc.Sets.Count -eq 1) (Sets $pad)

# The three other places a stop, resume or exit makes rows stale. Not reachable from this probe (they sit in
# UI lambdas with live-editor side effects), so they are pinned by POSITION: the clear must come before the
# re-reads that re-grant, or the fresh grants are wiped along with the stale ones.
$onPaused = Get-CSharpCodeOnly (Get-Method 'private void OnPaused(DebugPause p)' $web)
$webCode0 = Get-CSharpCodeOnly $web
$iClearP = $onPaused.IndexOf('_editGrants.Clear()'); $iReq = $onPaused.IndexOf('RequestStack();')
Check 'a new stop clears the grants BEFORE requesting the replies that re-grant' `
  (($iClearP -ge 0) -and ($iReq -gt $iClearP)) "clear=$iClearP request=$iReq"
# 49538b78 8b: the stopped thread is the selected one, and the SERVICE made it so before raising Paused
# (tools/test-addin-selection.ps1 runs that order). The pad keeps no selection of its own to set.
$tsel = Get-CSharpCodeOnly (Get-ArrowHandler 'private void OnSvcThreadSelected(')
Check 'an accepted thread switch clears the grants (the service has already moved the selection)' `
  ($tsel -match 'if \(ok\) _editGrants\.Clear\(\);') ''
Check 'the pad sets no selection of its own: EditGrants has no SelectThread, and nothing calls one' `
  (((Get-CSharpCodeOnly $hostGrants) -notmatch '\bSelectThread\s*\(') -and ($webCode0 -notmatch '_editGrants\.SelectThread')) ''
# An inventory that MOVED the selection has no handler of its own that clears (a stop and a switch do), so the
# pad's SelectionChanged handler does it: RUN, with the real handler over the real EditGrants.
$ivPad = New-Object ClarionDebugger.Terminal.BridgePad
$ivPad._sel.Stop(4812)
$ivPad._editGrants.Grant('0x4A10F0', '0x03', 4, 0, 4812)
$ivPad.OnSvcSelectionChanged((New-Object ClarionDebugger.Terminal.ThreadSelection ([Nullable[uint32]]4812), ([Nullable[uint32]]4812), 7, ([ClarionDebugger.Terminal.ThreadSelectionCause]::Stop)))
Check 'CONTROL: the stop''s own snapshot clears nothing here (OnPaused clears, positioned before its re-reads)' ($ivPad._editGrants.Count -eq 1) "$($ivPad._editGrants.Count) grant(s)"
$ivPad.OnSvcSelectionChanged((New-Object ClarionDebugger.Terminal.ThreadSelection ([Nullable[uint32]]9001), ([Nullable[uint32]]4812), 8, ([ClarionDebugger.Terminal.ThreadSelectionCause]::Inventory)))
Check 'an inventory that moved the selection retires every grant' ($ivPad._editGrants.Count -eq 0) "$($ivPad._editGrants.Count) grant(s)"
Check 'the pad subscribes and unsubscribes SelectionChanged, once each' `
  ((([regex]::Matches($webCode0, '_svc\.SelectionChanged\s*\+=\s*OnSvcSelectionChanged;')).Count -eq 1) -and `
   (([regex]::Matches($webCode0, '_svc\.SelectionChanged\s*-=\s*OnSvcSelectionChanged;')).Count -eq 1)) ''
Check 'the pad''s grant table reads the service''s selection' ($webCode0 -match '_editGrants = new EditGrants\(\(\) => _svc\.Selection\);') ''
$webCode = Get-CSharpCodeOnly $web
Check 'every stack request carries a recorded id: the page''s and the stop''s go through RequestStack, the only _svc.RequestStack call' `
  (($webCode -match 'case "stack": if \(_svc\.State == DebugSessionState\.Paused\) RequestStack\(\); break;') -and `
   ([regex]::Matches($webCode, '_svc\.RequestStack\(').Count -eq 1) -and `
   ((Get-CSharpCodeOnly (Get-Method 'private void RequestStack()' $web)) -match 'string id = _editGrants\.NewStackRequestId\(\);\s*if \(_svc\.RequestStack\(id\)\) _editGrants\.StackRequested\(id\);')) ''
# The service hands the reply's echo to the stack event. What it SENDS is run in the version-skew section below.
# -ServicePath's text, not a fixed path: a mutated copy handed to this suite has to be the one read here.
$svcCode = Get-CSharpCodeOnly $src
Check 'the service passes the stack reply''s reqId on' `
  ($svcCode -match 'StackReceived\?\.Invoke\(frames, GetUIntOrNull\(json, "tid"\), GetStr\(json, "reqId"\)\);') ''
Check 'a resume clears them' ((Get-CSharpCodeOnly (Get-ArrowHandler 'private void OnSvcResumed(')) -match '_editGrants\.Clear\(\)') ''
Check 'and so does the session ending' ((Get-CSharpCodeOnly (Get-ArrowHandler 'private void OnSvcExited(')) -match '_editGrants\.Clear\(\)') ''
Check 'the frame-locals and expand replies grant their rows only for a request the host verified' `
  (((Get-CSharpCodeOnly (Get-ArrowHandler 'private void OnSvcFrameLocals(')) -match 'if \(_editGrants\.FrameLocalsVerified\(reqId, tid\)\) _editGrants\.GrantRows\(itemsJson, tid\)') -and `
   ((Get-CSharpCodeOnly (Get-ArrowHandler 'private void OnSvcExpanded(')) -match 'if \(_editGrants\.ExpandVerified\(reqId\)\) _editGrants\.GrantRows\(itemsJson, null\)')) ''

# ---- one write per address at a time (codex security, pipeline run 2) ---------------------------------
# The varset reply names only the ADDRESS. With two issued tuples on one va (two type or thread views of it)
# and both writes in flight, the first reply re-issued the second write's grant before its own reply came.
# So a second write to an address whose write is pending is refused, and each reply restores exactly one.
$sp = New-Object ClarionDebugger.Terminal.BridgePad
$sp._editGrants.Grant('0x4A10F0', '0x03', 4, 0, 4812)          # view A of the address
$sp._editGrants.Grant('0x4A10F0', '0x12', 4, 0, 4812)          # view B of the SAME address
$editA = '{"va":"0x4A10F0","typeCode":"0x03","size":4,"places":0,"tid":4812,"value":"1"}'
$editB = '{"va":"0x4A10F0","typeCode":"0x12","size":4,"places":0,"tid":4812,"value":"2"}'
$sp.EditVar($editA)
Check 'CONTROL: the first write to the address goes out' ($sp._svc.Sets.Count -eq 1) ($sp._svc.Sets -join ' ; ')
$sp.Posts.Clear()
$sp.EditVar($editB)
Check 'a second write to the same address, under its OWN grant, is refused while the first is pending' `
  (($sp._svc.Sets.Count -eq 1) -and ($sp.Posts.Count -eq 1) -and ($sp.Posts[0] -cmatch 'still pending')) ($sp.Posts -join ' / ')
$sp.OnSvcVariableSet('0x4A10F0', $true, '1', $null)          # the engine answers write A
$sp.EditVar($editB)
Check 'after the reply, the second write proceeds' (($sp._svc.Sets.Count -eq 2) -and ($sp._svc.Sets[1] -cmatch '\|0x12\|')) ($sp._svc.Sets -join ' ; ')
# ...and the reply to A restored A ONLY: with B now in flight, A is refused as pending, not written twice.
$sp.Posts.Clear()
$sp.EditVar($editA)
Check 'and A is refused while B is pending: each reply restored exactly its own grant' `
  (($sp._svc.Sets.Count -eq 2) -and ($sp.Posts[0] -cmatch 'still pending')) ($sp.Posts -join ' / ')
# The WRITER holds the rule too, not only EditVar: TryConsume itself will not spend a second grant on a
# pending address.
$g2 = (New-Object ClarionDebugger.Terminal.SelectionSource).Grants
$g2.Grant('0x10', '0x03', 4, 0, 5); $g2.Grant('0x10', '0x12', 4, 0, 5)
$first = $g2.TryConsume('0x10', '0x03', 4, 0, 5)
Check 'EditGrants.TryConsume refuses a second spend on an address whose write is pending' `
  ($first -and -not $g2.TryConsume('0x10', '0x12', 4, 0, 5)) "first=$first"
# ---- expand is issued like edit (afbc68c7, codex security gate) --------------------------------------
# A forged expand needs no host-issued row: name a known group type at ANY address and the engine renders its
# members WITH edit metadata. Forwarded unchecked, those replies minted grants, and EditVar trusts grants.
# So the host records the expandable rows it issues, forwards only those, and grants an expand reply's rows
# only when it forwarded that very request.
$expandData = if ($pageOut) { DataOf $pageOut.expand } else { '' }
Check 'the page asks to expand the reference row exactly as the host sent it' ($expandData -ceq '1|clbrws011.clw|77|0x4B0000') $expandData
$xp = New-Object ClarionDebugger.Terminal.BridgePad
$xp.OnSvcModuleData('clbrws011.clw', $engineRows, 4812)
Check 'CONTROL: the host recorded the reference row as expandable' ($xp._editGrants.ExpandableCount -eq 1) "$($xp._editGrants.ExpandableCount)"
$xp.Expand($expandData)
Check 'an issued reference row is expanded' (($xp._svc.Expands.Count -eq 1) -and ($xp._svc.Expands[0] -ceq '1|clbrws011.clw|77|0x4B0000')) ($xp._svc.Expands -join ',')
$children = '{"name":"P:N","type":"LONG","value":"3","va":"0x4B0004","typeCode":"0x03","size":4,"places":0},{"name":"P:SUB","type":"","value":"0x4C0000","ref":true,"addr":"0x4C0000","module":"clbrws011.clw","typeRef":78}'
$xp.OnSvcExpanded('1', $children)
$xp.EditVar('{"va":"0x4B0004","typeCode":"0x03","size":4,"places":0,"tid":4812,"value":"9"}')
Check 'and the verified reply''s members are editable' ($xp._svc.Sets.Count -eq 1) ($xp._svc.Sets -join ' ; ')
$xp.Expand('2|clbrws011.clw|78|0x4C0000')
Check 'and its nested reference can be opened in turn (expand is recursive)' ($xp._svc.Expands.Count -eq 2) ($xp._svc.Expands -join ',')

# THE FORGERY: the same real type, at an address the host never offered.
$xp._svc.Expands.Clear(); $xp.Posts.Clear(); $xp.Lines.Clear()
$xp.Expand('3|clbrws011.clw|77|0x500000')
Check 'a forged expand (an issued type at a non-issued address) is not forwarded' ($xp._svc.Expands.Count -eq 0) ($xp._svc.Expands -join ',')
Check 'and is answered: an empty, refused reply for that reqId, and a console line' `
  (($xp.Posts.Count -eq 1) -and ($xp.Posts[0] -cmatch '"type":"expanded","reqId":"3","items":\[\],"refused":true') -and (@(Errs $xp).Count -eq 1)) ($xp.Posts -join ' / ')
# Even if an engine reply for it arrived anyway, the host never forwarded it, so its rows grant nothing.
$xp.OnSvcExpanded('3', '{"name":"F:N","type":"LONG","value":"0","va":"0x500004","typeCode":"0x03","size":4,"places":0}')
$xp._svc.Sets.Clear()
$xp.EditVar('{"va":"0x500004","typeCode":"0x03","size":4,"places":0,"tid":4812,"value":"9"}')
Check 'a reply to an expand the host did not forward creates no edit grant' ($xp._svc.Sets.Count -eq 0) ($xp._svc.Sets -join ' ; ')
# CURRENT, as for edits: a thread switch retires the issued expandable rows.
Switched $xp 9001
$xp._svc.Expands.Clear()
$xp.Expand($expandData)
Check 'after a thread switch the old reference row cannot be expanded until re-read' ($xp._svc.Expands.Count -eq 0) ($xp._svc.Expands -join ',')

# ---- frame locals are issued like expand (49538b78 wave 5, codex adversary) ---------------------------
# A framelocals request names a procedure VA and an EBP, and the engine renders that procedure's locals at
# EBP + each local's offset WITH edit metadata. Forwarded unchecked, a real VA and a made-up EBP minted edit
# grants at addresses the page chose. Now the host forwards only a (va, ebp) its own stack reply offered, and
# grants a reply's rows only when it forwarded that very request. Every hop real: OnStack's post and its
# offer (the follow probe), the page's requestFrameLocals, then FrameLocals, OnSvcFrameLocals and EditVar.
Check 'OnStack offers every frame it posts, with that reply''s thread and request id' `
  (($flProbe._editGrants.Calls -eq 1) -and ($flProbe._editGrants.Tid -eq 4812) -and ($flProbe._editGrants.ReqId -ceq '5') -and `
   (($flProbe._editGrants.Frames -join ',') -ceq '0x401000|0x19FF00,0x402000|0x19FF40,0x403000|0x0')) `
  ("tid=$($flProbe._editGrants.Tid) reqId=$($flProbe._editGrants.ReqId) " + ($flProbe._editGrants.Frames -join ','))
$flData = if ($pageOut) { DataOf $pageOut.framelocals } else { '' }
Check 'the page asks for the caller frame''s locals exactly as the host posted it' ($flData -ceq '1|0x402000|0x19FF40') $flData
# A stack reply for $tid carrying $offers. With no -ReqId it answers a stack request the host sends (and
# records) just before; with -ReqId it echoes that id as given, whatever was requested. It offers only when
# $tid is the selected thread: callers select it. Returns whether it offered.
function Offer { param($grants, $offers, $tid, $ReqId = 'auto')
  $kv = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
  foreach ($o in $offers) { $p = $o -split '\|'; $kv.Add((New-Object 'System.Collections.Generic.KeyValuePair[string,string]' $p[0], $p[1])) }
  if ($ReqId -ceq 'auto') { $ReqId = $grants.NewStackRequestId(); $grants.StackRequested($ReqId) }
  $grants.OfferFrames($tid, $ReqId, $kv)
}
function StackAsked { param($grants) $id = $grants.NewStackRequestId(); $grants.StackRequested($id); $id }
# One local of CALLER at its real EBP (0x19FF40 - 8), and the same local at forged EBPs. Each check below
# edits its OWN address: a write one check let through leaves that address pending, and a later check on it
# would then be refused for that reason instead of the one it names.
function LocalAt { param($va) '{"name":"L:N","type":"LONG","value":"1","va":"' + $va + '","typeCode":"0x03","size":4,"places":0}' }
function EditAt  { param($va) '{"va":"' + $va + '","typeCode":"0x03","size":4,"places":0,"tid":4812,"value":"9"}' }
$realLocal = LocalAt '0x19FF38'; $editReal = EditAt '0x19FF38'

$fp = New-Object ClarionDebugger.Terminal.BridgePad
$fp._sel.Stop(4812)   # the stop's thread (OnPaused)
[void](Offer $fp._editGrants $flProbe._editGrants.Frames 4812)
$fp.FrameLocals($flData)
Check 'an offered frame''s locals are requested' `
  (($fp._svc.FrameLocalsSent.Count -eq 1) -and ($fp._svc.FrameLocalsSent[0] -ceq '1|0x402000|0x19FF40')) ($fp._svc.FrameLocalsSent -join ',')
$fp.OnSvcFrameLocals('1', $realLocal, 4812)
$fp.EditVar($editReal)
Check 'and the verified reply''s locals are editable' ($fp._svc.Sets.Count -eq 1) ($fp._svc.Sets -join ' ; ')

# THE FORGERY: a real procedure VA, at an EBP no stack reply offered.
$fp._svc.FrameLocalsSent.Clear(); $fp.Posts.Clear(); $fp.Lines.Clear()
$fp.FrameLocals('2|0x402000|0x500000')
Check 'a forged framelocals (an offered VA at a non-offered EBP) is not forwarded' ($fp._svc.FrameLocalsSent.Count -eq 0) ($fp._svc.FrameLocalsSent -join ',')
Check 'and is answered: an empty, refused reply for that reqId, and a console line' `
  (($fp.Posts.Count -eq 1) -and ($fp.Posts[0] -cmatch '^\{"type":"framelocals","reqId":"2","items":\[\],"refused":true\}$') -and (@(Errs $fp).Count -eq 1)) ($fp.Posts -join ' / ')
# Even if an engine reply for it arrived anyway, the host never forwarded it: shown, and grants nothing.
$fp.Posts.Clear(); $fp._svc.Sets.Clear()
$fp.OnSvcFrameLocals('2', (LocalAt '0x4FFFF8'), 4812)
$fp.EditVar((EditAt '0x4FFFF8'))
Check 'a reply to a framelocals the host did not forward creates no edit grant' ($fp._svc.Sets.Count -eq 0) ($fp._svc.Sets -join ' ; ')
Check 'CONTROL: that reply was still posted for display' (($fp.Posts.Count -ge 1) -and ($fp.Posts[0] -cmatch '"type":"framelocals","reqId":"2","items":\[\{"name":"L:N"')) ($fp.Posts -join ' / ')
# A reqId the host never saw at all grants nothing either.
$fp._svc.Sets.Clear()
$fp.OnSvcFrameLocals('77', (LocalAt '0x4FFFE8'), 4812)
$fp.EditVar((EditAt '0x4FFFE8'))
Check 'a reply whose reqId was never verified creates no edit grant' ($fp._svc.Sets.Count -eq 0) ($fp._svc.Sets -join ' ; ')
# CONSUMED: a verified reqId grants once. A second reply under the same id is not the one the host asked for.
$fp.FrameLocals('5|0x402000|0x19FF40')
$fp.OnSvcFrameLocals('5', $realLocal, 4812)
$fp._svc.Sets.Clear()
$fp.OnSvcFrameLocals('5', (LocalAt '0x4FFFD8'), 4812)
$fp.EditVar((EditAt '0x4FFFD8'))
Check 'a verified reqId grants once: a second reply under it creates no edit grant' ($fp._svc.Sets.Count -eq 0) ($fp._svc.Sets -join ' ; ')
# An EBP the engine could not recover (0x0) is offered by nobody: the page never asks about one.
$fp._svc.FrameLocalsSent.Clear()
$fp.FrameLocals('6|0x403000|0x0')
Check 'a frame posted with the unknown EBP 0x0 is not an offer' ($fp._svc.FrameLocalsSent.Count -eq 0) ($fp._svc.FrameLocalsSent -join ',')
# A request the service would not send is answered, and recorded as nothing.
$fp._svc.AcceptFrameLocals = $false; $fp.Posts.Clear(); $fp._svc.Sets.Clear()
$fp.FrameLocals('8|0x401000|0x19FF00')
$fp._svc.AcceptFrameLocals = $true
Check 'a request the service refused is answered with an empty, refused reply' `
  (($fp.Posts.Count -eq 1) -and ($fp.Posts[0] -cmatch '"reqId":"8","items":\[\],"refused":true') -and ($fp.Lines[$fp.Lines.Count - 1] -cmatch 'did not take')) ($fp.Posts -join ' / ')
$fp.OnSvcFrameLocals('8', (LocalAt '0x4FFFC8'), 4812)
$fp.EditVar((EditAt '0x4FFFC8'))
Check 'and a reply under its reqId creates no edit grant' ($fp._svc.Sets.Count -eq 0) ($fp._svc.Sets -join ' ; ')

# CURRENT, as for edits and expands. A thread's NEXT stack reply replaces its offer: a frame that has left
# the stack cannot be asked about.
$fp._svc.FrameLocalsSent.Clear()
[void](Offer $fp._editGrants @('0x401000|0x19FF00') 4812)
$fp.FrameLocals('9|0x402000|0x19FF40')
Check 'a thread''s next stack reply replaces its offer: a frame no longer on it is refused' ($fp._svc.FrameLocalsSent.Count -eq 0) ($fp._svc.FrameLocalsSent -join ',')
# A request forwarded before a thread switch is answered AFTER it: the clear retired that request, so its
# reply grants nothing...
$fp.FrameLocals('10|0x401000|0x19FF00')
Check 'CONTROL: the frame still on the stack is forwarded' ($fp._svc.FrameLocalsSent.Count -eq 1) ($fp._svc.FrameLocalsSent -join ',')
Switched $fp 9001
$fp._svc.Sets.Clear()
$fp.OnSvcFrameLocals('10', (LocalAt '0x19FF34'), 4812)
$fp.EditVar((EditAt '0x19FF34'))
Check 'a reply to a request forwarded before the switch creates no edit grant' ($fp._svc.Sets.Count -eq 0) ($fp._svc.Sets -join ' ; ')
# ...and the clear retired the offer too: the previous stop's frame is refused until a stack re-offers it.
$fp._svc.FrameLocalsSent.Clear()
$fp.FrameLocals('11|0x401000|0x19FF00')
Check 'after the switch a frame from the previous offer is refused' ($fp._svc.FrameLocalsSent.Count -eq 0) ($fp._svc.FrameLocalsSent -join ',')
# EditGrants on its own: Clear retires offers and forwarded requests, whoever calls it (a stop, a resume).
$gfSel = New-Object ClarionDebugger.Terminal.SelectionSource; $gf = $gfSel.Grants
$gfSel.Stop(7)
[void](Offer $gf @('0x401000|0x19FF00') 7)
$gf.FrameLocalsForwarded(1)
$gf.Clear()
Check 'EditGrants.Clear retires the offered frames and the forwarded framelocals' `
  ((-not $gf.IsFrameOffered('0x401000', '0x19FF00')) -and (-not $gf.FrameLocalsVerified('1', 7))) ''
[void](Offer $gf @('0x40100A|0x19FF0B') 7)
Check 'CONTROL: an offered frame matches without regard to hex case' ($gf.IsFrameOffered('0x40100a', '0x19ff0b')) ''

# ---- an offer belongs to the SELECTED thread and the current epoch (49538b78 wave 5 run 2) --------------
# framelocals names no thread. Every stack reply used to offer its frames whatever thread it was for, so a
# late reply for thread A, landing after a switch to B, re-offered A's (va, ebp): the page's request for it
# was forwarded, and the engine rendered A's locals at A's EBP in a reply stamped and granted for B - stale
# cross-thread stack addresses, editable. Every path real: OnSvcThreadSelected, EditGrants, FrameLocals,
# OnSvcFrameLocals and EditVar.
$rp = New-Object ClarionDebugger.Terminal.BridgePad
$rp._sel.Stop(4812)                     # stopped on A (4812)
$idA = StackAsked $rp._editGrants                      # the page asks for A's stack...
Switched $rp 9001            # ...switches to B (9001) before it is answered...
$idB = StackAsked $rp._editGrants                      # ...and asks for B's
$aLate = Offer $rp._editGrants @('0x402000|0x19FF40') 4812 -ReqId $idA    # A's reply lands after the switch
Check 'a stale stack reply for the OLD thread, after the switch, offers nothing' (-not $aLate) ''
$rp.FrameLocals('20|0x402000|0x19FF40')
Check 'and a framelocals for its frame is refused, not forwarded' `
  (($rp._svc.FrameLocalsSent.Count -eq 0) -and ($rp.Posts.Count -ge 1) -and ($rp.Posts[$rp.Posts.Count - 1] -cmatch '"reqId":"20","items":\[\],"refused":true')) `
  (($rp._svc.FrameLocalsSent -join ',') + ' / ' + ($rp.Posts -join ' / '))
$rp.OnSvcFrameLocals('20', (LocalAt '0x19FF30'), 9001)
$rp.EditVar('{"va":"0x19FF30","typeCode":"0x03","size":4,"places":0,"tid":9001,"value":"9"}')
Check 'and a reply under its reqId, stamped for the new thread, creates no edit grant' ($rp._svc.Sets.Count -eq 0) ($rp._svc.Sets -join ' ; ')
# CONTROL, the genuine flow on the new thread: B's own reply to the counted request offers, is forwarded,
# and its verified reply's locals are editable.
$bOwn = Offer $rp._editGrants @('0x405000|0x2AFF40') 9001 -ReqId $idB
$rp.FrameLocals('21|0x405000|0x2AFF40')
$rp.OnSvcFrameLocals('21', (LocalAt '0x2AFF38'), 9001)
$rp.EditVar('{"va":"0x2AFF38","typeCode":"0x03","size":4,"places":0,"tid":9001,"value":"9"}')
Check 'CONTROL: the new thread''s own stack reply offers, and its frame''s locals are forwarded and editable' `
  ($bOwn -and ($rp._svc.FrameLocalsSent.Count -eq 1) -and ($rp._svc.Sets.Count -eq 1)) `
  ("offered=$bOwn sent=" + ($rp._svc.FrameLocalsSent -join ',') + " sets=" + ($rp._svc.Sets -join ' ; '))

# THE REGRESSION (run 3, codex security + adversary): freshness proven by a COUNT let a stale reply for the
# SAME thread spend the fresh request. A's stack is asked for, the page switches to B and back to A (each
# switch a clear), asks again, and the OLD A reply arrives first: same tid, so only its id tells it apart.
$cx = New-Object ClarionDebugger.Terminal.BridgePad
$cx._sel.Stop(4812)
$old = StackAsked $cx._editGrants
Switched $cx 9001
Switched $cx 4812
$new = StackAsked $cx._editGrants
$stale = Offer $cx._editGrants @('0x402000|0x19FF40') 4812 -ReqId $old
Check 'THE REGRESSION: an old reply for the SAME thread, arriving before the fresh one, offers nothing' (-not $stale) ''
$cx.FrameLocals('40|0x402000|0x19FF40')
Check 'and a framelocals for its frame is refused' `
  (($cx._svc.FrameLocalsSent.Count -eq 0) -and ($cx.Posts[$cx.Posts.Count - 1] -cmatch '"reqId":"40","items":\[\],"refused":true')) `
  (($cx._svc.FrameLocalsSent -join ',') + ' / ' + ($cx.Posts -join ' / '))
$fresh = Offer $cx._editGrants @('0x402000|0x19FE40') 4812 -ReqId $new
$cx.FrameLocals('41|0x402000|0x19FE40')
$cx.OnSvcFrameLocals('41', (LocalAt '0x19FE38'), 4812)
$cx.EditVar((EditAt '0x19FE38'))
Check 'CONTROL: the fresh reply then offers, and its frame''s locals are forwarded and editable' `
  ($fresh -and ($cx._svc.FrameLocalsSent.Count -eq 1) -and ($cx._svc.Sets.Count -eq 1)) `
  ("offered=$fresh sent=" + ($cx._svc.FrameLocalsSent -join ',') + " sets=" + ($cx._svc.Sets -join ' ; '))

# THE EPOCH: a stack reply to a request sent before a clear (a stop, a resume, a switch) offers nothing, even
# for the same thread; only a request recorded after the clear can be answered with an offer.
$epSel = New-Object ClarionDebugger.Terminal.SelectionSource; $ep = $epSel.Grants
$epSel.Stop(4812)
$before = StackAsked $ep
$ep.Clear()
$preBump = Offer $ep @('0x402000|0x19FF40') 4812 -ReqId $before
Check 'a stack reply requested before the epoch bump offers nothing, even for the selected thread' `
  ((-not $preBump) -and (-not $ep.IsFrameOffered('0x402000', '0x19FF40'))) "offered=$preBump"
$after = StackAsked $ep
$postBump = Offer $ep @('0x402000|0x19FF40') 4812 -ReqId $after
Check 'CONTROL: a reply to a request recorded after the bump offers' ($postBump -and $ep.IsFrameOffered('0x402000', '0x19FF40')) "offered=$postBump"
# An id is answered ONCE: a second reply under it is not an answer to anything.
$second = Offer $ep @('0x403000|0x19FF80') 4812 -ReqId $after
Check 'a reused (already answered) request id offers nothing' ((-not $second) -and $ep.IsFrameOffered('0x402000', '0x19FF40')) "offered=$second"
# A reply with no id (an engine that does not echo one, or a stack nobody asked for) offers nothing, even while
# a request is outstanding.
$pending = StackAsked $ep
$noId = Offer $ep @('0x404000|0x19FFC0') 4812 -ReqId ([NullString]::Value)
$neverSent = Offer $ep @('0x404000|0x19FFC0') 4812 -ReqId '999999'
Check 'a reply without a reqId, or with an id never sent, offers nothing' `
  ((-not $noId) -and (-not $neverSent) -and (-not $ep.IsFrameOffered('0x404000', '0x19FFC0'))) "noId=$noId neverSent=$neverSent"
# A LIVE id is still refused when the reply is stamped for a thread other than the selected one.
$wt = StackAsked $ep
$wrongTid = Offer $ep @('0x405000|0x19FFE0') 9001 -ReqId $wt
Check 'a reply echoing a live request id but stamped for another thread offers nothing' `
  ((-not $wrongTid) -and (-not $ep.IsFrameOffered('0x405000', '0x19FFE0'))) "offered=$wrongTid"
Check 'request ids are never reused, across clears too' `
  (($before -cne $after) -and ($after -cne $pending) -and ($before -cne $pending)) "$before,$after,$pending"

# THE SELECTION EPOCH (49538b78 8b). A stack request remembers the service's selection epoch it was sent
# under, so a selection that moved and came back - A, B, A with no clear between, which is what an inventory
# that disagreed and then a switch back can do - leaves the old request unable to offer, though its id is live
# and its stamp is the selected thread. Only the epoch tells it apart.
$seS = New-Object ClarionDebugger.Terminal.SelectionSource; $se = $seS.Grants
$seS.Stop(4812)
$seOld = StackAsked $se
$seS.Switch(9001); $seS.Switch(4812)
$seStale = Offer $se @('0x402000|0x19FF40') 4812 -ReqId $seOld
Check 'a stack request sent under an earlier selection epoch offers nothing, even for the same thread and with no clear between' `
  ((-not $seStale) -and (-not $se.IsFrameOffered('0x402000', '0x19FF40'))) "offered=$seStale"
$seNew = StackAsked $se
$seFresh = Offer $se @('0x402000|0x19FF40') 4812 -ReqId $seNew
Check 'CONTROL: one sent under the current selection offers' ($seFresh -and $se.IsFrameOffered('0x402000', '0x19FF40')) "offered=$seFresh"

# ---- version skew: a new add-in on an engine from before wave 5 (97f23f5d) ------------------------------
# cb2fcea sent `stack reqid=N`. An engine from before wave 5 reads the FIRST argument as the frame count, so it
# refused that request and a new add-in on an old engine showed no call stack at all. The host now names the
# count first, `stack 32 reqid=N`, and the old engine ignores the trailing token. Run: the REAL RequestStack
# over a recording SendCommand, and the REAL ParseStack / GetStr on the reply each engine sends.
$skewReader = (Get-Method 'internal static class JsonMessageReader' $readerEarly) -replace 'internal static class', 'public static class'
$skewSrc = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
namespace StackSkew {
$(Get-Method 'public sealed class DebugStackFrame')
public class StackSkewProbe {
  public string Sent;
  private bool SendCommand(string c) { Sent = c; return true; }
  $((Get-Statement 'internal const int StackFrameCount') -replace '^internal', 'public')
  $(Get-Method 'public bool RequestStack(string reqId = null)')
  $((Get-Method 'private static List<DebugStackFrame> ParseStack(string json)') -replace '^private static', 'public static')
  $((Get-Method 'private static string GetStr(string json, string key)') -replace '^private static', 'public static')
  $(Get-Method 'private static int GetInt(string json, string key)')
  $(Get-Method 'private static bool GetBool(string json, string key)')
  $skewReader
}
}
"@
Add-Type -TypeDefinition $skewSrc -Language CSharp | Out-Null
$sk = New-Object StackSkew.StackSkewProbe
Check 'the host''s stack frame count is 32, the engine default protocolcheck pins (CheckStackFrameCountSkew)' `
  ([StackSkew.StackSkewProbe]::StackFrameCount -eq 32) "$([StackSkew.StackSkewProbe]::StackFrameCount)"
[void]$sk.RequestStack('7')
Check 'a stack request with an id names the count FIRST: `stack 32 reqid=7`' ($sk.Sent -ceq 'stack 32 reqid=7') (ShowVal $sk.Sent)
$skNoId = New-Object StackSkew.StackSkewProbe
[void]$skNoId.RequestStack()
Check 'and one without an id names the count alone' ($skNoId.Sent -ceq 'stack 32') (ShowVal $skNoId.Sent)
# The pre-wave-5 argument rule, as it stood before cb2fcea (DebugEngine.StackWalker.cs HandleStackCommand):
#   if (parts.Length > 1 && (!int.TryParse(parts[1], out max) || max < 1 || max > STACK_FRAMES_MAX)) refuse;
# and nothing read parts[2]. Applied here to the text the host now sends, and to what cb2fcea sent.
function OldEngineTakes { param([string] $line)
  $parts = $line.Split(' '); $n = 0
  ($parts.Length -le 1) -or ([int]::TryParse($parts[1], [ref] $n) -and $n -ge 1 -and $n -le 256)
}
Check 'CONTROL: the old engine refused what cb2fcea sent (`stack reqid=7`)' (-not (OldEngineTakes 'stack reqid=7')) ''
Check 'the old engine takes what the host sends now' (OldEngineTakes $sk.Sent) (ShowVal $sk.Sent)
# The old engine's reply carries no reqId; the new one echoes the id (the engine side is protocolcheck's).
$oldReply = '{"tid":4812,"event":"stack","frames":[{"frame":0,"proc":"MAIN","module":"main.clw","line":88,"va":"0x402000","ebp":"0x19FF40"}]}'
$newReply = '{"tid":4812,"event":"stack","reqId":"7","frames":[{"frame":0,"proc":"MAIN","module":"main.clw","line":88,"va":"0x402000","ebp":"0x19FF40"}]}'
$oldFrames = [StackSkew.StackSkewProbe]::ParseStack($oldReply)
$oldId = [StackSkew.StackSkewProbe]::GetStr($oldReply, 'reqId')
Check 'an old engine''s reply (no reqId) still yields its stack' (($oldFrames.Count -eq 1) -and ($oldFrames[0].Proc -ceq 'MAIN')) "$($oldFrames.Count) frame(s)"
$sgSel = New-Object ClarionDebugger.Terminal.SelectionSource; $sg = $sgSel.Grants
$sgSel.Stop(4812)
[void](StackAsked $sg)
$oldOffered = Offer $sg @('0x402000|0x19FF40') 4812 -ReqId $oldId
Check 'and offers no frames: degraded, not dead' ((-not $oldOffered) -and (-not $sg.IsFrameOffered('0x402000', '0x19FF40'))) "reqId=$(ShowVal $oldId) offered=$oldOffered"
$newId = StackAsked $sg
$newEcho = $newReply -replace '"reqId":"7"', ('"reqId":"' + $newId + '"')
$newGot = [StackSkew.StackSkewProbe]::GetStr($newEcho, 'reqId')
$newOffered = Offer $sg @('0x402000|0x19FF40') 4812 -ReqId $newGot
Check 'CONTROL: a current engine''s reply echoes the id, and offers' (($newGot -ceq $newId) -and $newOffered -and $sg.IsFrameOffered('0x402000', '0x19FF40')) "reqId=$(ShowVal $newGot) offered=$newOffered"

# THE REPLY'S THREAD: a forwarded request grants only a reply stamped for the thread of the offer it was
# checked against; any other thread's stamp grants nothing.
$tp = New-Object ClarionDebugger.Terminal.BridgePad
$tp._sel.Stop(4812)
[void](Offer $tp._editGrants @('0x402000|0x19FF40') 4812)
$tp.FrameLocals('30|0x402000|0x19FF40')
$tp.OnSvcFrameLocals('30', (LocalAt '0x19FF2C'), 9001)
$tp.EditVar('{"va":"0x19FF2C","typeCode":"0x03","size":4,"places":0,"tid":9001,"value":"9"}')
$tp.EditVar((EditAt '0x19FF2C'))
Check 'a framelocals reply stamped for another thread than its offer''s creates no edit grant' `
  (($tp._svc.FrameLocalsSent.Count -eq 1) -and ($tp._svc.Sets.Count -eq 0)) (($tp._svc.FrameLocalsSent -join ',') + ' / ' + ($tp._svc.Sets -join ' ; '))

Check 'the bridge routes framelocals through the checked FrameLocals, not straight to the service' `
  (((Get-CSharpCodeOnly $web) -match 'case "framelocals": FrameLocals\(data\); break;') -and `
   ([regex]::Matches((Get-CSharpCodeOnly $web), '_svc\.RequestFrameLocals\(').Count -eq 1)) ''

# ---- the grant walker on its own ----------------------------------------------------------------------
$g = (New-Object ClarionDebugger.Terminal.SelectionSource).Grants
$g.GrantRows('{"va":"0x10","typeCode":"0x03","size":4,"places":0},{"name":"x","children":[{"va":"0x20","typeCode":"0x03","size":4}]}', $null)
Check 'unscoped rows (an expanded reference) grant for any thread' `
  ($g.IsGranted('0x10', '0x03', 4, 0, 77) -and $g.IsGranted('0x20', '0x03', 4, 0, $null)) "$($g.Count) grant(s)"
$g2 = (New-Object ClarionDebugger.Terminal.SelectionSource).Grants
$g2.GrantRows('{"va":"0x10","typeCode":"0x03","size":4,"places":0},{"va":"0x20",', 5)
Check 'a malformed reply grants NOTHING, not the rows before the fault' ($g2.Count -eq 0) "$($g2.Count) grant(s)"
$g3 = (New-Object ClarionDebugger.Terminal.SelectionSource).Grants
$g3.Grant('0x10', '0x03', 4, 0, 5)
Check 'a thread-scoped grant does not answer a page with no thread selection' (-not $g3.IsGranted('0x10', '0x03', 4, 0, $null)) ''
Check 'CONTROL: ...and does answer its own thread' ($g3.IsGranted('0x10', '0x03', 4, 0, 5)) ''
# ONE tuple reader (6ac29815 #2): the grant and the edit read size/places with PageNumbers.ReadEditTuple, so a
# row the engine sent and the page's echo of it agree, whichever member is missing or malformed. Run, per
# shape: grant the row, then parse the page's edit carrying the same members.
foreach ($t in @('"size":4,"places":2', '"size":4', '"places":2', '"size":"4","places":"x"', '"size":4,"places":null', '')) {
  $sep = if ($t) { ',' } else { '' }
  $gt = (New-Object ClarionDebugger.Terminal.SelectionSource).Grants
  $gt.GrantRows('{"va":"0x30","typeCode":"0x03"' + $sep + $t + '}', 5)
  $er = [ClarionDebugger.Terminal.EditVarRequest]::Parse('{"va":"0x30","typeCode":"0x03"' + $sep + $t + ',"tid":5,"value":"1"}')
  Check "edit tuple {$t}: the grant and the page's echo of it read the same size and places" `
    (($null -ne $er) -and $gt.IsGranted($er.Va, $er.TypeCode, $er.Size, $er.Places, $er.Tid)) "size=$($er.Size) places=$($er.Places)"
}
Check 'and both read it through PageNumbers.ReadEditTuple' `
  (((Get-Method 'public static EditVarRequest Parse(string data)' $pageMsgs) -match 'PageNumbers\.ReadEditTuple\(data, out size, out places\)') -and `
   ((Get-Method 'public void GrantRows(string itemsJson, uint? tid)' $hostGrants) -match 'PageNumbers\.ReadEditTuple\(o, out size, out places\)')) ''

# ---- the other request DTOs ---------------------------------------------------------------------------
# These payloads are delimiter strings, parsed exactly as before and now in one place each. Checked on the
# shapes the page builds and on the malformed shapes each one must drop.
$x = [ClarionDebugger.Terminal.ExpandRequest]::Parse('7|clbrws011.clw|123|0x4A0000')
Check 'expand: reqId|module|typeRef|addr reads as four typed fields' `
  (($null -ne $x) -and $x.ReqId -eq 7 -and $x.Module -ceq 'clbrws011.clw' -and $x.TypeRef -eq 123 -and $x.Addr -ceq '0x4A0000') ''
Check 'expand: a wrong field count, or a typeRef that is not a number, is dropped' `
  (($null -eq [ClarionDebugger.Terminal.ExpandRequest]::Parse('7|m|123')) -and ($null -eq [ClarionDebugger.Terminal.ExpandRequest]::Parse('7|m|-1|0x1'))) ''
$fl = [ClarionDebugger.Terminal.FrameLocalsRequest]::Parse('3|0x401000|0x19FF00')
Check 'framelocals: reqId|va|ebp reads as three typed fields' (($null -ne $fl) -and $fl.ReqId -eq 3 -and $fl.Ebp -ceq '0x19FF00') ''
$ml = [ClarionDebugger.Terminal.ModuleLineRequest]::Parse('a:b.clw:12')
Check 'module:line splits on the LAST colon' (($null -ne $ml) -and $ml.Module -ceq 'a:b.clw' -and $ml.Line -eq 12) ''
Check 'module:line with no module, or no number, is dropped' `
  (($null -eq [ClarionDebugger.Terminal.ModuleLineRequest]::Parse(':12')) -and ($null -eq [ClarionDebugger.Terminal.ModuleLineRequest]::Parse('m.clw:x'))) ''
$ob = [ClarionDebugger.Terminal.OpenBpRequest]::Parse("42`tC:\src\m.clw")
Check 'openbp: line<TAB>path' (($null -ne $ob) -and $ob.Line -eq 42 -and $ob.Path -ceq 'C:\src\m.clw') ''
# attach (3f2d747f part C): the data is the pid in decimal, as the picker sends it. The parsed pid is only a
# lookup key into the host's own listing; tools/test-addin-attach.ps1 covers that gate.
$at = [ClarionDebugger.Terminal.AttachRequest]::Parse('4242')
Check 'attach: a decimal pid reads as a uint' (($null -ne $at) -and $at.Pid -eq 4242) ''
Check 'attach: pid 0, a sign, a second word, hex or an empty payload is dropped' `
  ((@('0', '-1', '+7', '4242 quit', '4242;quit', '0x10', '', $null) | ForEach-Object { $null -eq [ClarionDebugger.Terminal.AttachRequest]::Parse($_) }) -notcontains $false) ''
Check 'attach: the page sends exactly the shape the host parses (the pid as a decimal string)' `
  ((Get-Content -Raw -LiteralPath $PagePath) -match "send\('attach', String\(pid\)\);") ''

# ---- the Memory panel's read (ticket 633d8b2f) --------------------------------------------------------
# The one request whose ADDRESS the page chooses freely, so the gate is the shape: hex with its 0x, 32 bits,
# 1..MaxLen bytes. RequestMem's doc comment carries the security reasoning; these hold it to its rules.
$mr = [ClarionDebugger.Terminal.MemRequest]::Parse('4|0x401000|256')
Check 'mem: reqId|0xADDR|len reads as three typed fields' `
  (($null -ne $mr) -and $mr.ReqId -eq 4 -and $mr.Addr -ceq '0x401000' -and $mr.Len -eq 256) ''
Check 'mem: CONTROL - the top of the cap and a full 8-digit address are accepted' `
  ($null -ne [ClarionDebugger.Terminal.MemRequest]::Parse('4|0xFFFFF000|4096')) ''
foreach ($bad in @('4|401000|256', '4|0x|16', '4|0x123456789|16', '4|0x40 1000|16', '4|0x40;1000|16', '4|0x401000|0',
                   '4|0x401000|4097', '4|0x401000', '-1|0x10|16', '4|0x10|16|x', 'x|0x10|16', '4|0x10|1e3')) {
  Check "mem: '$bad' is dropped" ($null -eq [ClarionDebugger.Terminal.MemRequest]::Parse($bad)) ''
}
# ONE cap on three sides of the bridge. A page that pages in bigger blocks than the host forwards would get
# every read dropped; a host looser than the engine would forward reads the engine refuses.
$engineCap = [regex]::Match($engineSrc, 'internal const int MemMaxLen = (\d+);')
$pageCap = [regex]::Match((Get-Content -Raw -LiteralPath $PagePath), 'const MEM_MAX=(\d+)')
Check 'mem: the host, the engine and the page share one cap' `
  ($engineCap.Success -and $pageCap.Success -and [int]$engineCap.Groups[1].Value -eq [ClarionDebugger.Terminal.MemRequest]::MaxLen `
   -and [int]$pageCap.Groups[1].Value -eq [ClarionDebugger.Terminal.MemRequest]::MaxLen) `
  "engine=$($engineCap.Groups[1].Value) host=$([ClarionDebugger.Terminal.MemRequest]::MaxLen) page=$($pageCap.Groups[1].Value)"

# RequestMem is the service-side gate, run for real over a recording SendCommand. It and MemRequest.Parse
# share WireRules (70860d6b D2); the regex RequestMem had before let "0x10<newline>" through, since .NET's
# $ matches before a trailing newline - a second command on the engine's stdin. That case is first below.
$memProbeSrc = @"
using System;
using System.Globalization;
using System.Text.RegularExpressions;
public class MemRequestProbe {
  public string Sent;
  private bool SendCommand(string c) { Sent = c; return true; }
  $(Get-Method 'public bool RequestMem(int reqId, string addrHex, int len)')
  $(Get-Method 'internal static class WireRules' $wireRulesText)
}
"@
Add-Type -TypeDefinition $memProbeSrc -Language CSharp | Out-Null
$mp = New-Object MemRequestProbe
Check 'RequestMem sends mem ADDR LEN reqId (the reqId TRAILS, where the engine reads it)' `
  ($mp.RequestMem(4, '0x401000', 256) -and $mp.Sent -ceq 'mem 0x401000 256 4') (ShowVal $mp.Sent)
foreach ($c in @(@(4, "0x10`n", 16), @(4, '0x40 1000', 16), @(4, '401000', 16), @(4, '0x1234567890', 16), @(4, '0x10', 0), @(4, '0x10', 4097), @(-1, '0x10', 16), @(4, $null, 16))) {
  # PowerShell stores $null into a C# string field as '', so "sent nothing" is IsNullOrEmpty, not -eq $null.
  $mp.Sent = $null
  Check "RequestMem refuses reqId=$($c[0]) addr=$((ShowVal $c[1]) -replace "`n", '
') len=$($c[2]) and sends nothing" `
    ((-not $mp.RequestMem($c[0], $c[1], $c[2])) -and [string]::IsNullOrEmpty($mp.Sent)) (ShowVal $mp.Sent)
}
Check 'RequestMem carries its security reasoning (read-only, capped, paused-only, validated)' `
  ($src -match 'SECURITY\. This is the one request' -and $src -match 'READ-ONLY' -and $src -match 'PAUSED-ONLY') ''

# The dispatch: paused-gated BEFORE the parse, exactly like framelocals, and a reply grants nothing.
$memCase = [regex]::Match($web, 'case "mem":[\s\S]*?break;')
$memCaseCode = Get-CSharpCodeOnly $memCase.Value
Check 'the bridge forwards mem only while Paused, through MemRequest.Parse and RequestMem' `
  ($memCase.Success -and $memCaseCode -match 'case "mem":\s*if \(_svc\.State == DebugSessionState\.Paused\)\s*\{\s*var mr = MemRequest\.Parse\(data\);\s*if \(mr != null\) _svc\.RequestMem\(mr\.ReqId, mr\.Addr, mr\.Len\);\s*\}\s*break;') `
  (ShowVal $memCase.Value)
$onSvcMem = [regex]::Match($web, 'private void OnSvcMem\([\s\S]*?(?=private void OnSvcRegs)')
Check 'the mem reply is posted and grants nothing (no _editGrants)' `
  ($onSvcMem.Success -and $onSvcMem.Value -match '\\"type\\":\\"mem\\"' -and $onSvcMem.Value -notmatch '_editGrants') ''
Check 'the bridge subscribes and unsubscribes the mem reply' `
  ($web -match '_svc\.MemReceived\s*\+=\s*OnSvcMem;' -and $web -match '_svc\.MemReceived\s*-=\s*OnSvcMem;') ''
Check 'the service raises MemReceived from a mem event' `
  ($src -match 'case "mem":\s*MemReceived\?\.Invoke\(GetStr\(json, "reqId"\)') ''

# A var row's read-only `addr` is NOT a grant. Only a ref:true row's addr is an EXPAND grant, and no addr is
# ever an EDIT grant: that is what keeps "View memory" on a group from minting pencils.
$ga = (New-Object ClarionDebugger.Terminal.SelectionSource).Grants
$ga.GrantRows('{"name":"G","type":"","value":"{}","children":[{"name":"F","addr":"0x400004"}],"addr":"0x400000"},{"name":"S","type":"LONG","addr":"0x400010"}', 5)
Check 'rows carrying only addr grant no edit and no expand' ($ga.Count -eq 0 -and $ga.ExpandableCount -eq 0) "$($ga.Count) edit, $($ga.ExpandableCount) expand"
$ga.GrantRows('{"name":"R","ref":true,"addr":"0x12345678","module":"m.clw","typeRef":7}', 5)
Check 'CONTROL: a ref:true row with addr is still an expand grant' ($ga.ExpandableCount -eq 1 -and $ga.Count -eq 0) "$($ga.ExpandableCount) expand"
$u = [uint32] 0
Check 'a thread id is a DWORD: a sign is not accepted' `
  (-not [ClarionDebugger.Terminal.PageNumbers]::TryUInt('-5', [ref] $u) -and [ClarionDebugger.Terminal.PageNumbers]::TryUInt('4294967295', [ref] $u)) ''
Check 'no envelope without an action' `
  (($null -eq [ClarionDebugger.Terminal.PageEnvelope]::Parse('{"data":"x"}')) -and ($null -eq [ClarionDebugger.Terminal.PageEnvelope]::Parse('not json'))) ''
# The switch itself: no case may go back to picking its own fields out of raw text.
$onMsg = Get-CSharpCodeOnly (Get-Method 'private void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)' $web)
Check 'OnWebMessage parses no payload inline - no Split, no bare TryParse' `
  (($onMsg -notmatch '\.Split\(') -and ($onMsg -notmatch '\b(u?int)\.TryParse\(')) ''

Write-Host ''
Write-Host 'a module path reaches the page as the path, not escaped twice (079ff431)'
# GetStr returned the raw text between the quotes, so a path read off the engine's module-loaded event kept
# its separators doubled, and OnModuleLoaded escaped it AGAIN on the way to the page: C:\\App\\... on screen.
# Every hop below is the shipped code: the engine's real writer, the host's real reader, the WebView's real
# writer. What the page is handed is decoded the way the page decodes it (JSON.parse <-> ConvertFrom-Json).
$modSrc = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
namespace ModPath {
$((Get-Method 'internal static class JsonMessageReader' $readerEarly) -replace 'internal static class', 'public static class')
// The engine's image, cut down to the fields its real ModuleLoaded writer reads. Pinned against
// LoadedModule.cs below.
public sealed class LoadedModule { public string Path; public string Name; public uint LoadBase; public uint Size; public bool HasDebug; }
public static class Json {
  $(Get-Method 'public static string Str(string s)' $engine)
  $(Get-Method 'public static string ModuleLoaded(LoadedModule m)' $engine)
}
$(Get-Method 'public sealed class DebugModule')
public static class Host {
  $((Get-Method 'private static string GetStr(string json, string key)') -replace 'private static', 'public static')
  $((Get-Method 'private static Dictionary<string, string> ParseRegs(string json)') -replace 'private static', 'public static')
}
public sealed class Pad {
  public List<string> Posts = new List<string>();
  private void Post(string json) { Posts.Add(json); }
  private void Console(string level, string text) { }
  $(Get-Method 'private static string Str(string s)' $web)
  $((Get-Method 'private void OnModuleLoaded(DebugModule m)' $web) -replace '^private void', 'public void')
}
}
"@
Add-Type -TypeDefinition $modSrc -Language CSharp | Out-Null
$lmSrc = Get-Content -Raw -LiteralPath $LoadedModulePath
Check 'the cut-down image stub matches the real LoadedModule field names' `
  (($lmSrc -cmatch 'public string Name;') -and ($lmSrc -cmatch 'public uint LoadBase;') -and ($lmSrc -cmatch 'public uint Size;') -and ($lmSrc -cmatch 'public bool HasDebug')) ''

$img = New-Object ModPath.LoadedModule
$img.Path = 'C:\App\Dll1\dll1.dll'; $img.Name = 'dll1.dll'; $img.LoadBase = 0x10000000; $img.Size = 0x1000; $img.HasDebug = $true
$evt = [ModPath.Json]::ModuleLoaded($img)
Check 'CONTROL: the engine escapes the path once, as JSON requires' ($evt.Contains('"path":"C:\\App\\Dll1\\dll1.dll"')) $evt
# The host's module-loaded arm, which sits in a switch too long to brace-match out: it is mirrored here with
# the same reader, and pinned to the shipped arm just below.
$dm = New-Object ModPath.DebugModule
$dm.Name = [ModPath.Host]::GetStr($evt, 'name'); $dm.Path = [ModPath.Host]::GetStr($evt, 'path')
$dm.Base = [ModPath.Host]::GetStr($evt, 'base'); $dm.HasDebug = $true
Check 'the module-loaded arm reads the path through GetStr' ($src -cmatch 'Path = GetStr\(json, "path"\)') ''
Check 'the host reads back the real path, unescaped' ($dm.Path -ceq $img.Path) (ShowVal $dm.Path)
$mp = New-Object ModPath.Pad
$mp.OnModuleLoaded($dm)
$pageSees = if ($mp.Posts.Count -ge 1) { ($mp.Posts[0] | ConvertFrom-Json).path } else { $null }
Check 'and the page receives C:\App\..., not C:\\App\\...' ($pageSees -ceq $img.Path) (ShowVal $pageSees)

# The reader swap fixed the regex's other two faults as well, and changed where it looks. Each is pinned.
Check 'a value holding an escaped quote is read whole, not cut at the quote' `
  ([ModPath.Host]::GetStr('{"message":"say \"hi\" now"}', 'message') -ceq 'say "hi" now') ([ModPath.Host]::GetStr('{"message":"say \"hi\" now"}', 'message'))
Check 'a number is still not a string, as the regex never matched one' ($null -eq [ModPath.Host]::GetStr('{"line":42}', 'line')) ''
Check 'a member inside a nested object is not the event''s own' `
  ($null -eq [ModPath.Host]::GetStr('{"event":"x","inner":{"module":"a.clw"}}', 'module')) ''
# ...which is why ParseRegs, the one caller that read NESTED members, now hands over the register block.
$regs = [ModPath.Host]::ParseRegs('{"event":"paused","module":"m.clw","regs":{"eax":"0x1","eip":"0x4754EB"},"tid":7}')
Check 'the registers inside "regs":{...} still read' (($null -ne $regs) -and ($regs['eip'] -ceq '0x4754EB') -and ($regs['eax'] -ceq '0x1')) ''
Check 'CONTROL: an event with no register block still has none' ($null -eq [ModPath.Host]::ParseRegs('{"event":"paused","regs":null}')) ''

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
# bp-list carries its owners INSIDE the bps array, so it is read per row through ParseBpList - the way the
# host reads it. GetStr reads only the object it is handed (079ff431), and the event itself has no owner.
$listOwner = @([BpHost]::ParseBpList($listD1)) | ForEach-Object { $_.OwnerPath } | Select-Object -First 1
$carrying = @(@([BpHost]::GetStr($setD1, 'ownerPath'), [BpHost]::GetStr($delD1, 'ownerPath'), $listOwner) | Where-Object { $_ }).Count
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

# What the owner IS: the IMAGE path, an identity token compared only with another owner read the same way.
# Until 079ff431 it read back in the wire's ESCAPED form (GetStr did not unescape); it now reads back as the
# real path. Both sides of every comparison moved together, which is what the two-DLL checks above prove.
Check 'the owner reads back unescaped, as the image''s real path' `
  ($dllRows.Count -ge 1 -and $dllRows[0].OwnerPath -ceq 'C:\App\Dll1\dll1.dll') (OwnerOf $dllRows)

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
  (($pendingSet -cmatch '"ownerPath":null') -and ($null -eq [BpHost]::GetStr($pendingSet, 'ownerPath'))) $pendingSet

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
  ([PadJsonProbe]::TidMember('stopped', 116932) -ceq ',"stopped":116932') ([PadJsonProbe]::TidMember('stopped', 116932))
Check 'and TidJson is that same writer, not a second copy of the rule' `
  ((Get-Method 'private static string TidJson(uint? tid)' $web) -match 'TidMember\(TidMemberTid, tid\)') ''
# ALL THREE, counted rather than asserted as "every": a fourth member added without the writer is what the
# count catches. The per-row tid is written inline in OnThreads and is the third.
$onThreads = Get-Method 'private void OnThreads(DebugThreadList list)' $web
# THREE since c299aced: the per-row tid used to be typed inline and now goes through the writer as well.
Check 'all three thread-id members in OnThreads go through it (stopped, selected, and each row''s tid)' `
  ((([regex]::Matches($onThreads, 'TidMember\(')).Count) -eq 3) `
  ((([regex]::Matches($onThreads, 'TidMember\(')).Count).ToString() + ' of 3')
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
  ([PadJsonProbe]::TidJson(4294967295) -ceq ',"tid":4294967295') `
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
$wireRules
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
$epochGates = [regex]::Matches($onDisasm, '!_seat\.IsCurrent\(epoch\)')
Check 'OnDisasm gates on the epoch on BOTH sides of the UI marshal' ($epochGates.Count -eq 2) "$($epochGates.Count) epoch gate(s)"
# ...and the marshal-side gates really are inside the lambda, not stacked ahead of it.
$marshalBody = if ($onDisasm -match '(?s)UI\(\(\)\s*=>\s*\{(.*)') { $Matches[1] } else { '' }
Check 'the second epoch gate is INSIDE the marshal, where the race is' `
  ($marshalBody -match '!_seat\.IsCurrent\(epoch\)') ''
Check 'and the tid gate is inside it too, on the same side of the race' `
  ($marshalBody -match 'TidMatchesView\(tid\)') ''
# The pending flags are cleared by NewEpoch, not by the replies: the dropped ones never arrive to clear
# them, and a stuck _pendFwd would freeze forward extension for the rest of the session.
# NewEpoch moved into SeatState.cs with the rest of the seat lifecycle (8f352618); same body, same rule.
$seatStateSrc = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Disassembly\SeatState.cs')
Check 'NewEpoch clears the in-flight flags as well as retiring the replies' `
  ((Get-Method 'private void NewEpoch()' $seatStateSrc) -match '_pendFwd\s*=\s*_pendBwd\s*=\s*false') ''

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
# The view's selected thread is SelTid since 49538b78 8b (the service's snapshot, read through TidOf); the idiom is
# banned under either name.
$seatIdiomRx = '\?\?\s*(_selTid|SelTid)\b'
$seatIdiom = [regex]::Matches($disasmCode, $seatIdiomRx)
Check 'no tid is unwrapped with `?? SelTid` (or the old `?? _selTid`), the idiom the seat and the gate disagreed on' `
  ($seatIdiom.Count -eq 0) "$($seatIdiom.Count) site(s) in code"
# CONTROL: the scan can see that idiom at all - otherwise the zero above is a zero nobody looked for.
Check 'CONTROL: the idiom scan matches it in code, under both names' `
  (([regex]::Matches((Get-CSharpCodeOnly 'uint x = tid ?? _selTid;'), $seatIdiomRx).Count -eq 1) -and `
   ([regex]::Matches((Get-CSharpCodeOnly 'uint x = tid ?? SelTid;'), $seatIdiomRx).Count -eq 1)) ''
# ...and the stripper is what makes the zero mean something: the same idiom in a COMMENT must not count,
# which is precisely the two hits the raw scan produced.
Check 'CONTROL: ...and does NOT match it in a comment' `
  ([regex]::Matches((Get-CSharpCodeOnly '// not `tid ?? _selTid` here'), $seatIdiomRx).Count -eq 0) ''

# ---- the SEAT lifecycle: moved to tools\test-disasm-seat.ps1 by 8f352618 --------------------------------
#
# Six POSITION checks used to live here, pinning the order of eight statements in OnDisasm's WinTag branch
# (the painted flag released before the listing is erased, wasSeat captured before the in-flight release,
# the decode claim gated on wasSeat, the banner re-derived after the cache replacement). They were a stopgap
# that said so - "a constant-true wasSeat passes all six" - and asked to be REPLACED, not kept alongside,
# when 8f352618 landed. It has: those statements are SeatState.WindowLanded now, and
# tools\test-disasm-seat.ps1 compiles SeatState.cs as it ships and drives each transition, so a WRONG VALUE
# goes red there as well as a wrong place. The one ordering that is still the view's own (WindowLanded
# before the cache replacement before the banner) is pinned by position in that suite too.
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

# SHAPE, NOT TEXT (49538b78 item 8c). This used to be `$onDisasm -match 'TidMatchesView\(tid\)'`, which
# passes against `if (false && !TidMatchesView(tid)) return;` - a gate still present and never applied - and
# against a comment that quotes it. So the comments are stripped, and the gate must be the marshal's SECOND
# statement, in exactly this form, straight after the inner epoch check: nothing between them, nothing
# ahead of them, no extra condition. Measured 2026-09-24: deleting the gate, `if (false && ...)`, a
# non-constant-false `&&`, an `||` in its condition, the gate commented out and the gate moved below the
# next statement each turn this red; the shipped source passes.
$tidGateShape = '(?s)UI\(\(\)\s*=>\s*\{\s*if\s*\(\s*!_seat\.IsCurrent\(epoch\)\s*\)\s*return\s*;' +
                '\s*if\s*\(\s*!TidMatchesView\(tid\)\s*\)\s*return\s*;'
Check 'OnDisasm applies the tid gate as well as the epoch, as the marshal''s second statement, unconditionally' `
  ((Get-CSharpCodeOnly $onDisasm) -match $tidGateShape) ''
# NEITHER GATE MAY REPLACE THE OTHER. A tid check written in place of the marshal-side epoch check reads
# like a strengthening and is a silent regression: it restores the exact race the second epoch check
# exists to close, and the tid cannot see it (a switch away and back leaves the tid agreeing again).
Check 'the tid gate was ADDED to the marshal, not substituted for the epoch check there' `
  (($marshalBody -match '!_seat\.IsCurrent\(epoch\)') -and ($marshalBody -match 'TidMatchesView\(tid\)')) ''
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

Write-Host ''
Write-Host 'the hover event, engine writer to page, with none as an ABSENT tid (f6e547ce)'
# EVERY HOP REAL but one. The engine's HoverJson and its tid writer, the service's readers, and the WebView's
# OnSvcHover are compiled out of the shipped source and RUN. The one hand-written hop is the service's
# `case "hover"` line, which sits in the middle of OnLine; its exact reader calls are pinned by text below,
# and the probe makes those same three calls.
$hoverEngineSrc = Get-Content -Raw -LiteralPath $EngineHoverPath
$engineTidDecls = @('private const string TidMemberTid', 'private const string TidMemberStopped',
  'private const string TidMemberSelected', 'private static readonly string[] TidValuedMemberNames') |
  ForEach-Object { Get-Statement $_ $engineSrc }
$engineTidDeclsText = $engineTidDecls -join "`n"
# Hoisted out of the here-string: its $() scanner counts the '(' inside the quoted signature and never
# finds the close.
$onSvcHoverSrc = (Get-ArrowHandler 'private void OnSvcHover(') -replace '^private void', 'public void'
$hoverProbeSrc = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
public static class HoverEngineSide {
$engineTidDeclsText
$((Get-Method 'private static bool TidIsKnown(uint tid)' $engineSrc) -replace 'private static', 'public static')
$((Get-Method 'private static void AppendTidValuedMember(StringBuilder sb, string name, uint tid)' $engineSrc) -replace 'private static', 'public static')
$((Get-Method 'private static void AppendTidMember(StringBuilder sb, uint tid)' $engineSrc) -replace 'private static', 'public static')
$((Get-Method 'private static string HoverJson(bool on, bool paused, uint tid)' $hoverEngineSrc) -replace 'private static', 'public static')
}
public static class HoverServiceSide {
$((Get-Method 'private static string ScanNumberToken(string json, string key)') -replace 'private static', 'public static')
$((Get-Method 'private static uint? GetUIntOrNull(string json, string key)') -replace 'private static', 'public static')
$((Get-Method 'private static bool GetBool(string json, string key)') -replace 'private static', 'public static')
}
public sealed class HoverWebSide {
$($tidNameDecls)
  public List<string> Posts = new List<string>();
  private void Post(string json) { Posts.Add(json); }
  private void UI(Action a) { a(); }
$(Get-Method 'private static string TidJson(uint? tid)' $web)
$(Get-Method 'private static string TidMember(string name, uint? tid)' $web)
$wireRules
$onSvcHoverSrc
  // the service's `case "hover"` hop, making the calls pinned below
  public void Deliver(string engineJson) {
    OnSvcHover(HoverServiceSide.GetUIntOrNull(engineJson, "tid"), HoverServiceSide.GetBool(engineJson, "on"),
               HoverServiceSide.GetBool(engineJson, "paused"));
  }
}
"@
Add-Type -TypeDefinition $hoverProbeSrc -Language CSharp | Out-Null

Check 'the service reads the hover event with exactly the calls this probe makes (tid stays nullable)' `
  ($src -match 'case "hover":\s*(//[^\n]*\n\s*)*HoverChanged\?\.Invoke\(GetUIntOrNull\(json, "tid"\), GetBool\(json, "on"\), GetBool\(json, "paused"\)\);') ''
$hw = New-Object HoverWebSide
$hw.Deliver([HoverEngineSide]::HoverJson($true, $true, [uint32] 5140))
$pg = $hw.Posts[0] | ConvertFrom-Json
Check 'a known thread reaches the page as the hover type, with its tid and state' `
  (($pg.type -ceq 'hover') -and ($pg.tid -eq 5140) -and ($pg.on -eq $true) -and ($pg.paused -eq $true)) $hw.Posts[0]
foreach ($none in @([uint32] 0, [uint32]::MaxValue)) {
  $hw.Posts.Clear()
  $hw.Deliver([HoverEngineSide]::HoverJson($true, $false, $none))
  $pg = $hw.Posts[0] | ConvertFrom-Json
  Check "none ($none) arrives with NO tid member, not a 0 the page would read as a thread" `
    (($pg.type -ceq 'hover') -and (-not ($pg.PSObject.Properties.Name -contains 'tid')) -and ($pg.paused -eq $false)) $hw.Posts[0]
}
$hw.Posts.Clear()
$hw.Deliver([HoverEngineSide]::HoverJson($false, $true, [uint32] 0))
$pg = $hw.Posts[0] | ConvertFrom-Json
Check '`hover off` arrives as on:false' (($pg.on -eq $false) -and ($pg.paused -eq $true)) $hw.Posts[0]

# The page->host half. NOT paused-gated, unlike selectthread beside it: the engine answers while running too.
$onMsgHover = Get-CSharpCodeOnly (Get-Method 'private void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)' $web)
$hoverCase = [regex]::Match($onMsgHover, 'case "hover":[^\n]*')
Check 'the page''s hover action reaches SetHover, and only for on/off' `
  ($hoverCase.Success -and ($hoverCase.Value -match 'data == "on" \|\| data == "off"') -and ($hoverCase.Value -match '_svc\.SetHover\(data == "on"\)')) $hoverCase.Value
Check 'and it is NOT gated on Paused (the engine polls while running too)' `
  ($hoverCase.Success -and ($hoverCase.Value -notmatch 'DebugSessionState')) $hoverCase.Value
Check 'OnSvcHover is subscribed and unsubscribed, once each' `
  ((([regex]::Matches($web, '_svc\.HoverChanged\s*\+=\s*OnSvcHover;')).Count -eq 1) -and `
   (([regex]::Matches($web, '_svc\.HoverChanged\s*-=\s*OnSvcHover;')).Count -eq 1)) ''
Check 'SetHover sends the engine''s verb' `
  ((Get-Method 'public bool SetHover(bool on)') -match 'SendCommand\(on \? "hover on" : "hover off"\)') ''

Write-Host ''
Write-Host 'a qualified watch name, [image!][module!]name, reaches the engine whole (04d7b4c8)'
# '!' starts a comment in Clarion, so it is in no label, and the engine now reads it as the qualifier separator.
# RUN: the real IsValidWatchName and Watch over a recording SendCommand. The command is one line split on
# spaces, so what the name must still never carry is a space, a quote, a ';' or a line break.
$watchProbeSrc = @"
using System;
using System.Text.RegularExpressions;
public class WatchNameProbe {
  public string Sent;
  private bool SendCommand(string c) { Sent = c; return true; }
  $(Get-Method 'public static bool IsValidWatchName(string name)')
  $(Get-Method 'public bool Watch(string name)')
}
"@
Add-Type -TypeDefinition $watchProbeSrc -Language CSharp | Out-Null
$wn = New-Object WatchNameProbe
$qualified = @('CLBRWS.EXE!CUS:RECORD', 'clbrws011.clw!LOC:Count', 'CLBRWS.EXE!clbrws011.clw!Glo:Name', 'GLO:X')
$wnBad = @($qualified | Where-Object { $wn.Sent = $null; -not ($wn.Watch($_) -and $wn.Sent -ceq ('watch ' + $_)) })
Check 'a qualified name is accepted and sent whole: `watch CLBRWS.EXE!CUS:RECORD`' ($wnBad.Count -eq 0) ($wnBad -join ', ')
$refused = @('A B', "A`n", "A!`n", "A`r", "A!`r`nquit", 'A;B', 'A"B', "A'B", 'A!B C', '', ('A' * 129), 'A..B')
$wnLet = @($refused | Where-Object { $wn.Sent = $null; $wn.Watch($_) -or -not [string]::IsNullOrEmpty($wn.Sent) } | ForEach-Object { ShowVal ($_ -replace "`r", '\r' -replace "`n", '\n') })
Check 'a space, a line break (a trailing one included), a quote or a ; is still refused, and nothing is sent' ($wnLet.Count -eq 0) ($wnLet -join ', ')

Write-Host ''
Write-Host 'the service needs nothing from Terminal (40a252d0)'
# AttachableProcess was the one Terminal type the Services layer imported, and the using it kept also carried
# PageNumbers into the process-listing parse unseen. Both now live in Wire (AttachableProcess, WireRules.TryUInt).
$terminalRef = '\bClarionDebugger\.Terminal\b'
Check 'the service names no ClarionDebugger.Terminal, as a using or a qualified name' `
  ([regex]::Matches($svcCode, $terminalRef).Count -eq 0) "$([regex]::Matches($svcCode, $terminalRef).Count) reference(s)"
Check 'CONTROL: that scan finds the using this ticket removed' `
  ([regex]::Matches((Get-CSharpCodeOnly "using ClarionDebugger.Terminal;`nnamespace X {}"), $terminalRef).Count -eq 1) ''
# The one uint rule, run: digits only, invariant, no sign or padding, null is not a number.
$tryU = @(@('4812', $true, 4812), @('4294967295', $true, 4294967295), @('0', $true, 0), @('4294967296', $false, 0),
  @('-1', $false, 0), @('+1', $false, 0), @(' 1', $false, 0), @('0x10', $false, 0), @('', $false, 0), @($null, $false, 0))
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Globalization;
public static class TryUIntProbe {
$wireRules
  public static bool Run(string s, out uint v) { return WireRules.TryUInt(s, out v); }
}
"@ | Out-Null
$tryUBad = @($tryU | Where-Object { $v = [uint32]0; $ok = [TryUIntProbe]::Run($_[0], [ref] $v); ($ok -ne $_[1]) -or ($ok -and $v -ne $_[2]) } |
  ForEach-Object { ShowVal $_[0] })
Check 'WireRules.TryUInt takes plain decimal digits in the DWORD range and nothing else' ($tryUBad.Count -eq 0) ($tryUBad -join ', ')

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
$EXPECTED_CHECKS = 459
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
