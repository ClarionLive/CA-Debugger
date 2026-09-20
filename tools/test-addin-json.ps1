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
  [string] $ControllerPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\DebugSessionController.cs'),
  # the inbound reader and the page that builds the payloads it parses
  [string] $ReaderPath  = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\JsonMessageReader.cs'),
  [string] $PagePath    = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\debugger.html'),
  # the disassembly view: its request tags carry the epoch that decides whether a reply is still wanted
  [string] $DisasmViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Disassembly\DisassemblyView.cs'),
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
$ctl = Get-Content -Raw -LiteralPath $ControllerPath
$disasmView = Get-Content -Raw -LiteralPath $DisasmViewPath

function Get-Method {
  param([string] $Signature, [string] $From)
  if (-not $From) { $From = $src }
  $block = Get-CSharpBlock $Signature $From
  if ($null -eq $block) {
    # Pointed at a version that predates the method under test: say so plainly instead of throwing
    # halfway through, which reads like a broken test rather than the before/after proof it is.
    Write-Host "  FAIL  absent from this version of the add-in: $Signature"
    Write-Host ''
    Write-Host 'This add-in predates the code these checks cover. 1 FAILURE(S)'
    exit 1
  }
  return $block
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
  (Get-Method 'public static string BpList(List<UserBreakpoint> bps)' $engine),
  (Get-Method 'private static void AppendBpProps(StringBuilder sb, UserBreakpoint bp)' $engine)
) -join "`n"
$hostMethods = @(
  (Get-Method 'private static DebugBreakpoint ParseBpFields(string json, string module)'),
  (Get-Method 'private static List<DebugBreakpoint> ParseBpList(string json)'),
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
$identBody = Get-Method 'internal static bool SameBpIdentity(DebugBreakpoint a, DebugBreakpoint b)'
Check 'SameBpIdentity falls back to the planted line when a requested line is absent' ($identBody -match 'a\.Line == b\.Line') ''
Check 'and it compares requested lines through the nullable carrier, not the 0-defaulting accessor' `
  ($identBody -match 'RequestedLineOrNull') ''
# The predicate SameBpIdentity mirrors has to read the carrier for the same reason: b.RequestedLine answers
# the PLANTED line when the requested one is absent, so reading it compares one kind of line against another.
$delBody = Get-Method 'internal static bool BpDelMatches(DebugBreakpoint b, string module, int? requestedLine, int plantedLine)'
Check 'BpDelMatches reads the nullable carrier too, not the substituting getter' `
  (($delBody -match 'RequestedLineOrNull') -and ($delBody -notmatch 'b\.RequestedLine ==')) ''
Check 'and it requires a requested line on BOTH sides before comparing them' `
  ($delBody -match 'requestedLine\.HasValue && rb\.HasValue') ''

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
# old JsonVal returned 'au0042c' - it appended the escape letter and then the digits verbatim
Check 'a \u escape is decoded' ((Read1 '{"name":"aBc"}' 'name') -eq 'aBc') (Read1 '{"name":"aBc"}' 'name')

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
$tagShim = @"
using System;
using System.Globalization;
public static class DisasmTagProbe {
  public const string WinTag = "win";
  public const string FwdTag = "winf";
  public const string BwdTag = "winb";
$(($fmtTag, $parseTag -join "`n") -replace 'private static', 'public static')
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
Check 'the view has the request sites this check expects' ($callLines.Count -eq 7) "$($callLines.Count) call site(s)"
Check 'no RequestDisasmAt still passes a bare tag constant' ($bareTag.Count -eq 0) "$($bareTag.Count) bare call(s)"
Check 'every disasm request goes out through MakeTag' ($viaMakeTag.Count -eq $callLines.Count) "$($viaMakeTag.Count) of $($callLines.Count)"
Check 'OnDisasm gates on the epoch before touching the cache' `
  ((Get-Method 'private void OnDisasm(string tag, List<DebugDisasmInstr> instrs)' $disasmView) -match 'epoch\s*!=\s*_epoch') ''
# The pending flags are cleared by NewEpoch, not by the replies: the dropped ones never arrive to clear
# them, and a stuck _pendFwd would freeze forward extension for the rest of the session.
Check 'NewEpoch clears the in-flight flags as well as retiring the replies' `
  ((Get-Method 'private void NewEpoch()' $disasmView) -match '_pendFwd\s*=\s*_pendBwd\s*=\s*false') ''

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host 'ALL CHECKS PASSED'
exit 0
