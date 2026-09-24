# The watch reply's addr / frameIdx / frameProc members, engine writer to page (04b9679e).
#
# The add-in does not forward a watch reply: ParseWatch reads it into a DebugWatch and OnWatch writes a NEW
# message for the page field by field, and the page's `case 'watch'` builds applyValue's meta by listing
# fields again. A member missing from any one of those four layers disappears without an error anywhere,
# which is why this runs every hop for real:
#
#   engine Json.Watch (+ DebugEngine.OwnStorageAddr)  ->  service ParseWatch  ->  WebView OnWatch
#     ->  the page's own `case 'watch'` line, under node, with applyValue replaced by a recorder
#
# THE ONE HAND-WRITTEN HOP: frameIdx/frameProc are spliced into the engine line, because their writer is
# helper F's (the frame-walk resolution, wave 5) and is not on this branch. The splice uses the frozen wire
# shape `"frameIdx":<int>,"frameProc":"<NAME>"`. Once both branches are merged, this splice is the line
# to replace with the real writer's parameters.
#
#   pwsh tools/test-addin-watch-fields.ps1
# Exit code 0 = all checks passed.

param(
  [string] $ServicePath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs'),
  [string] $WebViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs'),
  [string] $ReaderPath  = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\JsonMessageReader.cs'),
  [string] $EngineJsonPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\Json.cs'),
  [string] $EngineWatchPath = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\DebugEngine.Watch.cs'),
  [string] $PagePath    = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\debugger.html')
)

. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$ErrorActionPreference = 'Stop'
$svc    = Get-Content -Raw -LiteralPath $ServicePath
$web    = Get-Content -Raw -LiteralPath $WebViewPath
$reader = Get-Content -Raw -LiteralPath $ReaderPath
$ejson  = Get-Content -Raw -LiteralPath $EngineJsonPath
$ewatch = Get-Content -Raw -LiteralPath $EngineWatchPath
Set-ExtractSource $svc

$tidNameDecls = (@('private const string TidMemberTid', 'private const string TidMemberStopped', 'private const string TidMemberSelected',
  'private static readonly string[] TidValuedMemberNames') | ForEach-Object { Get-Statement $_ $web }) -join "`n"

# Signatures with an unbalanced '(' are hoisted: inside $() in a here-string they end the subexpression.
$sigWatch = Get-Method 'public static string Watch(string name, bool found' $ejson
$probeSrc = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
namespace WatchFieldsProbe {
$((Get-Method 'internal static class JsonMessageReader' $reader) -replace 'internal static class', 'public static class')
public static class EngineJson {
  $(Get-Method 'public static string Str(string s)' $ejson)
  $sigWatch
}
public static class EngineWatch {
  $((Get-Method 'internal static string OwnStorageAddr(bool threaded, uint templateVa, uint instanceVa)' $ewatch) -replace '^internal static', 'public static')
  // EmitWatchValue's call, in C#: PowerShell hands a C# string parameter "" for `$null, which would put
  // "note":"" and "addr":"" on the wire where the engine writes no member at all.
  public static string Line(string name, bool threaded, uint t, uint i, bool editable, string note) {
    return EngineJson.Watch(name, true, t, i, threaded, 3, "LONG", 4, 0, "7", new byte[] { 7, 0, 0, 0 }, 4, editable,
                            string.IsNullOrEmpty(note) ? null : note, addr: OwnStorageAddr(threaded, t, i));
  }
}
$(Get-Method 'public sealed class DebugWatch')
public static class Service {
  $((Get-Method 'private static DebugWatch ParseWatch(string json)') -replace '^private static', 'public static')
  $(Get-Method 'private static string GetStr(string json, string key)')
  $(Get-Method 'private static int GetInt(string json, string key)')
  $(Get-Method 'private static int? GetIntOrNull(string json, string key)')
  $(Get-Method 'private static uint? GetUIntOrNull(string json, string key)')
  $(Get-Method 'private static string ScanNumberToken(string json, string key)')
  $(Get-Method 'private static bool GetBool(string json, string key)')
}
// Not under test: OnWatch grants the edit tuple, which tools/test-addin-json.ps1 covers.
public sealed class FakeGrants { public void Grant(string va, string typeCode, int size, int places, uint? tid) { } }
public sealed class Pad {
  public FakeGrants _editGrants = new FakeGrants();
  public List<string> Posts = new List<string>();
  private void Post(string json) { Posts.Add(json); }
  $(Get-Method 'private static string Str(string s)' $web)
  $(Get-Method 'private static string TidJson(uint? tid)' $web)
  $(Get-Method 'private static string TidMember(string name, uint? tid)' $web)
  $tidNameDecls
  $((Get-Method 'private void OnWatch(DebugWatch w)' $web) -replace '^private void', 'public void')
}
}
"@
Add-Type -TypeDefinition $probeSrc -Language CSharp | Out-Null

$tmpl = [uint32]0x4C8010; $inst = [uint32]0x02A31010; $slot = [uint32]0x0019FE40
function EngineLine { param([string] $Name, [bool] $Threaded, [uint32] $T, [uint32] $I, [bool] $Editable, [string] $Note)
  [WatchFieldsProbe.EngineWatch]::Line($Name, $Threaded, $T, $I, $Editable, $Note)
}
function HostPost { param([string] $Line)
  $w = [WatchFieldsProbe.Service]::ParseWatch($Line)
  $pad = New-Object WatchFieldsProbe.Pad
  $pad.OnWatch($w)
  [pscustomobject]@{ W = $w; Post = $pad.Posts[$pad.Posts.Count - 1] }
}

$own   = EngineLine 'GLO:Rec' $true $tmpl $inst $true $null            # ThreadedResolve.Ok
$templ = EngineLine 'GLO:Rec' $true $tmpl $tmpl $false 'not yet used on this thread'   # Unallocated
# A local resolved in frame 2: its own stack slot, plus the frame members helper F's writer adds (spliced).
$local = (EngineLine 'LOC:N' $false $slot $slot $true $null) -replace ',"bytes":', ',"frameIdx":2,"frameProc":"BROWSE","bytes":'

Write-Host 'engine writer'
Check 'an own-instance reply carries addr' ($own -match ('"addr":"0x' + $inst.ToString('X') + '"')) $own
Check 'a template reply carries none' ($templ -notmatch '"addr"') $templ
Check 'CONTROL: the frame splice landed' ($local -match '"frameIdx":2,"frameProc":"BROWSE"') $local

Write-Host 'service ParseWatch'
$h1 = HostPost $own; $h2 = HostPost $templ; $h3 = HostPost $local
Check 'Addr is read' ($h1.W.Addr -eq ('0x' + $inst.ToString('X'))) (ShowVal $h1.W.Addr)
Check 'an absent addr is null, not empty' ($null -eq $h2.W.Addr) (ShowVal $h2.W.Addr)
Check 'FrameIdx and FrameProc are read' (($h3.W.FrameIdx -eq 2) -and ($h3.W.FrameProc -ceq 'BROWSE')) "$(ShowVal $h3.W.FrameIdx) $(ShowVal $h3.W.FrameProc)"
Check 'absent frame members are null' (($null -eq $h1.W.FrameIdx) -and ($null -eq $h1.W.FrameProc)) "$(ShowVal $h1.W.FrameIdx) $(ShowVal $h1.W.FrameProc)"

Write-Host 'WebView OnWatch'
Check 'the page message carries addr' ($h1.Post -match ('"addr":"0x' + $inst.ToString('X') + '"')) $h1.Post
Check 'and frameIdx as a NUMBER, with frameProc' ($h3.Post -match '"frameIdx":2,"frameProc":"BROWSE"') $h3.Post
Check 'absent members go out as null' ($h2.Post -match '"addr":null' -and $h2.Post -match '"frameIdx":null,"frameProc":null') $h2.Post

# ---- the page's own `case 'watch'` line, run ----------------------------------------------------------
$inputFile = Join-Path ([IO.Path]::GetTempPath()) ('cawatchf-in-' + [Guid]::NewGuid().ToString('N') + '.json')
$jsFile = Join-Path ([IO.Path]::GetTempPath()) ('cawatchf-' + [Guid]::NewGuid().ToString('N') + '.js')
@($h1.Post, $h2.Post, $h3.Post) | ConvertTo-Json -Compress | Set-Content -LiteralPath $inputFile -Encoding UTF8
$padDom = (Join-Path $PSScriptRoot 'pad-dom.js') -replace '\\', '\\'
$pageJs = $PagePath -replace '\\', '\\'
@"
const pad = require('$padDom');
const fs = require('fs');
const html = pad.readPage('$pageJs');
const onMsg = pad.extract(html, 'onMessage');
const m = /case 'watch':[^\n]*/.exec(onMsg);
if (!m) { console.log(JSON.stringify({ error: "no case 'watch' line in onMessage" })); process.exit(0); }
const META = [];
function tidAccepted() { return true; }
function applyValue(name, found, value, typeName, threaded, meta) { META.push(meta); }
const run = new Function('m', 'tidAccepted', 'applyValue', 'switch(m.type){ ' + m[0] + ' }');
const posts = JSON.parse(fs.readFileSync(process.argv[2], 'utf8').replace(/^\uFEFF/, ''));
posts.forEach(p => run(JSON.parse(p), tidAccepted, applyValue));
console.log(JSON.stringify({ meta: META }));
"@ | Set-Content -LiteralPath $jsFile -Encoding UTF8
try { $raw = & node $jsFile $inputFile 2>&1 } finally { Remove-Item -LiteralPath $jsFile, $inputFile -ErrorAction SilentlyContinue }
$out = $null; try { $out = ($raw | Select-Object -Last 1) | ConvertFrom-Json } catch { }
$outErr = if ($null -ne $out -and $out.PSObject.Properties['error']) { $out.error } else { $null }
$outMeta = if ($null -ne $out -and $out.PSObject.Properties['meta']) { @($out.meta) } else { $null }

Write-Host "the page's case 'watch'"
if ($null -eq $outMeta -or $outErr -or $outMeta.Count -ne 3) {
  Check 'could run the page line under node' $false ((@($raw) -join ' ') + ' ' + (ShowVal $outErr))
} else {
  $m1, $m2, $m3 = $outMeta
  # JSON.stringify drops an undefined member, and StrictMode throws on reading a missing one: absent is $null.
  function Get-MetaVal { param($o, [string] $k) if ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
  Check 'meta.addr is the engine address' ((Get-MetaVal $m1 'addr') -eq ('0x' + $inst.ToString('X'))) (ShowVal (Get-MetaVal $m1 'addr'))
  Check 'meta.frameIdx is the number 2 and meta.frameProc the name' (((Get-MetaVal $m3 'frameIdx') -is [long] -or (Get-MetaVal $m3 'frameIdx') -is [int]) -and (Get-MetaVal $m3 'frameIdx') -eq 2 -and (Get-MetaVal $m3 'frameProc') -ceq 'BROWSE') "$(ShowVal (Get-MetaVal $m3 'frameIdx')) $(ShowVal (Get-MetaVal $m3 'frameProc'))"
  Check 'a template reply reaches the page with no addr' ($null -eq (Get-MetaVal $m2 'addr')) (ShowVal (Get-MetaVal $m2 'addr'))
  Check 'CONTROL: the existing members still arrive (va)' ($null -ne (Get-MetaVal $m1 'va')) (ShowVal (Get-MetaVal $m1 'va'))
}

# 3 engine + 4 service + 3 WebView + 4 page. A section that stops early (node not run) fails here too.
Assert-CheckTotal 14
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
