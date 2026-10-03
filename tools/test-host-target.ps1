# suite: live=no
# suite: live=no; args=-SelfTest
# The Target EXE, v2 (0214f33a, contract C4): what the pad resolves, and what its target bar is allowed to claim.
#
#   pwsh -NoProfile -File tools\test-host-target.ps1 [-TargetServicePath <ProjectTargetService.cs>] [-CwprojReaderPath <CwprojReader.cs>] [-WebViewPath <ClarionDebuggerWebView.cs>]
#   pwsh -NoProfile -File tools\test-host-target.ps1 -SelfTest
# Exit code 0 = all checks passed.
#
# Three defects, one ticket. The resolver gave up silently when the active project was a DLL and the solution had
# several EXEs (the IDE's STARTUP project names the one to run); it read OutputType/OutputName with no regard for a
# PropertyGroup's Condition (a Release-only OutputName was read for Debug too); and the pad kept an old solution's
# auto path on the target bar with nothing saying it was no longer confirmed.
#
# fb5766d1 (wave 8) reshaped the code under test, not what it does: the .cwproj reader moved out of
# ProjectTargetService into CwprojReader.cs; every write of the target's state goes through SetTargetState, which
# pushes it; and a Start that switches the target lists its procedures ONCE (it listed them twice, the second parse
# only to be discarded by _procGen - debugger report de31a61b, X2).
#
# RUN, NOT READ. ProjectTargetService.cs and CwprojReader.cs are compiled whole and their pure deciders
# (TryEvaluateCondition, ReadOutput, Choose) are driven with literal .cwproj text. The pad's target writers - the
# Start's resolve, Browse, the auto-resolve, ApplyNoTarget, SetTargetState and the procedure-list bookkeeping - are
# lifted out of ClarionDebuggerWebView.cs and run over stubs of what they call; the Start and the attach are the
# REAL statements lifted from StartSession and AttachSession. The stubs, stated: ProjectTargetService.ResolveTarget
# and GetActiveContextKey answer what a scenario sets; OpenFileDialog answers a scenario's pick; PushTarget counts;
# PushProcedures records the EXE and bumps _procGen as the real one does (pinned in section 6). The IDE hops
# themselves (ProjectService.OpenSolution, Solution.Preferences.StartupProject, IProject.ActiveConfiguration) need a
# running Clarion IDE and are NOT covered here: their names were checked against the C10/C11/C12 binaries by
# reflection (2026-09-25), and the pad's calls into them are pinned by position below.
#
# ASCII only, for Windows PowerShell 5.1.

param(
  # Defaulted in the body: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $TargetServicePath = '',
  [string] $CwprojReaderPath = '',
  [string] $WebViewPath = '',
  [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$root = Join-Path $PSScriptRoot '..'
if (-not $TargetServicePath) { $TargetServicePath = Join-Path $root 'src\ClarionDebugger.Addin\Services\ProjectTargetService.cs' }
if (-not $CwprojReaderPath) { $CwprojReaderPath = Join-Path $root 'src\ClarionDebugger.Addin\Services\CwprojReader.cs' }
if (-not $WebViewPath) { $WebViewPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs' }
$others = @('Services\RedFileService.cs', 'Services\ClarionVersionService.cs', 'Services\ReflectionHelpers.cs') |
  ForEach-Object { Join-Path $root ('src\ClarionDebugger.Addin\' + $_) }

# ================================================================================================ -SelfTest
# Each mutation breaks ONE guard in a copy of the source and runs this suite on the copy in a fresh process
# (Add-Type cannot redefine a loaded type). CAUGHT only when that run exits non-zero AND never prints its success
# line, AND printed its compile line; a find that does not match exactly once is a failure.
if ($SelfTest) {
  $M = @(
    @{ Id = 'T1'; File = 'cwr'; Why = 'a condition is compared with regard to case';
       Find = 'bool equal = string.Equals(left, right, StringComparison.OrdinalIgnoreCase);'; Repl = 'bool equal = string.Equals(left, right, StringComparison.Ordinal);' }
    @{ Id = 'T2'; File = 'cwr'; Why = '!= is evaluated as ==';
       Find = 'result = m.Groups["op"].Value == "==" ? equal : !equal;'; Repl = 'result = equal;' }
    @{ Id = 'T3'; File = 'cwr'; Why = 'a condition naming another property is evaluated anyway';
       Find = 'if (left.IndexOf("$(", StringComparison.Ordinal) >= 0) return false;   // another property'; Repl = 'if (left.IndexOf("$(", StringComparison.Ordinal) >= 0 && left.Length < 0) return false;   // another property' }
    @{ Id = 'T4'; File = 'cwr'; Why = 'the FIRST applicable value wins, not the last (MSBuild)';
       Find = 'if (isType) type = value; else name = value;'; Repl = 'if (isType) { if (type == null) type = value; } else if (name == null) name = value;' }
    @{ Id = 'T5'; File = 'cwr'; Why = 'an unevaluable group condition is skipped instead of falling back';
       Find = 'if (!groupKnown) { unevaluated = groupCond; break; }'; Repl = 'if (!groupKnown) continue;' }
    @{ Id = 'T6'; File = 'cwr'; Why = 'the project''s default configuration is not used when the IDE gives none';
       Find = 'if (string.IsNullOrEmpty(config)) config = DefaultProperty(groups, "Configuration");'; Repl = '' }
    @{ Id = 'T7'; File = 'pts'; Why = 'the startup project is not preferred';
       Find = 'if (startup != null && (outputName = exeOutputName(startup)) != null) { chosen = startup; source = "startup"; return TargetOutcome.Resolved; }'; Repl = '' }
    @{ Id = 'T8'; File = 'pts'; Why = 'several EXEs resolve to one of them';
       Find = 'if (exeCount > 1) return TargetOutcome.SeveralExes;'; Repl = 'if (exeCount > 1 && exeCount < 0) return TargetOutcome.SeveralExes;' }
    @{ Id = 'T9'; File = 'cwr'; Why = 'a child property''s own condition is ignored';
       Find = 'if (!childApplies) continue;'; Repl = 'if (!childApplies && childCond == "") continue;' }
    @{ Id = 'T10'; File = 'pts'; Why = 'the startup project falls back to Solution.StartupProject (the first startable one)';
       Find = 'return ReflectionHelpers.GetProp(prefs, "StartupProject");'; Repl = 'return ReflectionHelpers.GetProp(prefs, "StartupProject") ?? ReflectionHelpers.GetProp(solution, "StartupProject");' }
    @{ Id = 'T11'; File = 'pts'; Why = 'the resolver reads a project through its own copy of the reader, not CwprojReader';
       Find = 'return CwprojReader.Read(fn, config, platform, out outType, out outName);'; Repl = 'outType = "WinExe"; outName = null; return fn != null;' }
    @{ Id = 'W1'; File = 'web'; Why = 'the target message omits state';
       Find = '+ ",\"state\":\"" + s + "\""'; Repl = '' }
    @{ Id = 'W2'; File = 'web'; Why = 'a target with no path is not "none"';
       Find = 'string s = path.Length == 0 ? "none"'; Repl = 'string s = path.Length < 0 ? "none"' }
    @{ Id = 'W3'; File = 'web'; Why = 'the note is not held to 200 characters';
       Find = 'if (n != null && n.Length > TargetNoteMax) n = n.Substring(0, TargetNoteMax);'; Repl = '' }
    @{ Id = 'W4'; File = 'web'; Why = 'an unconfirmed kept path is claimed as auto';
       Find = 'SetTargetState(string.IsNullOrEmpty(_exe) ? TargetState.None : TargetState.Unconfirmed, note);'
       Repl = 'SetTargetState(string.IsNullOrEmpty(_exe) ? TargetState.None : TargetState.Auto, note);' }
    @{ Id = 'W5'; File = 'web'; Why = 'Start''s step 3 leaves the old target on the bar as it was';
       Find = 'ApplyNoTarget(r != null ? r.Outcome : ProjectTargetService.TargetOutcome.Failed, why, ctx);'; Repl = '' }
    @{ Id = 'W6'; File = 'web'; Why = 'SetTargetState writes the state without pushing it';
       Find = "_exeState = state; _exeNote = note;`n            PushTarget();"; Repl = '_exeState = state; _exeNote = note;' }
    @{ Id = 'W7'; File = 'web'; Why = 'procedures are listed for an unconfirmed target';
       Find = 'if (!string.IsNullOrEmpty(_exe) && (_exeState == TargetState.Auto || _exeState == TargetState.Manual))'; Repl = 'if (!string.IsNullOrEmpty(_exe))' }
    @{ Id = 'W8'; File = 'web'; Why = 'a manual pick for this context is downgraded when the solution has no auto target';
       Find = 'if (manualHere) { SetTargetState(TargetState.Manual, null); return; }'; Repl = '' }
    @{ Id = 'W9'; File = 'web'; Why = 'no solution open: the cleared target is written but not pushed';
       Find = "SetTargetState(TargetState.None, note);`n                return;"; Repl = "_exeState = TargetState.None; _exeNote = note;`n                return;" }
    @{ Id = 'W10'; File = 'web'; Why = 'Start confirming a target does not relist';
       Find = 'if (!listed) ListProceduresForTarget();   // a list emptied'; Repl = '// a list emptied' }
    @{ Id = 'W11'; File = 'web'; Why = 'a Browse pick does not relist';
       Find = "SetTargetState(TargetState.Manual, null);`n                    if (!listed) ListProceduresForTarget();"; Repl = 'SetTargetState(TargetState.Manual, null);' }
    @{ Id = 'W12'; File = 'web'; Why = 'a Start lists a target it just switched to a second time';
       Find = 'LoadStaticSymbols(_exe, relist: !listed);'; Repl = 'LoadStaticSymbols(_exe, relist: true);' }
    @{ Id = 'W13'; File = 'web'; Why = 'LoadStaticSymbols lists whatever it is told';
       Find = 'if (relist) PushProcedures(exe);'; Repl = 'PushProcedures(exe);' }
    @{ Id = 'W14'; File = 'web'; Why = 'an attach (the default) does not list';
       Find = 'private void LoadStaticSymbols(string exe, bool relist = true)'; Repl = 'private void LoadStaticSymbols(string exe, bool relist = false)' }
    @{ Id = 'W15'; File = 'web'; Why = 'a Start that keeps its listed target does not list it';
       Find = 'listed = ok && ListedSince(gen0, _exe);'; Repl = 'listed = ok;' }
    @{ Id = 'W16'; File = 'web'; Why = 'a list that was cleared or replaced still counts as listed';
       Find = 'return _procGen != gen0 && _procGen == _procListGen'; Repl = 'return _procGen != gen0' }
    @{ Id = 'W17'; File = 'web'; Why = 'ListProceduresForTarget does not record what it listed';
       Find = '_procListGen = _procGen; _procListExe = _exe;'; Repl = '_procListExe = _exe;' }
    @{ Id = 'W18'; File = 'web'; Why = 'a list from before the Start counts as listed by it';
       Find = 'return _procGen != gen0 && _procGen == _procListGen'; Repl = 'return _procGen == _procListGen' }
    @{ Id = 'W19'; File = 'web'; Why = 'Start''s step 3 repeats ApplyNoTarget''s rule instead of calling it';
       Find = 'ApplyNoTarget(r != null ? r.Outcome : ProjectTargetService.TargetOutcome.Failed, why, ctx);'
       Repl = '_exeState = string.IsNullOrEmpty(_exe) ? TargetState.None : TargetState.Unconfirmed; _exeNote = why; PushTarget();' }
    @{ Id = 'W20'; File = 'web'; Why = 'a Browse pick is not made manual';
       Find = "SetTargetState(TargetState.Manual, null);`n                    if (!listed)"; Repl = 'if (!listed)' }
    @{ Id = 'W21'; File = 'web'; Why = 'an auto-resolve does not set or push the target';
       Find = "SetTargetState(TargetState.Auto, null);`n                    return;"; Repl = 'return;' }
  )
  $base = Join-Path ([IO.Path]::GetTempPath()) ('target-selftest-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $base | Out-Null
  try {
    $src = @{ pts = $TargetServicePath; cwr = $CwprojReaderPath; web = $WebViewPath }
    $runs = @()
    foreach ($m in $M) {
      $dir = Join-Path $base $m.Id; New-Item -ItemType Directory -Path $dir | Out-Null
      foreach ($k in $src.Keys) { Copy-Item -LiteralPath $src[$k] -Destination (Join-Path $dir ([IO.Path]::GetFileName($src[$k]))) }
      $target = Join-Path $dir ([IO.Path]::GetFileName($src[$m.File]))
      $text = [IO.File]::ReadAllText($target)
      # The sources are LF in git and CRLF in a working tree (autocrlf): the find matches either.
      $pattern = [regex]::Escape($m.Find) -replace '\\n', '\r?\n'
      $n = [regex]::Matches($text, $pattern).Count
      Check "$($m.Id) find matches once ($($m.Why))" ($n -eq 1) "$n match(es)"
      if ($n -eq 1) { [IO.File]::WriteAllText($target, [regex]::Replace($text, $pattern, $m.Repl.Replace('$', '$$'))); $runs += $m }
    }
    $dir = Join-Path $base 'CONTROL'; New-Item -ItemType Directory -Path $dir | Out-Null
    foreach ($k in $src.Keys) { Copy-Item -LiteralPath $src[$k] -Destination (Join-Path $dir ([IO.Path]::GetFileName($src[$k]))) }
    $runs += @{ Id = 'CONTROL'; Why = 'unmutated copies' }
    foreach ($r in $runs) {
      $d = Join-Path $base $r.Id
      $out = & pwsh -NoProfile -File $PSCommandPath -TargetServicePath (Join-Path $d 'ProjectTargetService.cs') `
        -CwprojReaderPath (Join-Path $d 'CwprojReader.cs') -WebViewPath (Join-Path $d 'ClarionDebuggerWebView.cs') 2>&1
      $code = $LASTEXITCODE
      $passed = [bool](@($out) -match '^ALL \d+ CHECKS PASSED')
      $compiled = [bool](@($out) -match '^compiled the target resolver and the pad''s target writers$')
      $fails = (@($out) -match '^\s*FAIL' | Select-Object -First 2) -join ' / '
      if ($r.Id -eq 'CONTROL') { Check 'CONTROL: the unmutated copies pass' ($passed -and $code -eq 0) "exit=$code" }
      else { Check "$($r.Id) CAUGHT: $($r.Why)" ($compiled -and (-not $passed) -and $code -ne 0) "exit=$code compiled=$compiled $fails" }
    }
  } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
  # 32 finds + 32 mutations + 1 control
  Assert-CheckTotal 65
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ================================================================================================ compile
$web = Get-Content -Raw -LiteralPath $WebViewPath
function Public { param([string] $s) $s -replace '^(private|internal) ', 'public ' }
# The stubs' names stand in for the IDE: a lifted method that asks ProjectTargetService for the target or the
# context asks the scenario instead.
function Stubbed { param([string] $s)
  $s -replace 'ProjectTargetService\.ResolveTarget\(\)', 'ResolveStub()' -replace 'ProjectTargetService\.GetActiveContextKey\(\)', 'CtxStub()' `
     -replace 'System\.Threading\.ThreadPool\.QueueUserWorkItem\(', 'RunNow('
}
# The Start and the attach, as StartSession and AttachSession ship them: the resolve and the symbol load.
$startSrc = Get-Method 'private void StartSession()' $web
$mResolve = [regex]::Match($startSrc, '(?s)bool listed;\s*if \(!ResolveTargetForStart\(out listed\)\) return;')
$mLoad = [regex]::Match($startSrc, 'LoadStaticSymbols\(_exe[^;]*\);')
$attachSrc = Get-Method 'private void AttachSession(AttachableProcess target)' $web
$mAttach = [regex]::Match($attachSrc, '[^\r\n;{}]*LoadStaticSymbols\(exe[^;]*\);')
if (-not ($mResolve.Success -and $mLoad.Success -and $mAttach.Success)) {
  Write-Host "FAIL: StartSession/AttachSession no longer read as this suite lifts them (resolve=$($mResolve.Success) load=$($mLoad.Success) attach=$($mAttach.Success))"
  exit 1
}
$lifted = @(
  (Get-Method 'private static string Str(string s)' $web),
  ((Get-Method 'internal enum TargetState' $web) -replace '^internal', 'public'),
  (Get-Statement 'internal const int TargetNoteMax' $web),
  (Public (Get-Method 'internal static string TargetJson(string path, bool exists, TargetState state, string note)' $web)),
  (Public (Get-Method 'private void ApplyNoTarget(ProjectTargetService.TargetOutcome outcome, string note, string ctx)' $web)),
  (Public (Get-Method 'private void SetTargetState(TargetState state, string note)' $web)),
  (Get-Statement 'private int _procListGen;' $web),
  (Get-Statement 'private string _procListExe;' $web),
  (Public (Get-Method 'private bool ListedSince(int gen0, string exe)' $web)),
  (Public (Get-Method 'private bool ListProceduresForTarget()' $web)),
  (Public (Get-Method 'private bool IsListedTarget(string exe)' $web)),
  (Public (Get-Method 'private void ClearProcedures()' $web)),
  (Public (Get-Method 'private void LoadStaticSymbols(string exe, bool relist' $web) | ForEach-Object { Stubbed $_ }),
  (Public (Get-Method 'private bool ResolveTargetForStart(out bool listed)' $web)),
  (Public (Get-Method 'private bool ResolveTargetForStartCore()' $web) | ForEach-Object { Stubbed $_ }),
  (Public (Get-Method 'private bool BrowseForContext(string ctx)' $web)),
  (Public (Get-Method 'private bool Browse()' $web)),
  (Public (Get-Method 'private void TryAutoResolveExe()' $web) | ForEach-Object { Stubbed $_ }),
  (Public (Get-Method 'private static string SafeContextKey()' $web) | ForEach-Object { Stubbed $_ })
) -join "`n"
$probe = @"
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using ClarionDebugger.Services;

namespace ClarionDebugger.Services
{
  // The resolver's pure deciders, reached from inside its assembly (they are internal).
  public static class TargetProbe {
    public static string Eval(string cond, string config, string platform) {
      bool r; return CwprojReader.TryEvaluateCondition(cond, config, platform, out r) ? (r ? "T" : "F") : "?";
    }
    public static string Read(string xml, string config, string platform) {
      var d = new XmlDocument(); d.LoadXml(xml);
      string t, n, u;
      bool ok = CwprojReader.ReadOutput(d, config, platform, out t, out n, out u);
      return (ok ? "ok" : "no") + "|" + (t ?? "-") + "|" + (n ?? "-") + "|" + (u == null ? "-" : "UNEVALUATED");
    }
    // Projects are strings: "exe:NAME" is an executable whose OutputName is NAME (or none for "exe:"), anything
    // else is not an executable. Returns outcome|chosen|outputName|source.
    public static string Choose(string startup, string active, string[] projects) {
      object chosen; string name, source;
      var o = ProjectTargetService.Choose(startup, active, projects,
        p => { var s = (string)p; return s.StartsWith("exe:") ? s.Substring(4) : null; }, out chosen, out name, out source);
      return o + "|" + (chosen ?? "-") + "|" + (name ?? "-") + "|" + (source ?? "-");
    }
  }
}
namespace ClarionDebugger.Terminal
{
  // What Browse's dialog answers: the scenario's pick, or a cancel when there is none (PowerShell sets a null
  // string field to "", so empty is none too).
  public enum DialogResult { OK, Cancel }
  public sealed class OpenFileDialog : IDisposable {
    public static string Pick;
    public string Filter; public string FileName;
    public DialogResult ShowDialog(object owner) { FileName = Pick; return string.IsNullOrEmpty(Pick) ? DialogResult.Cancel : DialogResult.OK; }
    public void Dispose() { }
  }
  public static class ClarionDebuggerService { public static string GetGlobalsJson(string exe) { return null; } }
  public sealed class ProcIdsStub { public void Clear() { } }

  // The pad's target writers, lifted as they ship, over the fields they write.
  public sealed class TargetPad {
    public string _exe = ""; public bool _exeAuto; public string _exeManualKey;
    public TargetState _exeState = TargetState.None; public string _exeNote;
    public int _procGen;
    private readonly ProcIdsStub _procIds = new ProcIdsStub();
    public static ProjectTargetService.TargetResolution Next;
    public static string Ctx;
    public int Pushes;
    public List<string> Pushed = new List<string>();
    public List<string> Consoles = new List<string>();
    private ProjectTargetService.TargetResolution ResolveStub() { return Next; }
    private static string CtxStub() { return Ctx; }
    private void PushTarget() { Pushes++; }
    // As the real one: nothing for no EXE, else one generation per list (pinned in section 6).
    private void PushProcedures(string exe) { if (string.IsNullOrEmpty(exe)) return; ++_procGen; Pushed.Add(exe); }
    private void Console(string level, string text) { Consoles.Add(level + ": " + text); }
    private void Post(string json) { }
    private void UI(Action a) { a(); }
    private static void RunNow(System.Threading.WaitCallback cb) { cb(null); }
    public void Start() { $($mResolve.Value) $($mLoad.Value) }
    public void Attach(string exe) { $($mAttach.Value) }
    $lifted
    public string State { get { return _exeState.ToString(); } }
  }
}
"@
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('target-probe-' + [guid]::NewGuid().ToString('N') + '.cs')
[IO.File]::WriteAllText($tmp, $probe)
try {
  $paths = @($TargetServicePath, $CwprojReaderPath) + $others | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
  Add-Type -Path ($paths + $tmp) -IgnoreWarnings -WarningAction SilentlyContinue -ReferencedAssemblies @(
    'System.Xml', 'System.Xml.ReaderWriter', 'System.Xml.XmlDocument', 'System.Diagnostics.Process', 'System.Diagnostics.FileVersionInfo',
    'System.ComponentModel.Primitives', 'System.Text.RegularExpressions', 'System.Collections', 'System.Linq',
    'System.Runtime.InteropServices', 'System.Diagnostics.Debug', 'Microsoft.Win32.Registry', 'System.Threading',
    'System.Threading.ThreadPool') | Out-Null
} finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
# Printed so the self-test can tell "a check caught the mutant" from "the mutant never compiled".
Write-Host 'compiled the target resolver and the pad''s target writers'

$P = [ClarionDebugger.Services.TargetProbe]
function Proj { param([string] $body) '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">' + $body + '</Project>' }
$defaults = '<PropertyGroup><Configuration Condition=" ''$(Configuration)'' == '''' ">Debug</Configuration><Platform Condition=" ''$(Platform)'' == '''' ">Win32</Platform></PropertyGroup>'

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '1. the conditions Clarion writes are evaluated against the active configuration and platform'
$cp = "'`$(Configuration)|`$(Platform)' == 'Debug|Win32'"
Check 'CONTROL: ''$(Configuration)|$(Platform)'' == ''Debug|Win32'' is true under Debug|Win32' ($P::Eval($cp, 'Debug', 'Win32') -ceq 'T') ''
Check '...and false under Release|Win32' ($P::Eval($cp, 'Release', 'Win32') -ceq 'F') ''
Check '...compared without regard to case, as MSBuild compares' ($P::Eval($cp, 'debug', 'WIN32') -ceq 'T') ''
Check '''$(Configuration)'' == ''Release'' alone' (($P::Eval("'`$(Configuration)' == 'Release'", 'Release', $null) -ceq 'T') -and ($P::Eval(" '`$(Configuration)'=='Release' ", 'Debug', $null) -ceq 'F')) ''
Check '''$(Platform)'' == ''Win32'' alone' ($P::Eval("'`$(Platform)' == 'Win32'", $null, 'Win32') -ceq 'T') ''
Check '!= is the negation' (($P::Eval("'`$(Configuration)' != 'Release'", 'Debug', $null) -ceq 'T') -and ($P::Eval("'`$(Configuration)' != 'Debug'", 'Debug', $null) -ceq 'F')) ''
$cannot = @("Exists('x.inc')", "'`$(Foo)' == 'x'", "'`$(Configuration)' == '`$(Other)'", "'`$(Configuration)' == 'A' and '`$(Platform)' == 'B'", "`$(Configuration) == Debug")
$said = @($cannot | Where-Object { $P::Eval($_, 'Debug', 'Win32') -cne '?' })
Check 'any other shape, another property, or a property on the right is "cannot say", never a guess' ($said.Count -eq 0) ($said -join ' | ')
Check 'a condition on a value the IDE did not give is "cannot say"' ($P::Eval($cp, $null, 'Win32') -ceq '?') ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2. OutputType and OutputName are read as MSBuild reads them for that configuration'
$typical = Proj ($defaults + '<PropertyGroup><OutputType>WinExe</OutputType><OutputName>clbrws</OutputName></PropertyGroup>' +
  '<PropertyGroup Condition=" ''$(Configuration)'' == ''Debug'' "><DebugSymbols>True</DebugSymbols></PropertyGroup>')
Check 'CONTROL: the usual cwproj - both unconditioned - reads as ever' ($P::Read($typical, 'Debug', 'Win32') -ceq 'ok|WinExe|clbrws|-') $P::Read($typical, 'Debug', 'Win32')
$splitGroups = '<PropertyGroup Condition=" ''$(Configuration)|$(Platform)'' == ''Debug|Win32'' "><OutputType>Exe</OutputType><OutputName>appdbg</OutputName></PropertyGroup>' +
  '<PropertyGroup Condition=" ''$(Configuration)|$(Platform)'' == ''Release|Win32'' "><OutputType>Library</OutputType><OutputName>apprel</OutputName></PropertyGroup>'
$split = Proj ($defaults + $splitGroups)
Check 'a Release-only group is read under Release (the rule it replaced read the Debug group for both)' ($P::Read($split, 'Release', 'Win32') -ceq 'ok|Library|apprel|-') $P::Read($split, 'Release', 'Win32')
Check '...and the Debug group under Debug' ($P::Read($split, 'Debug', 'Win32') -ceq 'ok|Exe|appdbg|-') $P::Read($split, 'Debug', 'Win32')
Check 'with no configuration from the IDE, the project''s own default (Debug) decides' ($P::Read($split, $null, $null) -ceq 'ok|Exe|appdbg|-') $P::Read($split, $null, $null)
$later = Proj ($defaults + '<PropertyGroup><OutputType>WinExe</OutputType><OutputName>base</OutputName></PropertyGroup>' +
  '<PropertyGroup Condition=" ''$(Configuration)'' == ''Release'' "><OutputName>shipped</OutputName></PropertyGroup>')
Check 'a later applicable value replaces an earlier one (Release)' ($P::Read($later, 'Release', 'Win32') -ceq 'ok|WinExe|shipped|-') $P::Read($later, 'Release', 'Win32')
Check '...and a group that does not apply changes nothing (Debug)' ($P::Read($later, 'Debug', 'Win32') -ceq 'ok|WinExe|base|-') $P::Read($later, 'Debug', 'Win32')
$prop = Proj ($defaults + '<PropertyGroup><OutputType>WinExe</OutputType><OutputName>base</OutputName><OutputName Condition=" ''$(Configuration)'' == ''Release'' ">rel</OutputName></PropertyGroup>')
Check 'a property''s OWN condition is evaluated too' (($P::Read($prop, 'Release', 'Win32') -ceq 'ok|WinExe|rel|-') -and ($P::Read($prop, 'Debug', 'Win32') -ceq 'ok|WinExe|base|-')) ($P::Read($prop, 'Debug', 'Win32'))
$odd = Proj ($defaults + '<PropertyGroup Condition=" Exists(''x.props'') "><OutputType>Library</OutputType><OutputName>odd</OutputName></PropertyGroup>' +
  '<PropertyGroup><OutputType>WinExe</OutputType><OutputName>app</OutputName></PropertyGroup>')
Check 'a condition it cannot evaluate, on a group that sets them, falls back WHOLE to the first-declared rule and says so' `
  ($P::Read($odd, 'Debug', 'Win32') -ceq 'ok|WinExe|app|UNEVALUATED') $P::Read($odd, 'Debug', 'Win32')
$oddElsewhere = Proj ($defaults + '<PropertyGroup Condition=" Exists(''x.props'') "><DefineConstants>X</DefineConstants></PropertyGroup>' + $splitGroups)
Check 'one it cannot evaluate on a group that sets neither is no reason to fall back' ($P::Read($oddElsewhere, 'Release', 'Win32') -ceq 'ok|Library|apprel|-') $P::Read($oddElsewhere, 'Release', 'Win32')
$noDefault = Proj ('<PropertyGroup Condition=" ''$(Configuration)'' == ''Release'' "><OutputType>Library</OutputType></PropertyGroup><PropertyGroup Condition=" ''$(Configuration)'' == ''Debug'' "><OutputType>Exe</OutputType></PropertyGroup>')
Check 'no configuration from the IDE and none in the project: the conditions cannot be evaluated, so the old rule reads it' `
  ($P::Read($noDefault, $null, $null) -ceq 'ok|Library|-|UNEVALUATED') $P::Read($noDefault, $null, $null)
Check 'a project that declares no OutputType resolves nothing' ($P::Read((Proj $defaults), 'Debug', 'Win32') -ceq 'no|-|-|-') ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '3. which project is the target: the startup project, then the active one, then the only EXE'
Check 'the IDE''s startup project wins over an active EXE' ($P::Choose('exe:A', 'exe:B', @('exe:A', 'exe:B')) -ceq 'Resolved|exe:A|A|startup') ''
Check 'several EXEs, one of them the startup project: that one (the multi-EXE case this ticket fixes)' `
  ($P::Choose('exe:A', 'dll', @('exe:A', 'exe:B', 'dll')) -ceq 'Resolved|exe:A|A|startup') ''
Check 'a startup project that is a DLL is passed over for an active EXE' ($P::Choose('dll', 'exe:B', @('dll', 'exe:B', 'exe:C')) -ceq 'Resolved|exe:B|B|active') ''
Check 'neither an EXE: the solution''s only EXE' ($P::Choose('dll', 'dll', @('dll', 'exe:C')) -ceq 'Resolved|exe:C|C|only') ($P::Choose('dll', 'dll', @('dll', 'exe:C')))
Check 'several EXEs and none of them startup or active: no target, and it says why' ($P::Choose('dll', $null, @('exe:A', 'exe:B')) -ceq 'SeveralExes|-|-|-') ''
Check 'no EXE at all: no target' ($P::Choose($null, 'dll', @('dll')) -ceq 'NoExe|-|-|-') ''
$sev = New-Object ClarionDebugger.Services.ProjectTargetService+TargetResolution
$sev.Outcome = [ClarionDebugger.Services.ProjectTargetService+TargetOutcome]::SeveralExes
Check 'the several-EXEs note is the contract''s wording' ($sev.Note -ceq 'Several EXEs in this solution - pick one (Browse)') $sev.Note

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '4. the target message, in the contract''s literal shape (C4)'
$S = [ClarionDebugger.Terminal.TargetPad+TargetState]
$TP = [ClarionDebugger.Terminal.TargetPad]
Check 'auto: path, exists, state - and no note member when there is none' `
  ($TP::TargetJson('C:\App\clbrws.exe', $true, $S::Auto, $null) -ceq '{"type":"target","path":"C:\\App\\clbrws.exe","exists":true,"state":"auto"}') ($TP::TargetJson('C:\App\clbrws.exe', $true, $S::Auto, $null))
Check 'manual' ($TP::TargetJson('D:\x.exe', $false, $S::Manual, $null) -ceq '{"type":"target","path":"D:\\x.exe","exists":false,"state":"manual"}') ''
Check 'unconfirmed, with its note LAST' `
  ($TP::TargetJson('C:\Old\a.exe', $true, $S::Unconfirmed, 'Several EXEs in this solution - pick one (Browse)') -ceq '{"type":"target","path":"C:\\Old\\a.exe","exists":true,"state":"unconfirmed","note":"Several EXEs in this solution - pick one (Browse)"}') ''
Check 'none: an empty path is "none" whatever the pad''s state says' `
  ($TP::TargetJson('', $false, $S::Auto, 'No solution open') -ceq '{"type":"target","path":"","exists":false,"state":"none","note":"No solution open"}') ''
Check 'a path whose state was never confirmed is sent as unconfirmed, never as authoritative' ($TP::TargetJson('C:\a.exe', $true, $S::None, $null) -cmatch '"state":"unconfirmed"\}$') ''
$long = 'x' * 250
$j = $TP::TargetJson('', $false, $S::None, "one`r`ntwo " + $long)
$note = [regex]::Match($j, '"note":"([^"]*)"').Groups[1].Value
Check 'the note is ONE line of at most 200 characters' (($note.Length -eq 200) -and ($note -notmatch '[\r\n]') -and $note.StartsWith('one  two')) "len=$($note.Length)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '5. what a resolve that found no target does to the one the pad holds'
$O = [ClarionDebugger.Services.ProjectTargetService+TargetOutcome]
function Pad { param([string] $exe, [bool] $auto, $key, $state)
  $p = New-Object ClarionDebugger.Terminal.TargetPad
  $p._exe = $exe; $p._exeAuto = $auto; if ($null -ne $key) { $p._exeManualKey = $key }; $p._exeState = $state; $p
}
$pushes = @()
$p = Pad 'C:\Old\a.exe' $true $null $S::Auto
$p.ApplyNoTarget($O::SeveralExes, 'Several EXEs in this solution - pick one (Browse)', 'sln|proj'); $pushes += $p.Pushes
Check 'an older AUTO path is kept for a retry, but UNCONFIRMED, with the reason' `
  (($p._exe -ceq 'C:\Old\a.exe') -and ($p.State -ceq 'Unconfirmed') -and $p._exeAuto -and ($p._exeNote -ceq 'Several EXEs in this solution - pick one (Browse)')) "$($p.State) $($p._exe)"
$p = Pad 'D:\Mine\m.exe' $false 'sln|proj' $S::Manual
$p.ApplyNoTarget($O::NoExe, 'No EXE project in this solution', 'SLN|PROJ'); $pushes += $p.Pushes
Check 'a manual pick made for THIS context stays manual' (($p.State -ceq 'Manual') -and ($null -eq $p._exeNote)) "$($p.State)"
$p = Pad 'D:\Mine\m.exe' $false 'other|ctx' $S::Manual
$p.ApplyNoTarget($O::NoExe, 'No EXE project in this solution', 'sln|proj'); $pushes += $p.Pushes
Check 'a manual pick made for ANOTHER context is unconfirmed' ($p.State -ceq 'Unconfirmed') "$($p.State)"
$p = Pad '' $false $null $S::None
$p.ApplyNoTarget($O::SeveralExes, 'Several EXEs in this solution - pick one (Browse)', 'sln|proj'); $pushes += $p.Pushes
Check 'with no path at all it is "none", and the note says why' (($p.State -ceq 'None') -and ($p._exeNote -cmatch 'Several EXEs')) "$($p.State)"
$p = Pad 'C:\Old\a.exe' $true $null $S::Auto
$p.ApplyNoTarget($O::NoSolution, 'No solution open', $null); $pushes += $p.Pushes
Check 'no solution open: the target is gone' (($p._exe -ceq '') -and ($p.State -ceq 'None') -and (-not $p._exeAuto)) "$($p.State) '$($p._exe)'"
Check 'each of those five outcomes is pushed to the target bar exactly once' ((@($pushes | Where-Object { $_ -ne 1 })).Count -eq 0) ($pushes -join ',')
# The auto-resolve the IDE's events run (TryAutoResolveExe), both ways.
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ('target-exes-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir | Out-Null
$ExeA = Join-Path $tmpDir 'a.exe'; $ExeB = Join-Path $tmpDir 'b.exe'; $ExeMissing = Join-Path $tmpDir 'missing.exe'
[IO.File]::WriteAllText($ExeA, ''); [IO.File]::WriteAllText($ExeB, '')
$TP = [ClarionDebugger.Terminal.TargetPad]
function Res { param($outcome, [string] $path)
  $r = New-Object ClarionDebugger.Services.ProjectTargetService+TargetResolution
  $r.Outcome = $O::$outcome; if ($path) { $r.Path = $path }; $r
}
$TP::Ctx = 'sln|proj'
$TP::Next = Res 'Resolved' $ExeB
$p = Pad $ExeA $true $null $S::Unconfirmed
$p.TryAutoResolveExe()
Check 'an auto-resolve that finds a target sets it auto and pushes it once' (($p._exe -ceq $ExeB) -and ($p.State -ceq 'Auto') -and ($p.Pushes -eq 1)) "$($p.State) pushes=$($p.Pushes)"
$TP::Next = Res 'SeveralExes' $null
$p = Pad $ExeA $true $null $S::Auto
$p.TryAutoResolveExe()
Check '...and one that finds none applies the no-target rule and pushes once' (($p.State -ceq 'Unconfirmed') -and ($p.Pushes -eq 1)) "$($p.State) pushes=$($p.Pushes)"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '6. every change or invalidation of the target is pushed (pinned by position: the pad is a WinForms control)'
$webCode = Get-CSharpCodeOnly $web
$sts = Get-CSharpCodeOnly (Get-Method 'private void SetTargetState(TargetState state, string note)' $web)
Check 'SetTargetState writes the state and the note, then pushes - and does nothing else' `
  ($sts -match '^private void SetTargetState\(TargetState state, string note\)\s*\{\s*_exeState = state; _exeNote = note;\s*PushTarget\(\);\s*\}$') ''
$stateWrites = [regex]::Matches($webCode, '_exeState = ').Count
$noteWrites = [regex]::Matches($webCode, '_exeNote = ').Count
Check 'nothing else writes _exeState or _exeNote: SetTargetState is the only writer, so no write goes unpushed' `
  (($webCode -match 'private TargetState _exeState = TargetState\.None;') -and ($webCode -match 'private string _exeNote;') -and
   ($stateWrites -eq 2) -and ($noteWrites -eq 1)) "_exeState = x$stateWrites (field initializer + SetTargetState), _exeNote = x$noteWrites"
Check 'CONTROL: that count sees one more write' ([regex]::Matches($webCode + ' _exeNote = why;', '_exeNote = ').Count -eq 2) ''
$core = Get-CSharpCodeOnly (Get-Method 'private bool ResolveTargetForStartCore()' $web)
$iSay = $core.IndexOf('"Could not auto-detect'); $iApply = $core.IndexOf('ApplyNoTarget('); $iLast = $core.LastIndexOf('return BrowseForContext(ctx);')
Check 'Start''s step 3 applies ApplyNoTarget''s rule before it offers Browse, and keeps no copy of that rule' `
  (($iSay -ge 0) -and ($iApply -gt $iSay) -and ($iLast -gt $iApply) -and ($core -notmatch 'TargetState\.Unconfirmed')) "say=$iSay apply=$iApply browse=$iLast"
Check 'a procedures list is pushed only through ListProceduresForTarget, and the start path' `
  (([regex]::Matches($webCode, 'PushProcedures\(_exe\)').Count -eq 1) -and ($webCode -match 'private bool ListProceduresForTarget\(\)\s*\{\s*if \(!string\.IsNullOrEmpty\(_exe\) && \(_exeState == TargetState\.Auto \|\| _exeState == TargetState\.Manual\)\)')) ''
Check 'the refresh, the ready handler, the refresh button, and a confirm by Start or Browse list through it' `
  ([regex]::Matches($webCode, 'ListProceduresForTarget\(\)').Count -eq 6) "$([regex]::Matches($webCode, 'ListProceduresForTarget\(\)').Count) mention(s)"
# A list emptied while the target was unconfirmed comes back when Start or Browse confirms one (debugger LOW, run 1):
# after the state is set, unless it was already listed for that same confirmed path.
foreach ($c in @(@('private bool ResolveTargetForStartCore()', 'SetTargetState(TargetState.Auto, null);'), @('private bool Browse()', 'SetTargetState(TargetState.Manual, null);'))) {
  $b = Get-CSharpCodeOnly (Get-Method $c[0] $web)
  $iListed = $b.IndexOf('bool listed = IsListedTarget('); $iSet = $b.IndexOf($c[1], [Math]::Max($iListed, 0))
  $iList = $b.IndexOf('if (!listed) ListProceduresForTarget();')
  Check "$($c[0]) relists after it sets a confirmed target, when that target was not the one listed" `
    (($iListed -ge 0) -and ($iSet -gt $iListed) -and ($iList -gt $iSet)) "listed=$iListed set=$iSet list=$iList"
}
Check 'IsListedTarget means: confirmed, and the same path' `
  ((Get-CSharpCodeOnly (Get-Method 'private bool IsListedTarget(string exe)' $web)) -match `
    'return \(_exeState == TargetState\.Auto \|\| _exeState == TargetState\.Manual\)\s*&& string\.Equals\(_exe, exe, StringComparison\.OrdinalIgnoreCase\);') ''
# Section 7 runs a stub PushProcedures; this is what it stands in for.
$pp = Get-CSharpCodeOnly (Get-Method 'private void PushProcedures(string exe)' $web)
Check 'the real PushProcedures does as its stub does: returns for no EXE, then takes ONE new generation' `
  (($pp -match '^private void PushProcedures\(string exe\)\s*\{\s*if \(string\.IsNullOrEmpty\(exe\)\) return;\s*_svc\.PrimeTarget\(exe\);\s*int gen = \+\+_procGen;') -and
   ([regex]::Matches($pp, '_procGen\b').Count -eq 2)) ''
$iRes = $startSrc.IndexOf($mResolve.Value); $iLoad = $startSrc.IndexOf($mLoad.Value)
Check 'StartSession resolves the target before it loads symbols (the order section 7 runs them in)' `
  (($iRes -ge 0) -and ($iLoad -gt $iRes)) "resolve=$iRes load=$iLoad"
# The startup project is the one the user SET. Solution.StartupProject falls back to the first IsStartable project
# (its IL, C10/C11/C12, read 2026-09-25), which would make "Several EXEs" unreachable.
$ptsSrc = Get-Content -Raw -LiteralPath $TargetServicePath
$ptsCode = Get-CSharpCodeOnly $ptsSrc
$gsp = Get-CSharpCodeOnly (Get-Method 'private static object GetStartupProject(object solution)' $ptsSrc)
Check 'GetStartupProject reads only the preferences'' StartupProject, never the solution''s fallback' `
  (($gsp -match 'return ReflectionHelpers\.GetProp\(prefs, "StartupProject"\);') -and ([regex]::Matches($gsp, '"StartupProject"').Count -eq 1)) ''
Check 'ProjectTargetService reads a project through CwprojReader, the reader sections 1-2 run, and keeps no copy of it' `
  (((Get-CSharpCodeOnly (Get-Method 'private static bool ReadProjectOutput(object project, object solution, out string outType, out string outName)' $ptsSrc)) -match `
     'return CwprojReader\.Read\(fn, config, platform, out outType, out outName\);') -and ($ptsCode -notmatch 'XmlDocument|PropertyGroup|TryEvaluateCondition')) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '7. a Start lists the target''s procedures once; an attach always lists (fb5766d1 X2)'
# Each scenario starts from a pad whose list belongs to $ExeA, an auto target, as the ready handler leaves it.
function ListedPad { param([string] $exe)
  $p = Pad $exe $true $null $S::Auto
  [void]$p.ListProceduresForTarget(); $p.Pushed.Clear(); $p.Pushes = 0; $p
}
$TP::Ctx = 'sln|proj'; [ClarionDebugger.Terminal.OpenFileDialog]::Pick = $null
$TP::Next = Res 'Resolved' $ExeA
$p = ListedPad $ExeA; $p.Start()
Check 'CONTROL: a Start that keeps its listed target lists it once, as it starts' (($p.Pushed -join '|') -ceq $ExeA) ($p.Pushed -join '|')
$TP::Next = Res 'Resolved' $ExeB
$p = ListedPad $ExeA; $p.Start()
Check 'a Start that switches the auto target lists the new one ONCE (it listed it twice)' `
  ((($p.Pushed -join '|') -ceq $ExeB) -and ($p._exe -ceq $ExeB) -and ($p.State -ceq 'Auto')) ($p.Pushed -join '|')
$TP::Next = Res 'NoExe' $null; [ClarionDebugger.Terminal.OpenFileDialog]::Pick = $ExeB
$p = ListedPad $ExeA; $p.Start()
Check 'a Start whose target is picked by Browse lists the pick once, as a manual target' `
  ((($p.Pushed -join '|') -ceq $ExeB) -and ($p.State -ceq 'Manual') -and ($p._exeManualKey -ceq 'sln|proj')) "$($p.Pushed -join '|') $($p.State)"
$TP::Next = Res 'Resolved' $ExeMissing; [ClarionDebugger.Terminal.OpenFileDialog]::Pick = $ExeB
$p = ListedPad $ExeA; $p.Start()
Check 'a resolved target missing on disk, then a Browse pick: each listed once, and the Start lists neither again' `
  (($p.Pushed -join '|') -ceq "$ExeMissing|$ExeB") ($p.Pushed -join '|')
$TP::Next = Res 'SeveralExes' $null; [ClarionDebugger.Terminal.OpenFileDialog]::Pick = $null
$p = ListedPad $ExeA; $p.Start()
Check 'no target and Browse cancelled: the old path stays for a retry, UNCONFIRMED and pushed, and nothing is listed' `
  (($p._exe -ceq $ExeA) -and ($p.State -ceq 'Unconfirmed') -and ($p.Pushes -ge 1) -and ($p._exeNote -cmatch 'Several EXEs') -and ($p.Pushed.Count -eq 0)) `
  "$($p.State) pushes=$($p.Pushes) listed=$($p.Pushed -join '|')"
$TP::Next = Res 'NoSolution' $null
$p = ListedPad $ExeA; $p.Start()
Check 'no solution open: Start''s step 3 drops the old path, as every other no-solution resolve does' `
  (($p._exe -ceq '') -and ($p.State -ceq 'None') -and ($p.Pushes -ge 1)) "$($p.State) '$($p._exe)'"
$p = ListedPad $ExeA; $p.Attach($ExeA)
Check 'an attach lists the image it attached to, even one already listed' (($p.Pushed -join '|') -ceq $ExeA) ($p.Pushed -join '|')
# ListedSince, the test the Start's answer is made of.
$p = Pad $ExeB $true $null $S::Auto
$g0 = $p._procGen; [void]$p.ListProceduresForTarget()
$fresh = $p.ListedSince($g0, $ExeB); $other = $p.ListedSince($g0, $ExeA); $none = $p.ListedSince($p._procGen, $ExeB)
$p.ClearProcedures(); $cleared = $p.ListedSince($g0, $ExeB)
$g1 = $p._procGen; [void]$p.ListProceduresForTarget(); $p.LoadStaticSymbols($ExeB); $superseded = $p.ListedSince($g1, $ExeB)
Check 'ListedSince: true just after ListProceduresForTarget lists that EXE; false for another EXE, with no list since, after a clear, and after any other push' `
  ($fresh -and -not ($other -or $none -or $cleared -or $superseded)) "fresh=$fresh other=$other none=$none cleared=$cleared superseded=$superseded"
Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

Assert-CheckTotal 61
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
