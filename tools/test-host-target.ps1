# The Target EXE, v2 (0214f33a, contract C4): what the pad resolves, and what its target bar is allowed to claim.
#
#   pwsh -NoProfile -File tools\test-host-target.ps1 [-TargetServicePath <ProjectTargetService.cs>] [-WebViewPath <ClarionDebuggerWebView.cs>]
#   pwsh -NoProfile -File tools\test-host-target.ps1 -SelfTest
# Exit code 0 = all checks passed.
#
# Three defects, one ticket. The resolver gave up silently when the active project was a DLL and the solution had
# several EXEs (the IDE's STARTUP project names the one to run); it read OutputType/OutputName with no regard for a
# PropertyGroup's Condition (a Release-only OutputName was read for Debug too); and the pad kept an old solution's
# auto path on the target bar with nothing saying it was no longer confirmed.
#
# RUN, NOT READ. ProjectTargetService.cs is compiled whole and its pure deciders (TryEvaluateCondition,
# ReadCwprojOutput, Choose) are driven with literal .cwproj text. The pad's TargetJson and ApplyNoTarget are lifted
# out of ClarionDebuggerWebView.cs and run against the contract's literal message shapes. The IDE hops themselves
# (ProjectService.OpenSolution, Solution.Preferences.StartupProject, IProject.ActiveConfiguration) need a running
# Clarion IDE and are NOT covered here: their names were checked against the C10/C11/C12 binaries by reflection
# (2026-09-25), and the pad's calls into them are pinned by position below.
#
# ASCII only, for Windows PowerShell 5.1.

param(
  # Defaulted in the body: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $TargetServicePath = '',
  [string] $WebViewPath = '',
  [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$root = Join-Path $PSScriptRoot '..'
if (-not $TargetServicePath) { $TargetServicePath = Join-Path $root 'src\ClarionDebugger.Addin\Services\ProjectTargetService.cs' }
if (-not $WebViewPath) { $WebViewPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs' }
$others = @('Services\RedFileService.cs', 'Services\ClarionVersionService.cs', 'Services\ReflectionHelpers.cs') |
  ForEach-Object { Join-Path $root ('src\ClarionDebugger.Addin\' + $_) }

# ================================================================================================ -SelfTest
# Each mutation breaks ONE guard in a copy of the source and runs this suite on the copy in a fresh process
# (Add-Type cannot redefine a loaded type). CAUGHT only when that run exits non-zero AND never prints its success
# line, AND printed its compile line; a find that does not match exactly once is a failure.
if ($SelfTest) {
  $M = @(
    @{ Id = 'T1'; File = 'pts'; Why = 'a condition is compared with regard to case';
       Find = 'bool equal = string.Equals(left, right, StringComparison.OrdinalIgnoreCase);'; Repl = 'bool equal = string.Equals(left, right, StringComparison.Ordinal);' }
    @{ Id = 'T2'; File = 'pts'; Why = '!= is evaluated as ==';
       Find = 'result = m.Groups["op"].Value == "==" ? equal : !equal;'; Repl = 'result = equal;' }
    @{ Id = 'T3'; File = 'pts'; Why = 'a condition naming another property is evaluated anyway';
       Find = 'if (left.IndexOf("$(", StringComparison.Ordinal) >= 0) return false;   // another property'; Repl = 'if (left.IndexOf("$(", StringComparison.Ordinal) >= 0 && left.Length < 0) return false;   // another property' }
    @{ Id = 'T4'; File = 'pts'; Why = 'the FIRST applicable value wins, not the last (MSBuild)';
       Find = 'if (isType) type = value; else name = value;'; Repl = 'if (isType) { if (type == null) type = value; } else if (name == null) name = value;' }
    @{ Id = 'T5'; File = 'pts'; Why = 'an unevaluable group condition is skipped instead of falling back';
       Find = 'if (!groupKnown) { unevaluated = groupCond; break; }'; Repl = 'if (!groupKnown) continue;' }
    @{ Id = 'T6'; File = 'pts'; Why = 'the project''s default configuration is not used when the IDE gives none';
       Find = 'if (string.IsNullOrEmpty(config)) config = DefaultProperty(groups, "Configuration");'; Repl = '' }
    @{ Id = 'T7'; File = 'pts'; Why = 'the startup project is not preferred';
       Find = 'if (startup != null && (outputName = exeOutputName(startup)) != null) { chosen = startup; source = "startup"; return TargetOutcome.Resolved; }'; Repl = '' }
    @{ Id = 'T8'; File = 'pts'; Why = 'several EXEs resolve to one of them';
       Find = 'if (exeCount > 1) return TargetOutcome.SeveralExes;'; Repl = 'if (exeCount > 1 && exeCount < 0) return TargetOutcome.SeveralExes;' }
    @{ Id = 'T9'; File = 'pts'; Why = 'a child property''s own condition is ignored';
       Find = 'if (!childApplies) continue;'; Repl = 'if (!childApplies && childCond == "") continue;' }
    @{ Id = 'T10'; File = 'pts'; Why = 'the startup project falls back to Solution.StartupProject (the first startable one)';
       Find = 'return ReflectionHelpers.GetProp(prefs, "StartupProject");'; Repl = 'return ReflectionHelpers.GetProp(prefs, "StartupProject") ?? ReflectionHelpers.GetProp(solution, "StartupProject");' }
    @{ Id = 'W10'; File = 'web'; Why = 'Start confirming a target does not relist';
       Find = 'if (!listed) ListProceduresForTarget();   // a list emptied'; Repl = '// a list emptied' }
    @{ Id = 'W11'; File = 'web'; Why = 'a Browse pick does not relist';
       Find = "PushTarget();`n                    if (!listed) ListProceduresForTarget();"; Repl = 'PushTarget();' }
    @{ Id = 'W1'; File = 'web'; Why = 'the target message omits state';
       Find = '+ ",\"state\":\"" + s + "\""'; Repl = '' }
    @{ Id = 'W2'; File = 'web'; Why = 'a target with no path is not "none"';
       Find = 'string s = path.Length == 0 ? "none"'; Repl = 'string s = path.Length < 0 ? "none"' }
    @{ Id = 'W3'; File = 'web'; Why = 'the note is not held to 200 characters';
       Find = 'if (n != null && n.Length > TargetNoteMax) n = n.Substring(0, TargetNoteMax);'; Repl = '' }
    @{ Id = 'W4'; File = 'web'; Why = 'an unconfirmed kept path is claimed as auto';
       Find = "_exeState = string.IsNullOrEmpty(_exe) ? TargetState.None : TargetState.Unconfirmed;`n            _exeNote = note;";
       Repl = "_exeState = string.IsNullOrEmpty(_exe) ? TargetState.None : TargetState.Auto;`n            _exeNote = note;" }
    @{ Id = 'W5'; File = 'web'; Why = 'Start''s step 3 does not push the invalidated target';
       Find = "_exeNote = why;`n            PushTarget();`n            return BrowseForContext(ctx);"; Repl = "_exeNote = why;`n            return BrowseForContext(ctx);" }
    @{ Id = 'W6'; File = 'web'; Why = 'a Browse pick is not pushed';
       Find = "_exeState = TargetState.Manual; _exeNote = null;`n                    PushTarget();"; Repl = '_exeState = TargetState.Manual; _exeNote = null;' }
    @{ Id = 'W7'; File = 'web'; Why = 'procedures are listed for an unconfirmed target';
       Find = 'if (!string.IsNullOrEmpty(_exe) && (_exeState == TargetState.Auto || _exeState == TargetState.Manual))'; Repl = 'if (!string.IsNullOrEmpty(_exe))' }
    @{ Id = 'W8'; File = 'web'; Why = 'a manual pick for this context is downgraded when the solution has no auto target';
       Find = 'if (manualHere) { _exeState = TargetState.Manual; _exeNote = null; return; }'; Repl = '' }
    @{ Id = 'W9'; File = 'web'; Why = 'a null resolve leaves the target bar as it was';
       Find = "ApplyNoTarget(r.Outcome, r.Note, SafeContextKey());`n                PushTarget();"; Repl = 'ApplyNoTarget(r.Outcome, r.Note, SafeContextKey());' }
  )
  $base = Join-Path ([IO.Path]::GetTempPath()) ('target-selftest-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $base | Out-Null
  try {
    $src = @{ pts = $TargetServicePath; web = $WebViewPath }
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
        -WebViewPath (Join-Path $d 'ClarionDebuggerWebView.cs') 2>&1
      $code = $LASTEXITCODE
      $passed = [bool](@($out) -match '^ALL \d+ CHECKS PASSED')
      $compiled = [bool](@($out) -match '^compiled the target resolver and the pad''s target writers$')
      $fails = (@($out) -match '^\s*FAIL' | Select-Object -First 2) -join ' / '
      if ($r.Id -eq 'CONTROL') { Check 'CONTROL: the unmutated copies pass' ($passed -and $code -eq 0) "exit=$code" }
      else { Check "$($r.Id) CAUGHT: $($r.Why)" ($compiled -and (-not $passed) -and $code -ne 0) "exit=$code compiled=$compiled $fails" }
    }
  } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
  # 21 finds + 21 mutations + 1 control
  Assert-CheckTotal 43
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ================================================================================================ compile
$web = Get-Content -Raw -LiteralPath $WebViewPath
$lifted = @(
  (Get-Method 'private static string Str(string s)' $web),
  ((Get-Method 'internal enum TargetState' $web) -replace '^internal', 'public'),
  (Get-Statement 'internal const int TargetNoteMax' $web),
  ((Get-Method 'internal static string TargetJson(string path, bool exists, TargetState state, string note)' $web) -replace '^internal', 'public'),
  ((Get-Method 'private void ApplyNoTarget(ProjectTargetService.TargetOutcome outcome, string note, string ctx)' $web) -replace '^private', 'public')
) -join "`n"
$probe = @"
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using ClarionDebugger.Services;

namespace ClarionDebugger.Services
{
  // The resolver's pure deciders, reached from inside its assembly (they are internal).
  public static class TargetProbe {
    public static string Eval(string cond, string config, string platform) {
      bool r; return ProjectTargetService.TryEvaluateCondition(cond, config, platform, out r) ? (r ? "T" : "F") : "?";
    }
    public static string Read(string xml, string config, string platform) {
      var d = new XmlDocument(); d.LoadXml(xml);
      string t, n, u;
      bool ok = ProjectTargetService.ReadCwprojOutput(d, config, platform, out t, out n, out u);
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
  // The pad's target writers, lifted as they ship, over the fields they write.
  public sealed class TargetPad {
    public string _exe = ""; public bool _exeAuto; public string _exeManualKey;
    public TargetState _exeState = TargetState.None; public string _exeNote;
    $lifted
    public string State { get { return _exeState.ToString(); } }
  }
}
"@
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('target-probe-' + [guid]::NewGuid().ToString('N') + '.cs')
[IO.File]::WriteAllText($tmp, $probe)
try {
  $paths = @($TargetServicePath) + $others | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
  Add-Type -Path ($paths + $tmp) -IgnoreWarnings -WarningAction SilentlyContinue -ReferencedAssemblies @(
    'System.Xml', 'System.Xml.ReaderWriter', 'System.Xml.XmlDocument', 'System.Diagnostics.Process', 'System.Diagnostics.FileVersionInfo',
    'System.ComponentModel.Primitives', 'System.Text.RegularExpressions', 'System.Collections', 'System.Linq',
    'System.Runtime.InteropServices', 'System.Diagnostics.Debug', 'Microsoft.Win32.Registry', 'System.Threading') | Out-Null
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
$p = Pad 'C:\Old\a.exe' $true $null $S::Auto
$p.ApplyNoTarget($O::SeveralExes, 'Several EXEs in this solution - pick one (Browse)', 'sln|proj')
Check 'an older AUTO path is kept for a retry, but UNCONFIRMED, with the reason' `
  (($p._exe -ceq 'C:\Old\a.exe') -and ($p.State -ceq 'Unconfirmed') -and $p._exeAuto -and ($p._exeNote -ceq 'Several EXEs in this solution - pick one (Browse)')) "$($p.State) $($p._exe)"
$p = Pad 'D:\Mine\m.exe' $false 'sln|proj' $S::Manual
$p.ApplyNoTarget($O::NoExe, 'No EXE project in this solution', 'SLN|PROJ')
Check 'a manual pick made for THIS context stays manual' (($p.State -ceq 'Manual') -and ($null -eq $p._exeNote)) "$($p.State)"
$p = Pad 'D:\Mine\m.exe' $false 'other|ctx' $S::Manual
$p.ApplyNoTarget($O::NoExe, 'No EXE project in this solution', 'sln|proj')
Check 'a manual pick made for ANOTHER context is unconfirmed' ($p.State -ceq 'Unconfirmed') "$($p.State)"
$p = Pad '' $false $null $S::None
$p.ApplyNoTarget($O::SeveralExes, 'Several EXEs in this solution - pick one (Browse)', 'sln|proj')
Check 'with no path at all it is "none", and the note says why' (($p.State -ceq 'None') -and ($p._exeNote -cmatch 'Several EXEs')) "$($p.State)"
$p = Pad 'C:\Old\a.exe' $true $null $S::Auto
$p.ApplyNoTarget($O::NoSolution, 'No solution open', $null)
Check 'no solution open: the target is gone' (($p._exe -ceq '') -and ($p.State -ceq 'None') -and (-not $p._exeAuto)) "$($p.State) '$($p._exe)'"

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '6. every change or invalidation of the target is pushed (pinned by position: the pad is a WinForms control)'
$webCode = Get-CSharpCodeOnly $web
# Each method that writes the target state pushes after EVERY write, before it returns.
$writers = @('private bool ResolveTargetForStart()', 'private bool BrowseForContext(string ctx)', 'private void TryAutoResolveExe()',
  'private bool Browse()', 'private void ClearForClosedSolution()')
$unpushed = @()
foreach ($sig in $writers) {
  $body = Get-CSharpCodeOnly (Get-Method $sig $web)
  $parts = [regex]::Split($body, '_exeState = |ApplyNoTarget\(')
  for ($i = 1; $i -lt $parts.Count; $i++) {
    $seg = $parts[$i]
    $iPush = $seg.IndexOf('PushTarget();'); $iRet = $seg.IndexOf('return')
    if ($iPush -lt 0 -or ($iRet -ge 0 -and $iRet -lt $iPush)) { $unpushed += "$sig #$i" }
  }
}
Check 'every write of the target state is followed by a push before the method returns' ($unpushed.Count -eq 0) ($unpushed -join '; ')
Check 'CONTROL: that scan sees a write with no push' `
  (([regex]::Split('_exeState = TargetState.None; return BrowseForContext(ctx);', '_exeState = ')[1].IndexOf('PushTarget();')) -lt 0) ''
$inWriters = [regex]::Matches(((($writers + 'private void ApplyNoTarget(ProjectTargetService.TargetOutcome outcome, string note, string ctx)') |
  ForEach-Object { Get-CSharpCodeOnly (Get-Method $_ $web) }) -join "`n"), '_exeState = ').Count
$everywhere = [regex]::Matches($webCode, '_exeState = ').Count - 1   # less the field's own initializer
Check 'the pad writes _exeState nowhere else (ApplyNoTarget''s caller pushes)' `
  (($webCode -match 'private TargetState _exeState = TargetState\.None;') -and ($everywhere -eq $inWriters)) "$everywhere write(s), $inWriters in the checked methods"
Check 'a procedures list is pushed only through ListProceduresForTarget, and the start path' `
  (([regex]::Matches($webCode, 'PushProcedures\(_exe\)').Count -eq 1) -and ($webCode -match 'private bool ListProceduresForTarget\(\)\s*\{\s*if \(!string\.IsNullOrEmpty\(_exe\) && \(_exeState == TargetState\.Auto \|\| _exeState == TargetState\.Manual\)\)')) ''
Check 'the refresh, the ready handler, the refresh button, and a confirm by Start or Browse list through it' `
  ([regex]::Matches($webCode, 'ListProceduresForTarget\(\)').Count -eq 6) "$([regex]::Matches($webCode, 'ListProceduresForTarget\(\)').Count) mention(s)"
# A list emptied while the target was unconfirmed comes back when Start or Browse confirms one (debugger LOW, run 1):
# after the push, unless it was already listed for that same confirmed path.
foreach ($sig in 'private bool ResolveTargetForStart()', 'private bool Browse()') {
  $b = Get-CSharpCodeOnly (Get-Method $sig $web)
  $iListed = $b.IndexOf('bool listed = IsListedTarget('); $iPush = $b.IndexOf('PushTarget();', [Math]::Max($iListed, 0))
  $iList = $b.IndexOf('if (!listed) ListProceduresForTarget();')
  Check "$sig relists after it pushes a confirmed target, when that target was not the one listed" `
    (($iListed -ge 0) -and ($iPush -gt $iListed) -and ($iList -gt $iPush)) "listed=$iListed push=$iPush list=$iList"
}
Check 'IsListedTarget means: confirmed, and the same path' `
  ((Get-CSharpCodeOnly (Get-Method 'private bool IsListedTarget(string exe)' $web)) -match `
    'return \(_exeState == TargetState\.Auto \|\| _exeState == TargetState\.Manual\)\s*&& string\.Equals\(_exe, exe, StringComparison\.OrdinalIgnoreCase\);') ''
# The startup project is the one the user SET. Solution.StartupProject falls back to the first IsStartable project
# (its IL, C10/C11/C12, read 2026-09-25), which would make "Several EXEs" unreachable.
$ptsSrc = Get-Content -Raw -LiteralPath $TargetServicePath
$gsp = Get-CSharpCodeOnly (Get-Method 'private static object GetStartupProject(object solution)' $ptsSrc)
Check 'GetStartupProject reads only the preferences'' StartupProject, never the solution''s fallback' `
  (($gsp -match 'return ReflectionHelpers\.GetProp\(prefs, "StartupProject"\);') -and ([regex]::Matches($gsp, '"StartupProject"').Count -eq 1)) ''

Assert-CheckTotal 46
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
