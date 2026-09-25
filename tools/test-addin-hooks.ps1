# Negative tests for the cross-addin reflection hooks into ClarionAssistant.
#
# A reflection hook with no negative test is unverified by construction. The happy path - ClarionAssistant
# loaded, correct build, everything binds - is the one case that CANNOT go wrong quietly. Every failure here
# is silent by nature: rename a method or drop a parameter on the other side and the feature simply stops
# existing, with nothing in either process saying so. So these checks are all about the far side being
# MISSING or the WRONG SHAPE.
#
# The hooks are driven by the REAL MonacoHook / FindMonacoType extracted out of ClarionDebuggerWebView.cs by
# brace matching (the trick tools/test-addin-json.ps1 uses), including the REAL hook declarations - so the
# signatures under test are the ones the shipped code actually demands, not ones this file re-types. Against
# them we compile fake ClarionAssistant.dll assemblies with deliberately drifted shapes and load them into a
# live AppDomain, so the scan being exercised is a real AppDomain scan.
#
# Assemblies cannot be unloaded, and each scenario needs a different set of them loaded, so each runs in its
# own child pwsh. The parent just reports.
#
#   pwsh tools/test-addin-hooks.ps1
# Exit code 0 = all checks passed.

param(
  [string] $Scenario = '',
  [string] $WebViewPath    = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs'),
  [string] $ControllerPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\DebugSessionController.cs')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')

# ─────────────────────────────────────────────────────────────────────── parent: fan the scenarios out

# EVERY SCENARIO AND ITS EXPECTED CHECK COUNT, in one table, so the list of scenarios and the totals cannot
# drift apart. THE COUNTING RULE (ticket 60344b78, which found two static counts of this file disagreeing
# by nearly 2x - 20 and 38 - because they counted different things): a number here is the RUNTIME count of
# lib-check's Check calls in that scenario's child process, i.e. $script:checks just before
# Assert-CheckTotal, measured 2026-09-22 on a clean run. A Check inside a loop counts once per pass, which
# is why no grep for `^\s*Check\b` reproduces these. off-thread is 2: its own two Checks on the WinForms
# probe's verdict. The probe's seven C# checks are counted INSIDE the probe and asserted by the second.
$ExpectedByScenario = [ordered] @{
  'absent'         = 8
  'bound'          = 7
  'older-build'    = 5
  'wrong-shape'    = 10
  'wrong-assembly' = 3
  'cached-miss'    = 5
  'stale-copy'     = 5
  'off-thread'     = 2
  'source'         = 8
}
$AllScenarios = @($ExpectedByScenario.Keys)

if (-not $Scenario) {
  # A child's exit code alone is not its verdict. A child that died without throwing - a top-level `break`
  # - exits 0 and prints nothing, which is how a suite passes with half its checks gone (60344b78). So each
  # child must ALSO print its result line, and the line must name its expected total. Invoke-CheckSection
  # in the child turns a thrown or broken-out-of scenario into a non-zero exit; this turns a child that
  # printed no verdict at all into a failed check here.
  $script:childChecks = 0
  Invoke-CheckSection 'run every scenario in its own process' {
    foreach ($s in $AllScenarios) {
      $out = @(& (Get-Process -Id $PID).Path -NoProfile -File $PSCommandPath -Scenario $s -WebViewPath $WebViewPath -ControllerPath $ControllerPath 2>&1 |
               ForEach-Object { "$_" })
      $code = $LASTEXITCODE
      $out | ForEach-Object { Write-Host $_ }
      $want = $ExpectedByScenario[$s] + 1     # + the child's own Assert-CheckTotal, which is a check too
      $line = @($out | Where-Object { $_ -match '^##SCENARIO-RESULT ' }) | Select-Object -Last 1
      $got = -1; $bad = -1
      if ($line -and $line -match "^##SCENARIO-RESULT $([regex]::Escape($s)) checks=(\d+) failures=(\d+)$") {
        $got = [int] $matches[1]; $bad = [int] $matches[2]
        $script:childChecks += $got
      }
      Check "scenario '$s' exited 0 and reported $want checks, none failed" `
        ($code -eq 0 -and $got -eq $want -and $bad -eq 0) "exit $code, result line: $(ShowVal $line)"
      Write-Host ''
    }
  }
  # One check per scenario, so a scenario dropped from the loop is a short total here.
  Assert-CheckTotal $AllScenarios.Count
  Write-Host ''
  $total = $script:checks + $script:childChecks
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) SCENARIO CHECKS FAILED"; exit 1 }
  Write-Host "ALL $total CHECKS PASSED ($($script:childChecks) across $($AllScenarios.Count) scenario processes, $($script:checks) in this one)"
  exit 0
}

# ─────────────────────────────────────────────────────────────────────────────── child: one scenario

$web  = Get-Content -Raw -LiteralPath $WebViewPath
$ctrl = Get-Content -Raw -LiteralPath $ControllerPath

# Get-Method (this file used to call it Get-Block) and Get-Statement come from lib-extract.ps1, dot-sourced
# above. This names the text a bare call reads, which each harness used to bury in its own `if (-not $From)`.
Set-ExtractSource $web



if (-not $ExpectedByScenario.Contains($Scenario)) { Write-Host "  FAIL  unknown scenario '$Scenario'"; exit 1 }

# The child's verdict: its pinned total, then ONE machine-readable line the parent requires. Printed only
# from here, so a child that never reached this point has no result line for the parent to find.
function Done {
  Assert-CheckTotal $ExpectedByScenario[$Scenario]
  Write-Host ''
  Write-Host "##SCENARIO-RESULT $Scenario checks=$($script:checks) failures=$($script:failures)"
  if ($script:failures) { Write-Host "  $($script:failures) FAILURE(S) in scenario '$Scenario'"; exit 1 }
  exit 0
}

# ── the source-level checks need no fake assemblies ───────────────────────────────────────────────────

if ($Scenario -eq 'source') {
  Invoke-CheckSection "[$Scenario] the shape of the code itself" {

    # Finding 1: three copies of the AppDomain scan became one. -le 1 would also pass at zero, i.e. if someone
    # deleted the scan entirely, so this pins the exact count.
    $scans = [regex]::Matches($web, 'AppDomain\.CurrentDomain\.GetAssemblies\(\)')
    Check 'exactly one AppDomain scan in the bridge, not three' ($scans.Count -eq 1) "$($scans.Count) occurrence(s)"

    # Finding 3: the old name inverted the usual Try* meaning by returning true on the FALLBACK path.
    $old = [regex]::Matches($web, '\bTryJump\b')
    Check 'no TryJump left anywhere, doc comments included' ($old.Count -eq 0) "$($old.Count) occurrence(s)"
    Check 'JumpToLine exists and says its return value is not success' `
      ($web -match 'private static bool JumpToLine' -and (Get-Method 'private static bool JumpToLine(string path, int line)') -ne $null -and $web -match 'usedNativeMarker')
    # Finding 3 [NIT]: the native-marker paint was duplicated between the jump helper and MarkExecutionLine.
    # Match the CALL - fully qualified, open paren - not the bare name, which also appears in a doc comment
    # about 0-based line conversion. Counting mentions would make this check claim more than it verifies.
    $paint = [regex]::Matches($web, 'ICSharpCode\.SharpDevelop\.Debugging\.DebuggerService\.JumpToCurrentLine\s*\(')
    Check 'exactly one call site paints the native marker' ($paint.Count -eq 1) "$($paint.Count) call(s)"
    Check 'and it is PaintNativeMarker that owns it' `
      ((Get-Method 'private static void PaintNativeMarker(string path, int line)') -match 'JumpToCurrentLine')

    # Finding 2: the miss must be cached, and re-armed at session start - not on some other event.
    Check 'the hooks are re-armed from StartSession' ((Get-Method 'private void StartSession()') -match 'RearmAndReportMonacoHooks')

    # THE FROZEN CONTRACT. ClarionAssistant's ClarionDebuggerBridge.Bind() requires BOTH of these to resolve,
    # or the entire debugger context menu disappears on that side. They are the wire; this is the guard that
    # says so in a place a future change will trip over.
    Check 'DebugSessionController still exposes: public static DebugControllerState State' `
      ($ctrl -match 'public\s+static\s+DebugControllerState\s+State')
    Check 'DebugSessionController still exposes: public static void RunToCursor()' `
      ($ctrl -match 'public\s+static\s+void\s+RunToCursor\s*\(\s*\)')
  }
  Done
}

# ── build the probe: the REAL hook machinery, lifted out of the source ────────────────────────────────

$probeSrc = @"
using System;
using System.Collections.Generic;
using System.Reflection;

public static class MonacoProbe {
$(Get-Statement 'private const string MonacoTypeName')
$(Get-Statement 'private const string MonacoAssemblyName')
$(Get-Method 'private enum HookStatus')
$((Get-Method 'private sealed class MonacoHook') -replace 'private sealed class MonacoHook', 'public sealed class MonacoHook')
$(Get-Statement 'private static string _monacoDupeNote')
$(Get-Method 'private static Type FindMonacoType()')
$(Get-Statement 'private static readonly MonacoHook _hookNavigate')
$(Get-Statement 'private static readonly MonacoHook _hookExecLine')
$(Get-Statement 'private static readonly MonacoHook _hookCursor')
$(Get-Method 'private static void RearmMonacoHooks()')
}
"@ -replace '(?m)^\s*private const string', '    public const string' `
   -replace '(?m)^\s*private enum HookStatus', '    public enum HookStatus' `
   -replace '(?m)^\s*private static string _monacoDupeNote', '    public static string _monacoDupeNote' `
   -replace '(?m)^\s*private static Type FindMonacoType', '    public static Type FindMonacoType' `
   -replace '(?m)^\s*private static readonly MonacoHook', '    public static readonly MonacoHook' `
   -replace '(?m)^\s*private static void RearmMonacoHooks', '    public static void RearmMonacoHooks'

Add-Type -TypeDefinition $probeSrc -Language CSharp | Out-Null

# ── fake far sides ────────────────────────────────────────────────────────────────────────────────────
#
# Emitted rather than compiled, because the ASSEMBLY NAME is part of what is under test and Add-Type
# -OutputAssembly gives the assembly a random internal name regardless of the file name - which would make
# the assembly-name check look like it was working when it was only ever rejecting garbage. A dynamic
# assembly lets us name it exactly, needs no compiler or temp file, and still shows up in a real
# AppDomain.CurrentDomain.GetAssemblies() scan, which is the code path being exercised.
#
# Only the SIGNATURES matter here - the signature IS the contract - so every body is a stub.

$OP = [System.Reflection.Emit.OpCodes]
$STR = [string]; $INT = [int]; $BOOL = [bool]
$REF_STR = $STR.MakeByRefType(); $REF_INT = $INT.MakeByRefType()

# name, return type, parameter types, and how to fill the body.
$Shapes = @{
  # the three hooks as ClarionAssistant really ships them
  'navigate'        = @{ Name = 'NavigateToFileAndLine'; Ret = $BOOL; Args = @($STR, $INT, $INT);  Body = 'true' }
  'execline'        = @{ Name = 'SetExecutionLine';      Ret = $BOOL; Args = @($STR, $INT);        Body = 'true' }
  'cursor'          = @{ Name = 'TryGetActiveCursor';    Ret = $BOOL; Args = @($REF_STR, $REF_INT, $REF_INT); Body = 'cursor' }
  # the same three names under drifted shapes: a dropped parameter, and a return type changed to void
  'navigate-drift'  = @{ Name = 'NavigateToFileAndLine'; Ret = $BOOL; Args = @($STR, $INT);        Body = 'true' }
  'execline-void'   = @{ Name = 'SetExecutionLine';      Ret = [void]; Args = @($STR, $INT);       Body = 'void' }
  'cursor-drift'    = @{ Name = 'TryGetActiveCursor';    Ret = $BOOL; Args = @($REF_STR, $REF_INT); Body = 'cursor2' }
}

$Good  = @('navigate', 'execline', 'cursor')
$Older = @('navigate')                                        # the type exists; two hooks simply do not yet
$Skew  = @('navigate-drift', 'execline-void', 'cursor-drift') # every name present, every shape wrong

function New-FarSide {
  param([string[]] $Members, [string] $AssemblyName = 'ClarionAssistant', [string] $Version = '5.9.0.1235')
  $an = [System.Reflection.AssemblyName]::new($AssemblyName)
  $an.Version = [Version] $Version
  $ab = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($an, 'Run')
  $mod = $ab.DefineDynamicModule($AssemblyName)
  $tb = $mod.DefineType('ClarionAssistant.Services.MonacoSourceNavigator', 'Public, Abstract, Sealed')
  foreach ($key in $Members) {
    $s = $Shapes[$key]
    $m = $tb.DefineMethod($s.Name, 'Public, Static', $s.Ret, [Type[]] $s.Args)
    $il = $m.GetILGenerator()
    switch ($s.Body) {
      'true' { $il.Emit($OP::Ldc_I4_1); $il.Emit($OP::Ret) }
      'void' { $il.Emit($OP::Ret) }
      'cursor' {
        $il.Emit($OP::Ldarg_0); $il.Emit($OP::Ldstr, 'MAIN.CLW'); $il.Emit($OP::Stind_Ref)
        $il.Emit($OP::Ldarg_1); $il.Emit($OP::Ldc_I4, 7);         $il.Emit($OP::Stind_I4)
        $il.Emit($OP::Ldarg_2); $il.Emit($OP::Ldc_I4, 1);         $il.Emit($OP::Stind_I4)
        $il.Emit($OP::Ldc_I4_1); $il.Emit($OP::Ret)
      }
      'cursor2' {
        $il.Emit($OP::Ldarg_0); $il.Emit($OP::Ldstr, 'X'); $il.Emit($OP::Stind_Ref)
        $il.Emit($OP::Ldarg_1); $il.Emit($OP::Ldc_I4, 1); $il.Emit($OP::Stind_I4)
        $il.Emit($OP::Ldc_I4_1); $il.Emit($OP::Ret)
      }
    }
  }
  $tb.CreateType() | Out-Null
}

function Status { param([string] $Hook) [MonacoProbe]::$Hook.Status.ToString() }
function Explain { param([string] $Hook) [MonacoProbe]::$Hook.Explain() }

# ── scenarios ─────────────────────────────────────────────────────────────────────────────────────────

# CASE-INSENSITIVE ON PURPOSE, and left that way deliberately (ticket 09207c17). PowerShell's `switch` and
# `-eq` ignore case by default, which is a REAL hazard for a token whose spelling is fixed by something
# outside this file - a JSON wire token, an enum name, a hook signature - because a case-only drift then
# ships a value the other side silently fails to match. That is what the -ceq sweep is for.
# `$Scenario` is a third category: a human-typed CLI argument. Nothing on the wire carries it, nothing
# else defines its spelling, and accepting -Scenario Absent is a convenience rather than a drift. Named
# here so the sweep does not read it as an oversight and "fix" it into a worse tool.
switch ($Scenario) {

  'absent' {
    Invoke-CheckSection "[$Scenario] ClarionAssistant is not loaded at all - the normal state for anyone not using Monaco" {
      foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
        Check "$h reads NotLoaded" ((Status $h) -eq 'NotLoaded') (Status $h)
        Check "$h hands back no method, so callers take the native path" ($null -eq [MonacoProbe]::$h.Method) ''
      }
      Check 'and it says so in words a user can act on' ((Explain '_hookCursor') -match "isn't loaded") (Explain '_hookCursor')
      Check 'no stale-copy warning when there is only one far side' ($null -eq [MonacoProbe]::_monacoDupeNote) ''
    }
  }

  'bound' {
    Invoke-CheckSection "[$Scenario] the real contract still binds against a correctly shaped far side" {
      # Guards the signatures themselves: if someone tightens a hook declaration past what ClarionAssistant
      # actually ships, this is what fails instead of the feature silently vanishing in the IDE.
      New-FarSide $Good
      foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
        Check "$h binds" ((Status $h) -eq 'Bound') (Status $h)
        Check "$h has nothing left to explain" ($null -eq (Explain $h)) ''
      }
      # The out-parameter hook is the one read through an object[]; prove the bound MethodInfo is callable
      # exactly the way ResolveMonacoCursorSpec calls it.
      # Not named $args: that is an automatic variable inside the section's scriptblock.
      $cursorArgs = [object[]] @($null, 0, 0)
      $ok = [MonacoProbe]::_hookCursor.Method.Invoke($null, $cursorArgs)
      Check 'the cursor hook is invokable with the object[] the caller actually passes' `
        ($ok -eq $true -and $cursorArgs[0] -eq 'MAIN.CLW' -and $cursorArgs[1] -eq 7) "$($cursorArgs[0]):$($cursorArgs[1])"
    }
  }

  'older-build' {
    Invoke-CheckSection "[$Scenario] ClarionAssistant IS loaded, but predates two of the three hooks" {
      New-FarSide $Older
      Check 'the hook it does have still binds' ((Status '_hookNavigate') -eq 'Bound') (Status '_hookNavigate')
      foreach ($h in '_hookExecLine', '_hookCursor') {
        Check "$h reads OlderBuild, not NotLoaded" ((Status $h) -eq 'OlderBuild') (Status $h)
        Check "$h tells the user to upgrade rather than to install" ((Explain $h) -match 'upgrade it') (Explain $h)
      }
    }
  }

  'wrong-shape' {
    Invoke-CheckSection "[$Scenario] every hook is present under a DRIFTED signature - the failure nothing else reports" {
      New-FarSide $Skew
      foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
        Check "$h refuses to bind to the wrong shape" ($null -eq [MonacoProbe]::$h.Method) ''
        Check "$h reads WrongShape, distinctly from OlderBuild and NotLoaded" ((Status $h) -eq 'WrongShape') (Status $h)
        Check "$h names the real problem: the two addins have drifted" ((Explain $h) -match 'drifted apart') ''
      }
      # SetExecutionLine here differs ONLY in return type (void, not bool). A bind that checked parameters but
      # not the return type would accept it and then blow up in InvokeExecutionLine's cast.
      Check 'a hook that differs only in RETURN type is still refused' ((Status '_hookExecLine') -eq 'WrongShape') (Status '_hookExecLine')
    }
  }

  'wrong-assembly' {
    Invoke-CheckSection "[$Scenario] the right type name in the wrong assembly is not our far side" {
      New-FarSide $Good -AssemblyName 'NotClarionAssistant'
      foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
        Check "$h does not bind to an assembly that merely defines the type name" ((Status $h) -eq 'NotLoaded') (Status $h)
      }
    }
  }

  'cached-miss' {
    Invoke-CheckSection "[$Scenario] the MISS is cached for the session, and a session start re-arms it" {
      # Finding 2, proved by behaviour rather than by counting scans: if the miss were not cached, step 2 below
      # would re-scan and find the far side that has since loaded.
      Check 'starts NotLoaded with nothing loaded' ((Status '_hookNavigate') -eq 'NotLoaded') (Status '_hookNavigate')
      New-FarSide $Good
      Check 'STILL NotLoaded after a good far side loads - the miss was cached, not re-scanned' `
        ((Status '_hookNavigate') -eq 'NotLoaded') (Status '_hookNavigate')
      [MonacoProbe]::RearmMonacoHooks()
      foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
        Check "$h binds after the session-start re-arm" ((Status $h) -eq 'Bound') (Status $h)
      }
    }
  }

  'stale-copy' {
    Invoke-CheckSection "[$Scenario] two ClarionAssistant builds in one process is reported, not silently resolved" {
      New-FarSide $Good -Version '5.9.0.1235'
      New-FarSide $Good -Version '5.9.0.9999'
      Check 'the hooks still bind (to the first copy)' ((Status '_hookNavigate') -eq 'Bound') (Status '_hookNavigate')
      $note = [MonacoProbe]::_monacoDupeNote
      Check 'a stale-copy note is recorded' ($null -ne $note) ''
      Check 'it counts them' ($note -match '2 loaded copies') $note
      Check 'it names both versions, so the stale one is identifiable' `
        ($note -match '5\.9\.0\.1235' -and $note -match '5\.9\.0\.9999') $note
      [MonacoProbe]::RearmMonacoHooks()
      Check 'the note is cleared by the re-arm so it cannot be reported twice for one scan' `
        ($null -eq [MonacoProbe]::_monacoDupeNote) ''
    }
  }

  'off-thread' {
    Invoke-CheckSection "[$Scenario] a reflected call from a non-UI thread is marshalled, not raced and not dropped" {
      # Finding 4. RunToCursor is PUBLIC and reached by reflection from ClarionAssistant, and CmdRunToCursor
      # mutates the transient-breakpoint list with no lock of its own, so an off-thread caller is a live data
      # race. The REAL Invoke helper is lifted out of DebugSessionController.cs and driven against a stub pad
      # that is a genuine WinForms Control running a genuine message loop on its own thread.
      #
      # Built as a small console app rather than through Add-Type: deriving from Control drags in WinForms'
      # internal COM interop types, and no workable reference set for that exists in-process here - the
      # runtime assemblies break on types forwarded into System.Private.CoreLib, and the reference packs
      # collide with the host's own framework version. A csproj is how WinForms code is meant to be compiled,
      # and it keeps the probe out of this process entirely.
      $proj = Join-Path ([System.IO.Path]::GetTempPath()) ("camarshal-" + [Guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Path $proj | Out-Null

      @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0-windows</TargetFramework>
    <UseWindowsForms>true</UseWindowsForms>
    <AssemblyName>marshalprobe</AssemblyName>
    <EnableDefaultCompileItems>true</EnableDefaultCompileItems>
  </PropertyGroup>
</Project>
'@ | Set-Content (Join-Path $proj 'marshalprobe.csproj')

      $program = @"
using System;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;

$((Get-Method 'public enum DebugControllerState' $ctrl))

$((Get-Method 'public interface IDebugSessionTarget' $ctrl))

/// A pad that is a real Control, so the cast and the InvokeRequired test in Invoke mean what they mean
/// in the IDE. It records WHICH THREAD each command actually ran on - the whole point of the exercise.
public class PadStub : Control, IDebugSessionTarget {
    public int RanOnThread;
    public int Calls;
    public bool IsReady { get { return true; } }
    public bool IsSessionIdle { get { return true; } }
    public void CmdStart() { } public void CmdContinue() { } public void CmdPause() { }
    public void CmdStepOver() { } public void CmdStepInto() { } public void CmdStepOut() { }
    public void CmdStop() { }
    public void CmdRunToCursor(string spec) {
        RanOnThread = Thread.CurrentThread.ManagedThreadId;
        Calls++;
    }
    public bool BoeOk; public int BoeCalls; public int BoeRanOnThread;
    public bool CmdBreakOnProcEntryAt(string filePath, int line, out string message) {
        BoeRanOnThread = Thread.CurrentThread.ManagedThreadId;
        BoeCalls++;
        message = "pad answered " + (BoeOk ? "set" : "missed") + " for " + filePath + ":" + line;
        return BoeOk;
    }
}

public static class Program {
    // The controller's own state, lifted verbatim.
    private static readonly object _gate = new object();
    private static IDebugSessionTarget _target;
    private static DebugControllerState _state = DebugControllerState.Paused;

$((Get-Method 'private static void Invoke(Action<IDebugSessionTarget> action, bool requireReady = true, Func<DebugControllerState, bool> allowed = null)' $ctrl))

$((Get-Method 'private static bool SafeIsReady(IDebugSessionTarget t)' $ctrl))

$((Get-Method 'private static bool IsPaused(DebugControllerState s)' $ctrl))

    // BreakOnProcEntry marshals for itself, synchronously (e61e4f92): lifted verbatim with what it calls.
$((Get-Method 'public static bool BreakOnProcEntry(string filePath, int line, out string message)' $ctrl))
    $((Get-CSharpStatement 'internal const string NoPad' $ctrl))
    $((Get-CSharpStatement 'internal const int MaxMessage' $ctrl))
$((Get-Method 'private static bool BreakOnProcEntryHere(IDebugSessionTarget readBy, string filePath, int line, out string message)' $ctrl))
$((Get-Method 'private static string OneLine(string text, bool ok)' $ctrl))

    private static int _failures;
    private static void Check(string label, bool ok, string detail) {
        Console.WriteLine((ok ? "  PASS  " : "  FAIL  ") + label + (detail.Length > 0 ? "  ->  " + detail : ""));
        if (!ok) _failures++;
    }

    private static PadStub _pad;
    private static int _uiThreadId;
    private static ApplicationContext _ctx;
    private static readonly ManualResetEvent _up = new ManualResetEvent(false);

    private static void StartUi() {
        var th = new Thread(delegate() {
            _uiThreadId = Thread.CurrentThread.ManagedThreadId;
            _pad = new PadStub();
            IntPtr h = _pad.Handle;          // force the HWND, so InvokeRequired means something
            _ctx = new ApplicationContext();
            _up.Set();
            Application.Run(_ctx);
        });
        th.SetApartmentState(ApartmentState.STA);
        th.IsBackground = true;
        th.Start();
        if (!_up.WaitOne(15000)) throw new Exception("the pad's UI thread never came up");
        _target = _pad;
    }

    /// Drain the UI thread's queue, so a BeginInvoke has actually run before anything is asserted.
    private static void Drain() {
        var done = new ManualResetEvent(false);
        _pad.BeginInvoke((Action) delegate { done.Set(); });
        if (!done.WaitOne(15000)) throw new Exception("the pad's message queue never drained");
    }

    [STAThread]
    public static int Main() {
        StartUi();
        int caller = Thread.CurrentThread.ManagedThreadId;
        Check("the test really is off the pad's thread (or everything below is vacuous)",
              caller != _uiThreadId, "test=" + caller + " pad=" + _uiThreadId);

        Action<IDebugSessionTarget> runToCursor = delegate(IDebugSessionTarget t) { t.CmdRunToCursor(null); };

        // 1. the off-thread call - the reflected ClarionAssistant context-menu path
        Invoke(runToCursor, true, IsPaused);
        Drain();
        Check("the command was NOT dropped", _pad.Calls == 1, _pad.Calls + " call(s)");
        Check("it ran on the pad's thread, not the caller's", _pad.RanOnThread == _uiThreadId,
              "ran on " + _pad.RanOnThread + ", pad is " + _uiThreadId);
        Check("and not on the calling thread", _pad.RanOnThread != caller, "");

        // 2. the state guard must survive the marshal. Re-entering Invoke on the pad's thread re-runs it
        //    THERE, so a state change while the post was in flight is still honoured.
        _state = DebugControllerState.Running;
        Invoke(runToCursor, true, IsPaused);
        Drain();
        Check("a command not allowed in the current state is still a no-op when marshalled",
              _pad.Calls == 1, _pad.Calls + " call(s)");

        // 3. on-thread callers (the IDE toolbar) must keep running synchronously. The marshal is for the
        //    other case; making every toolbar click asynchronous would be a behaviour change of its own.
        _state = DebugControllerState.Paused;
        _pad.Invoke((Action) delegate { Invoke(runToCursor, true, IsPaused); });
        Check("an on-thread caller still runs synchronously, with no extra hop",
              _pad.Calls == 2, _pad.Calls + " call(s)");

        // 3b. BreakOnProcEntry has an ANSWER, so from this thread it must BLOCK on the pad's thread and hand
        //     back what the pad said - a post would return before the pad ran. Nothing is drained first: the
        //     result has to be there when the call returns.
        string boeMsg;
        _pad.BoeOk = false;
        bool boeOk = BreakOnProcEntry(@"C:\src\clbrws011.clw", 50, out boeMsg);
        Check("an off-thread BreakOnProcEntry ran on the pad's thread before it returned",
              _pad.BoeCalls == 1 && _pad.BoeRanOnThread == _uiThreadId, _pad.BoeCalls + " call(s), ran on " + _pad.BoeRanOnThread);
        Check("and returned the pad's own miss, with its message",
              !boeOk && boeMsg == @"pad answered missed for C:\src\clbrws011.clw:50", boeOk + " / " + boeMsg);
        _pad.BoeOk = true;
        boeOk = BreakOnProcEntry(@"C:\src\clbrws011.clw", 50, out boeMsg);
        Check("and the pad's own hit", boeOk && _pad.BoeCalls == 2 && boeMsg.StartsWith("pad answered set"), boeOk + " / " + boeMsg);

        // 4. a target that is not a Control at all. Since fc8d63f5 the interface requires ISynchronizeInvoke,
        //    and the claim is no longer "forwarded on the caller's thread" but "posted through its OWN marshal".
        _target = new PlainTarget();
        Invoke(delegate(IDebugSessionTarget t) { t.CmdRunToCursor(null); }, true, IsPaused);
        Check("a non-Control target is marshalled through its own BeginInvoke, not run on the caller's thread",
              PlainTarget.BeginInvokeCalls == 1 && PlainTarget.Calls == 1 && PlainTarget.RanPosted,
              PlainTarget.BeginInvokeCalls + " post(s), " + PlainTarget.Calls + " call(s), posted=" + PlainTarget.RanPosted);

        if (_ctx != null) _pad.BeginInvoke((Action) delegate { _ctx.ExitThread(); });
        return _failures == 0 ? 0 : 1;
    }

    /// Not every IDebugSessionTarget has to be a Control, but every one now carries a marshal (fc8d63f5).
    /// This one reports "wrong thread" until its own BeginInvoke is running the posted delegate, and records
    /// whether a command ran inside that post.
    private class PlainTarget : IDebugSessionTarget {
        public static int Calls;
        public static int BeginInvokeCalls;
        public static bool RanPosted;
        [ThreadStatic] private static bool _inPost;
        public bool IsReady { get { return true; } }
        public bool IsSessionIdle { get { return true; } }
        public bool InvokeRequired { get { return !_inPost; } }
        public IAsyncResult BeginInvoke(Delegate method, object[] args) {
            BeginInvokeCalls++; _inPost = true;
            try { method.DynamicInvoke(args); } finally { _inPost = false; }
            return null;
        }
        public object EndInvoke(IAsyncResult result) { return null; }
        public object Invoke(Delegate method, object[] args) { return method.DynamicInvoke(args); }
        public void CmdStart() { } public void CmdContinue() { } public void CmdPause() { }
        public void CmdStepOver() { } public void CmdStepInto() { } public void CmdStepOut() { }
        public void CmdStop() { }
        public void CmdRunToCursor(string spec) { Calls++; RanPosted = _inPost; }
        public bool CmdBreakOnProcEntryAt(string filePath, int line, out string message) { message = ""; return false; }
    }
}
"@
      Set-Content (Join-Path $proj 'Program.cs') -Value $program

      $build = & dotnet build (Join-Path $proj 'marshalprobe.csproj') -v q --nologo 2>&1
      $exe = Join-Path $proj 'bin\Debug\net9.0-windows\marshalprobe.exe'
      # A Check and a return, not `exit 1`: an exit inside a section is flow control, which
      # Invoke-CheckSection would report as a section that terminated the script - true, but not the reason.
      $built = ($LASTEXITCODE -eq 0 -and (Test-Path $exe))
      Check 'the WinForms marshal probe builds' $built $(if ($built) { '' } else { ($build | ForEach-Object { "$_" }) -join ' | ' })
      if (-not $built) { return }

      # The probe counts its own checks in C#, so neither its exit code nor its PASS lines alone say it ran
      # them all: an exit 0 from a probe that asserted nothing is the vacuous pass this file is guarded
      # against. Both are asserted, and the count is the probe's ten Check calls in Main.
      $probeOut = @(& $exe 2>&1 | ForEach-Object { "$_" })
      $probeExit = $LASTEXITCODE
      $probeOut | ForEach-Object { Write-Host $_ }
      $probeRan = @($probeOut | Where-Object { $_ -cmatch '^  (PASS|FAIL)  ' }).Count
      Check 'the probe exited 0 and ran all 10 of its checks' ($probeExit -eq 0 -and $probeRan -eq 10) `
        "exit $probeExit, $probeRan check(s) reported"
      try { Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue } catch { }
    }
  }

  default { Write-Host "  FAIL  unknown scenario '$Scenario'"; exit 1 }
}

Done
