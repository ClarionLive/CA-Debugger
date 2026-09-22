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

$AllScenarios = @('absent', 'bound', 'older-build', 'wrong-shape', 'wrong-assembly', 'cached-miss', 'stale-copy', 'off-thread', 'source')

if (-not $Scenario) {
  $failed = 0
  foreach ($s in $AllScenarios) {
    & (Get-Process -Id $PID).Path -NoProfile -File $PSCommandPath -Scenario $s -WebViewPath $WebViewPath -ControllerPath $ControllerPath
    if ($LASTEXITCODE -ne 0) { $failed++ }
    Write-Host ''
  }
  if ($failed) { Write-Host "$failed SCENARIO(S) FAILED"; exit 1 }
  Write-Host 'ALL CHECKS PASSED'
  exit 0
}

# ─────────────────────────────────────────────────────────────────────────────── child: one scenario

$web  = Get-Content -Raw -LiteralPath $WebViewPath
$ctrl = Get-Content -Raw -LiteralPath $ControllerPath

# Get-Method (this file used to call it Get-Block) and Get-Statement come from lib-extract.ps1, dot-sourced
# above. This names the text a bare call reads, which each harness used to bury in its own `if (-not $From)`.
Set-ExtractSource $web



function Done {
  Write-Host ''
  if ($script:failures) { Write-Host "  $($script:failures) FAILURE(S) in scenario '$Scenario'"; exit 1 }
  exit 0
}

# ── the source-level checks need no fake assemblies ───────────────────────────────────────────────────

if ($Scenario -eq 'source') {
  Write-Host "[$Scenario] the shape of the code itself"

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
    Write-Host "[$Scenario] ClarionAssistant is not loaded at all - the normal state for anyone not using Monaco"
    foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
      Check "$h reads NotLoaded" ((Status $h) -eq 'NotLoaded') (Status $h)
      Check "$h hands back no method, so callers take the native path" ($null -eq [MonacoProbe]::$h.Method) ''
    }
    Check 'and it says so in words a user can act on' ((Explain '_hookCursor') -match "isn't loaded") (Explain '_hookCursor')
    Check 'no stale-copy warning when there is only one far side' ($null -eq [MonacoProbe]::_monacoDupeNote) ''
  }

  'bound' {
    Write-Host "[$Scenario] the real contract still binds against a correctly shaped far side"
    # Guards the signatures themselves: if someone tightens a hook declaration past what ClarionAssistant
    # actually ships, this is what fails instead of the feature silently vanishing in the IDE.
    New-FarSide $Good
    foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
      Check "$h binds" ((Status $h) -eq 'Bound') (Status $h)
      Check "$h has nothing left to explain" ($null -eq (Explain $h)) ''
    }
    # The out-parameter hook is the one read through an object[]; prove the bound MethodInfo is callable
    # exactly the way ResolveMonacoCursorSpec calls it.
    $args = [object[]] @($null, 0, 0)
    $ok = [MonacoProbe]::_hookCursor.Method.Invoke($null, $args)
    Check 'the cursor hook is invokable with the object[] the caller actually passes' `
      ($ok -eq $true -and $args[0] -eq 'MAIN.CLW' -and $args[1] -eq 7) "$($args[0]):$($args[1])"
  }

  'older-build' {
    Write-Host "[$Scenario] ClarionAssistant IS loaded, but predates two of the three hooks"
    New-FarSide $Older
    Check 'the hook it does have still binds' ((Status '_hookNavigate') -eq 'Bound') (Status '_hookNavigate')
    foreach ($h in '_hookExecLine', '_hookCursor') {
      Check "$h reads OlderBuild, not NotLoaded" ((Status $h) -eq 'OlderBuild') (Status $h)
      Check "$h tells the user to upgrade rather than to install" ((Explain $h) -match 'upgrade it') (Explain $h)
    }
  }

  'wrong-shape' {
    Write-Host "[$Scenario] every hook is present under a DRIFTED signature - the failure nothing else reports"
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

  'wrong-assembly' {
    Write-Host "[$Scenario] the right type name in the wrong assembly is not our far side"
    New-FarSide $Good -AssemblyName 'NotClarionAssistant'
    foreach ($h in '_hookNavigate', '_hookExecLine', '_hookCursor') {
      Check "$h does not bind to an assembly that merely defines the type name" ((Status $h) -eq 'NotLoaded') (Status $h)
    }
  }

  'cached-miss' {
    Write-Host "[$Scenario] the MISS is cached for the session, and a session start re-arms it"
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

  'stale-copy' {
    Write-Host "[$Scenario] two ClarionAssistant builds in one process is reported, not silently resolved"
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

  'off-thread' {
    Write-Host "[$Scenario] a reflected call from a non-UI thread is marshalled, not raced and not dropped"
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
}

public static class Program {
    // The controller's own state, lifted verbatim.
    private static readonly object _gate = new object();
    private static IDebugSessionTarget _target;
    private static DebugControllerState _state = DebugControllerState.Paused;

$((Get-Method 'private static void Invoke(Action<IDebugSessionTarget> action, bool requireReady = true, Func<DebugControllerState, bool> allowed = null)' $ctrl))

$((Get-Method 'private static bool SafeIsReady(IDebugSessionTarget t)' $ctrl))

$((Get-Method 'private static bool IsPaused(DebugControllerState s)' $ctrl))

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

        // 4. a target that is not a Control at all must still be forwarded, not silently skipped.
        _target = new PlainTarget();
        Invoke(delegate(IDebugSessionTarget t) { t.CmdRunToCursor(null); }, true, IsPaused);
        Check("a non-Control target is still forwarded rather than dropped by the thread guard",
              PlainTarget.Calls == 1, PlainTarget.Calls + " call(s)");

        if (_ctx != null) _pad.BeginInvoke((Action) delegate { _ctx.ExitThread(); });
        return _failures == 0 ? 0 : 1;
    }

    /// Not every IDebugSessionTarget has to be a Control. The thread guard must fall through for one that
    /// is not, instead of treating "cannot marshal" as "do not run".
    private class PlainTarget : IDebugSessionTarget {
        public static int Calls;
        public bool IsReady { get { return true; } }
        public bool IsSessionIdle { get { return true; } }
        public void CmdStart() { } public void CmdContinue() { } public void CmdPause() { }
        public void CmdStepOver() { } public void CmdStepInto() { } public void CmdStepOut() { }
        public void CmdStop() { }
        public void CmdRunToCursor(string spec) { Calls++; }
    }
}
"@
    Set-Content (Join-Path $proj 'Program.cs') -Value $program

    $build = & dotnet build (Join-Path $proj 'marshalprobe.csproj') -v q --nologo 2>&1
    $exe = Join-Path $proj 'bin\Debug\net9.0-windows\marshalprobe.exe'
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) {
      Write-Host '  FAIL  could not build the WinForms marshal probe'
      $build | ForEach-Object { Write-Host "        $_" }
      exit 1
    }

    & $exe
    if ($LASTEXITCODE -ne 0) { $script:failures++ }
    try { Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue } catch { }
  }

  default { Write-Host "  FAIL  unknown scenario '$Scenario'"; exit 1 }
}

Done
