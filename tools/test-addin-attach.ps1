# Regression check: the HOST side of "Attach to a running process" (ticket 3f2d747f part C).
#
#   pwsh -NoProfile -File tools\test-addin-attach.ps1
#   pwsh -NoProfile -File tools\test-addin-attach.ps1 -SelfTest     # break each guard once; each must go red
#
# What it guards, against the FROZEN engine contract (part A is built separately):
#   1. the bridge attaches ONLY to a pid the host itself listed in its latest `procs` reply, and one listing
#      authorises one attach (ListedProcesses + CmdAttach);
#   2. the engine's `procs --json` line is read as the engine writes it - its REAL writer is run here - and a
#      --verbose skip entry never becomes an attachable process;
#   3. Stop in attach mode sends `detach` and waits DetachWaitMs, never `quit`; a kill is the last resort and
#      says the app may crash;
#   4. the `detached` event ends the session and names the app; an older engine's `detached` does not end a
#      newer session;
#   5. the pad resets exactly what a session end resets, says "Detached; <name> is still running.", warns when
#      a breakpoint byte was not restored, and keeps an attach failure's reason visible past the console clear.
#
# HOW. The service is not extracted: ClarionDebuggerService.cs is compiled WHOLE, with the reader and the DTOs
# it depends on, and driven through reflection - its real OnLine and its real Stop, against real child
# processes standing in for the engine. The pad cannot be compiled whole (WinForms, WebView2), so its attach
# methods are lifted out of ClarionDebuggerWebView.cs by brace matching and compiled beside the real service
# types, with the pad's collaborators replaced by recorders. Substitutions in code under test, stated: the
# thread-pool work item runs through RunNow (so a test can hold it), and ClarionDebuggerService.ListProcesses
# is replaced by FakeLists.ListProcesses (so no real engine is spawned for the listing).
#
# NOT COVERED: the engine itself (part A, tools/test-attach.ps1), and anything live - no app is attached to.
#
# ASCII only, for Windows PowerShell 5.1.

param(
  # Defaulted in the body: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $ServicePath = '',
  [string] $WebViewPath = '',
  [string] $PageMessagesPath = '',
  [string] $HostGrantsPath = '',
  [string] $ReaderPath = '',
  [string] $RedPath = '',
  [string] $VersionPath = '',
  [string] $EngineJsonPath = '',
  [string] $ProcsCommandPath = '',
  # protocolcheck's pins of the engine's attach wire shapes, which the writer compiled here must match
  [string] $ProtocolCheckPath = '',
  [string] $PagePath = '',
  [switch] $SelfTest,
  # For -SelfTest's child runs ONLY: while the engine's Procs writer cannot emit "started" yet (Kit, item 3d), its
  # one check would fail every run - the unmutated control included - and a mutation could not be told apart from
  # it. This relaxes THAT check alone, in those runs alone; a plain run still fails it until the engine emits it.
  [switch] $PendingStartedOk
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$root = Join-Path $PSScriptRoot '..'
if (-not $ServicePath) { $ServicePath = Join-Path $root 'src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs' }
if (-not $WebViewPath) { $WebViewPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs' }
if (-not $PageMessagesPath) { $PageMessagesPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\PageMessages.cs' }
if (-not $HostGrantsPath) { $HostGrantsPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\HostGrants.cs' }
if (-not $ReaderPath) { $ReaderPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\JsonMessageReader.cs' }
if (-not $RedPath) { $RedPath = Join-Path $root 'src\ClarionDebugger.Addin\Services\RedFileService.cs' }
if (-not $VersionPath) { $VersionPath = Join-Path $root 'src\ClarionDebugger.Addin\Services\ClarionVersionService.cs' }
if (-not $EngineJsonPath) { $EngineJsonPath = Join-Path $root 'src\ClarionDbg.Cli\Json.cs' }
if (-not $ProcsCommandPath) { $ProcsCommandPath = Join-Path $root 'src\ClarionDbg.Cli\ProcsCommand.cs' }
if (-not $ProtocolCheckPath) { $ProtocolCheckPath = Join-Path $root 'src\ClarionDbg.Cli\ProtocolCheck.Attach.cs' }
if (-not $PagePath) { $PagePath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\debugger.html' }

# ================================================================================================ -SelfTest
# Each mutation breaks ONE guard in a copy of the sources, and the matching suite is run against the copy in a
# fresh process (Add-Type cannot redefine a loaded type). A mutation is CAUGHT only when that run exits non-zero
# AND never prints its success line; a find that does not match exactly once is itself a failure, so a
# mutation that silently changed nothing can never count as caught. The two controls run the same suites on
# unmutated copies and must pass, which is what makes a red run mean the mutation and not the harness.
if ($SelfTest) {
  $sources = [ordered]@{
    service = $ServicePath; web = $WebViewPath; msgs = $PageMessagesPath; grants = $HostGrantsPath; reader = $ReaderPath; red = $RedPath
    version = $VersionPath; json = $EngineJsonPath; procs = $ProcsCommandPath; pcheck = $ProtocolCheckPath; page = $PagePath
  }
  $M = @(
    @{ Id = 'M1';  Suite = 'ps';   File = 'msgs';    Why = 'an unlisted pid resolves';
       Find = 'if (!_byPid.TryGetValue(pid, out p)) return null;'; Repl = 'if (!_byPid.TryGetValue(pid, out p)) return new AttachableProcess { Pid = pid, Name = "forged" };' }
    @{ Id = 'M2';  Suite = 'ps';   File = 'msgs';    Why = 'a listing can be replayed into a second attach';
       Find = "_byPid = new Dictionary<uint, AttachableProcess>();`n            return p;"; Repl = 'return p;' }
    @{ Id = 'M3';  Suite = 'ps';   File = 'msgs';    Why = 'an older listing overwrites a newer one';
       Find = "if (generation != _generation) return false;`n            var t = new Dictionary<uint, AttachableProcess>();"; Repl = 'var t = new Dictionary<uint, AttachableProcess>();' }
    @{ Id = 'M4';  Suite = 'ps';   File = 'msgs';    Why = 'pid 0 parses';
       Find = 'if (!PageNumbers.TryUInt(data, out pid) || pid == 0) return null;'; Repl = 'if (!PageNumbers.TryUInt(data, out pid)) return null;' }
    @{ Id = 'M5';  Suite = 'ps';   File = 'service'; Why = 'Stop quits an attached app';
       Find = 'return attached ? "detach" : "quit";'; Repl = 'return "quit";' }
    @{ Id = 'M6';  Suite = 'ps';   File = 'service'; Why = 'Stop waits only the launch-mode 1.5 s for a detach';
       Find = '_proc.WaitForExit(attached ? DetachWaitMs : QuitWaitMs)'; Repl = '_proc.WaitForExit(QuitWaitMs)' }
    @{ Id = 'M7';  Suite = 'ps';   File = 'service'; Why = 'a --verbose skip entry becomes attachable';
       Find = 'if (tswd == null) return;'; Repl = 'if (tswd == null) tswd = "false";' }
    @{ Id = 'M8';  Suite = 'ps';   File = 'service'; Why = 'the detached event is never raised';
       Find = 'Detached?.Invoke(d);'; Repl = 'if (d == null) Detached?.Invoke(d);' }
    @{ Id = 'M9';  Suite = 'ps';   File = 'service'; Why = 'an older engine''s detached ends the new session';
       Find = 'if (ReferenceEquals(source, _proc))' + "`n" + '                    {' + "`n" + '                        var d = ParseDetached'; Repl = 'if (source != null)' + "`n" + '                    {' + "`n" + '                        var d = ParseDetached' }
    @{ Id = 'M10'; Suite = 'ps';   File = 'web';     Why = 'CmdAttach attaches to any pid';
       Find = 'var target = _listedProcs.Take(req.Pid);'; Repl = 'var target = new AttachableProcess { Pid = req.Pid, Name = "forged", Started = "1" };' }
    @{ Id = 'M11'; Suite = 'ps';   File = 'web';     Why = 'CmdAttach is not gated on the pad being idle';
       Find = "if (CurrentState != DebugSessionState.Idle) return;`n            if (DebugSessionController.State != DebugControllerState.Idle) return;`n            var req = AttachRequest.Parse(data);"; Repl = "if (DebugSessionController.State != DebugControllerState.Idle) return;`n            var req = AttachRequest.Parse(data);" }
    @{ Id = 'M12'; Suite = 'ps';   File = 'web';     Why = 'the exit after a detach wipes the Detached line';
       Find = 'if (attach.Detached) return;'; Repl = 'if (attach.Detached && attach == null) return;' }
    @{ Id = 'M13'; Suite = 'ps';   File = 'web';     Why = 'a failed breakpoint restore is not warned about';
       Find = 'if (d != null && !string.IsNullOrEmpty(d.Error))'; Repl = 'if (d == null)' }
    @{ Id = 'M24'; Suite = 'ps';   File = 'service'; Why = 'restored read as a bool again (the seam bug: every clean detach warned or lost its count)';
       Find = 'Restored = GetIntOrNull(json, "restored") ?? -1,'; Repl = 'Restored = GetBool(json, "restored") ? 1 : -1,' }
    @{ Id = 'M25'; Suite = 'ps';   File = 'web';     Why = 'a detach with restored 0 and no error warns of a crash';
       Find = 'if (d != null && !string.IsNullOrEmpty(d.Error))'; Repl = 'if (d != null && (d.Restored == 0 || !string.IsNullOrEmpty(d.Error)))' }
    @{ Id = 'M14'; Suite = 'ps';   File = 'web';     Why = 'an attach failure''s reason is lost in the clear';
       Find = '_attach.LastError = msg;'; Repl = '_attach.Name = _attach.Name;' }
    @{ Id = 'M15'; Suite = 'ps';   File = 'web';     Why = 'process paths are written into the procs JSON unescaped';
       Find = '.Append(",\"path\":").Append(Str(p.Path)).Append(''}'');'; Repl = '.Append(",\"path\":\"").Append(p.Path).Append("\"}");' }
    @{ Id = 'M22'; Suite = 'ps';   File = 'service'; Why = 'attached state outlives a failed attach''s engine';
       Find = "_attachTarget = null;`n            SetState(DebugSessionState.Idle);`n            Exited?.Invoke(code);"; Repl = "SetState(DebugSessionState.Idle);`n            Exited?.Invoke(code);" }
    @{ Id = 'M23'; Suite = 'ps';   File = 'web';     Why = 'the Detached line loses the app name when the exit came first';
       Find = ': !string.IsNullOrEmpty(_lastAttachName) ? _lastAttachName : "the app";'; Repl = ': "the app";' }
    @{ Id = 'M26'; Suite = 'ps';   File = 'web';     Why = 'a closing pad stops observing BEFORE Stop (detach errors and kills lost on close)';
       Find = "using (new TeardownObserver(svc, attachedName, warn))`n            {`n                return svc.Stop();`n            }"; Repl = "new TeardownObserver(svc, attachedName, warn).Dispose();`n            return svc.Stop();" }
    @{ Id = 'M27'; Suite = 'ps';   File = 'service'; Why = 'the attach goes out without --expect-start (a pid taken as an identity)';
       Find = "`n                .Append("" --expect-start "").Append(target.Started);"; Repl = ';' }
    @{ Id = 'M28'; Suite = 'ps';   File = 'web';     Why = 'a listed entry with no start time is attached blind';
       Find = "if (!AttachableProcess.IsStartTime(target.Started))`n            {`n                Console(""err"", ""attach: the process list gave no start time"; Repl = "if (target == null)`n            {`n                Console(""err"", ""attach: the process list gave no start time" }
    @{ Id = 'M29'; Suite = 'ps';   File = 'service'; Why = 'a killed attached engine raises no DetachAbandoned';
       Find = 'if (attached) DetachAbandoned?.Invoke(target);'; Repl = '' }
    # NOT A MUTATION HERE, measured 2026-09-23: removing Stop's untimed drain (`engine.WaitForExit()` after an
    # attached exit) is NOT caught by this harness, because it runs on pwsh's .NET, whose TIMED WaitForExit already
    # waits for redirected output. The add-in runs on .NET Framework 4.8, whose timed overload does not, so the drain
    # stays; proving it needs a net48 host, which this suite is not.
    @{ Id = 'M31'; Suite = 'ps';   File = 'web';     Why = 'a THROWING UI post is swallowed again, so no dialog is shown';
       Find = "catch (Exception)`n                {`n                    // The UI context is going"; Repl = "catch (Exception)`n                {`n                    return sent;`n                    // The UI context is going" }
    @{ Id = 'M32'; Suite = 'ps';   File = 'web';     Why = 'the log stops at the first location (no fallback log)';
       Find = 'catch { }   // try the next location'; Repl = 'catch { break; }   // try the next location' }
    @{ Id = 'M16'; Suite = 'node'; File = 'page';    Why = 'a process name is written as markup';
       Find = "name.textContent=p.name==null?'':String(p.name);"; Repl = "name.innerHTML=p.name==null?'':String(p.name);" }
    @{ Id = 'M17'; Suite = 'node'; File = 'page';    Why = 'a row with a non-integer pid is shown';
       Find = 'if(!p || !Number.isInteger(p.pid) || p.pid<=0) return;'; Repl = 'if(!p) return;' }
    @{ Id = 'M18'; Suite = 'node'; File = 'page';    Why = 'a pick sends attach while a session runs';
       Find = "if(pid==null || runState!=='idle') return;"; Repl = 'if(pid==null) return;' }
    @{ Id = 'M19'; Suite = 'node'; File = 'page';    Why = 'the picker opens while a session runs';
       Find = "if(runState!=='idle'){ toast('Stop the current session before attaching'); return; }"; Repl = '' }
    @{ Id = 'M20'; Suite = 'node'; File = 'page';    Why = 'Stop''s tip still says terminate while attached';
       Find = "c.id==='stop' && attachMode ? STOP_TIP_ATTACHED"; Repl = "c.id==='stop' && attachMode && false ? STOP_TIP_ATTACHED" }
    @{ Id = 'M21'; Suite = 'node'; File = 'page';    Why = 'going idle does not end attach mode';
       Find = "if(runState==='idle' && attachMode) setAttachMode(false);"; Repl = '' }
  )
  $base = Join-Path ([IO.Path]::GetTempPath()) ('attach-selftest-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $base | Out-Null
  $nodeSuite = Join-Path $PSScriptRoot 'test-pad-attach.js'
  $self = $PSCommandPath
  try {
    $runs = @(@{ Id = 'CONTROL-ps'; Suite = 'ps' }, @{ Id = 'CONTROL-node'; Suite = 'node' }) + $M
    Invoke-CheckSection 'mutation self-test: every find matches exactly once' {
      foreach ($m in $M) {
        $dir = Join-Path $base $m.Id
        New-Item -ItemType Directory -Path $dir | Out-Null
        foreach ($k in $sources.Keys) { Copy-Item -LiteralPath $sources[$k] -Destination (Join-Path $dir ([IO.Path]::GetFileName($sources[$k]))) }
        $target = Join-Path $dir ([IO.Path]::GetFileName($sources[$m.File]))
        $text = [IO.File]::ReadAllText($target)
        # Match line endings of either kind: the .cs files are LF, the page may not be.
        $pattern = [regex]::Escape($m.Find) -replace '\\n', '\r?\n'
        $n = [regex]::Matches($text, $pattern).Count
        Check "$($m.Id) find matches once ($($m.Why))" ($n -eq 1) "$n match(es)"
        if ($n -eq 1) { [IO.File]::WriteAllText($target, [regex]::Replace($text, $pattern, $m.Repl.Replace('$', '$$'))) }
      }
      foreach ($c in 'CONTROL-ps', 'CONTROL-node') {
        $dir = Join-Path $base $c
        New-Item -ItemType Directory -Path $dir | Out-Null
        foreach ($k in $sources.Keys) { Copy-Item -LiteralPath $sources[$k] -Destination (Join-Path $dir ([IO.Path]::GetFileName($sources[$k]))) }
      }
    }
    Invoke-CheckSection 'mutation self-test: each mutation CAUGHT, each control clean' {
      $results = $runs | ForEach-Object -ThrottleLimit 6 -Parallel {
        $r = $_; $dir = Join-Path $using:base $r.Id
        $f = { param($name) Join-Path $dir ([IO.Path]::GetFileName(($using:sources)[$name])) }
        if ($r.Suite -eq 'ps') {
          $out = & pwsh -NoProfile -File $using:self -ServicePath (& $f 'service') -WebViewPath (& $f 'web') `
            -PageMessagesPath (& $f 'msgs') -HostGrantsPath (& $f 'grants') -ReaderPath (& $f 'reader') -RedPath (& $f 'red') -VersionPath (& $f 'version') `
            -EngineJsonPath (& $f 'json') -ProcsCommandPath (& $f 'procs') -ProtocolCheckPath (& $f 'pcheck') -PagePath (& $f 'page') -PendingStartedOk 2>&1
          $ok = [bool](@($out) -match '^ALL \d+ CHECKS PASSED')
        } else {
          $out = & node $using:nodeSuite (& $f 'page') 2>&1
          $ok = [bool](@($out) -match '^ALL \d+ CHECKS PASSED')
        }
        [pscustomobject]@{ Id = $r.Id; Exit = $LASTEXITCODE; Passed = $ok; Fails = (@($out) -match '^\s*FAIL' | Select-Object -First 2) -join ' / ' }
      }
      foreach ($r in ($results | Sort-Object { [int](($_.Id -replace '\D', '0')) }, Id)) {
        if ($r.Id -like 'CONTROL-*') {
          Check "$($r.Id): the unmutated copy passes" (($r.Exit -eq 0) -and $r.Passed) "exit=$($r.Exit) $($r.Fails)"
        } else {
          $why = ($M | Where-Object { $_.Id -eq $r.Id }).Why
          Check "$($r.Id) CAUGHT: $why" (($r.Exit -ne 0) -and (-not $r.Passed)) "exit=$($r.Exit) $($r.Fails)"
        }
      }
    }
  } finally {
    Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
  }
  # 31 finds + 31 mutations + 2 controls
  $EXPECTED_CHECKS = 64
  Assert-CheckTotal $EXPECTED_CHECKS
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ================================================================================================ compile
$web = Get-Content -Raw -LiteralPath $WebViewPath
$svcSrc = Get-Content -Raw -LiteralPath $ServicePath
Set-ExtractSource $web

function Get-ArrowHandler { param([string] $Sig) (Get-Method $Sig $web) + ');' }
function Public { param([string] $s) $s -replace '^(private|internal) ', 'public ' }

# Hoisted out of the here-string: a quoted '(' inside $() there breaks the parse.
$xStr = Get-Method 'private static string Str(string s)'
$xList = (Get-Method 'private void CmdListProcs()') -replace '^private', 'public' `
  -replace 'System\.Threading\.ThreadPool\.QueueUserWorkItem\(', 'RunNow(' -replace 'ClarionDebuggerService\.ListProcesses\(', 'FakeLists.ListProcesses('
$xProcsJson = Public (Get-Method 'private static string ProcsJson(List<AttachableProcess> procs, string error)')
$xAttach = Get-Method 'public void CmdAttach(string data)'
$xAttachSession = ((Get-Method 'private void AttachSession(AttachableProcess target)'), (Get-Method 'private void LoadStaticSymbols(string exe)'), (Get-Method 'private string SessionCounts(List<string> solutionDlls)') -join "`n") -replace 'System\.Threading\.ThreadPool\.QueueUserWorkItem\(', 'RunNow('
$xCtx = Get-Method 'private sealed class AttachContext'
$xExited = Public (Get-ArrowHandler 'private void OnSvcExited(int code)')
$xDetached = Public (Get-ArrowHandler 'private void OnSvcDetached(DebugDetach d)')
$xEngErr = Public (Get-ArrowHandler 'private void OnSvcEngineError(string msg)')
# The teardown path a closing pad takes (3f2d747f run 2): the static helper, its observer, and the warning text.
$xTeardown = Public (Get-Method 'internal static bool TeardownLive(ClarionDebuggerService svc, string attachedName, Action<string> warn)')
$xObserver = (Get-Method 'internal sealed class TeardownObserver : IDisposable') -replace '^internal', 'public'
$xWarnText = Public (Get-Method 'internal static string DetachWarningText(string name, uint? pid, string error)')
# The durable warning's delivery logic, lifted out whole (its callers' MessageBox and thread are injected).
$xChannels = (Get-Method 'internal enum Channels') -replace '^internal', 'public'
$xDeliver = Public (Get-Method 'internal static Channels Deliver(string text, IList<string> logPaths, System.Threading.SynchronizationContext ui,')

$padProbe = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using ClarionDebugger.Services;

namespace ClarionDebugger.Terminal
{
  // Stand-ins for the pad's collaborators. None of them decides anything the checks below are about.
  public enum DebugControllerState { Idle, Launching, Running, Paused }
  public static class DebugSessionController { public static DebugControllerState State = DebugControllerState.Idle; }
  public static class ProjectTargetService {
    public static List<string> Dlls = new List<string>();
    public static List<string> ResolveSolutionDlls() { return new List<string>(Dlls); }
  }
  public static class FakeLists {
    public static List<AttachableProcess> Next; public static string NextError; public static int Calls; public static int LastExclude;
    public static List<AttachableProcess> ListProcesses(int exclude, out string error) {
      Calls++; LastExclude = exclude; error = NextError;
      return Next == null ? null : new List<AttachableProcess>(Next);
    }
  }
  public sealed class FakeSvc {
    public DebugSessionState State = DebugSessionState.Idle;
    public bool IsEngineStillClosing;
    public List<AttachableProcess> Attached = new List<AttachableProcess>();
    public int LastBpCount = -1;
    public void AttachSession(AttachableProcess t, IEnumerable<DebugBreakpoint> bps, IEnumerable<string> dlls) {
      Attached.Add(t); LastBpCount = new List<DebugBreakpoint>(bps).Count;
    }
  }

  public sealed class AttachPad
  {
    public FakeSvc _svc = new FakeSvc();
    public List<DebugBreakpoint> _pending = new List<DebugBreakpoint>();
    private readonly ListedProcesses _listedProcs = new ListedProcesses();
    private int _procsGen;
    private AttachContext _attach;
    private string _lastAttachName;
    private readonly EditGrants _editGrants = new EditGrants();
    public HashSet<string> _transientBps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public string _pendingRtcKey;
    // Posts and console lines in ONE ordered list, because the order is the point: `clear` empties the
    // page's console, so a line posted before it is gone.
    public List<string> Posts = new List<string>();
    public int ClearedLine, Rearms, Merges;
    public List<string> Pushed = new List<string>();

    private DebugSessionState CurrentState { get { return _svc.State; } }
    private void Console(string level, string text) { Posts.Add("console|" + level + "|" + text); }
    private void Post(string json) { Posts.Add(json); }
    private void UI(Action a) { a(); }
    public bool HoldWork; public List<Action<object>> Held = new List<Action<object>>();
    private void RunNow(Action<object> w) { if (HoldWork) Held.Add(w); else w(null); }
    public void Release(int i) { var w = Held[i]; w(null); }
    private void ClearExecutionLine() { ClearedLine++; }
    private void RearmAndReportMonacoHooks() { Rearms++; }
    private void MergeGutterIntoPending() { Merges++; }
    private void PushProcedures(string exe) { Pushed.Add(exe); }

    public bool HasAttach { get { return _attach != null; } }
    public int ListedCount { get { return _listedProcs.Count; } }
    public int GrantCount { get { return _editGrants.Count; } }
    public void GrantOne() { _editGrants.Grant("0x401000", "0x11", 4, 0, null); }

    $xStr
    $xList
    $xProcsJson
    $xAttach
    $xAttachSession
    $xCtx
    $xExited
    $xDetached
    $xEngErr
    $xTeardown
    $xWarnText
  }

  $($xObserver -replace 'ClarionDebuggerWebView\.', 'AttachPad.')

  public static class DurableProbe
  {
    [Flags]
    $xChannels
    $xDeliver
    // Recorders for the dialog and the STA thread, both run inline.
    public static readonly List<string> Boxes = new List<string>();
    public static int Threads;
    public static void Box(string t) { Boxes.Add(t); }
    public static void RunInline(Action a) { Threads++; a(); }
    public static int Run(string text, IList<string> logs, System.Threading.SynchronizationContext ui) {
      Boxes.Clear(); Threads = 0;
      return (int)Deliver(text, logs, ui, RunInline, Box);
    }
  }
  // A UI context that runs a post inline, and one whose Post THROWS (a destroyed handle at IDE shutdown).
  public sealed class InlineContext : System.Threading.SynchronizationContext {
    public int Posts;
    public override void Post(System.Threading.SendOrPostCallback d, object state) { Posts++; d(state); }
  }
  public sealed class DeadContext : System.Threading.SynchronizationContext {
    public override void Post(System.Threading.SendOrPostCallback d, object state) { throw new InvalidOperationException("Invoke or BeginInvoke cannot be called on a control until the window handle has been created."); }
  }

  // Wires a real process's stdout into the service's real (private) OnLine, as Launch does.
  public static class ProbeWire {
    public static void Wire(ClarionDebuggerService svc, System.Diagnostics.Process p) {
      var onLine = typeof(ClarionDebuggerService).GetMethod("OnLine", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
      p.OutputDataReceived += (s, e) => { if (e.Data != null) onLine.Invoke(svc, new object[] { p, e.Data }); };
      p.BeginOutputReadLine();
    }
    // The durable channel, recorded. A C# collector, not a PowerShell scriptblock: the Detached warning is raised
    // on the output-reader thread, which has no runspace.
    public static readonly List<string> Warns = new List<string>();
    public static Action<string> Collector() { return t => { lock (Warns) Warns.Add(t); }; }
    // How many handlers are still subscribed to an event of the service (its compiler-generated backing field).
    public static int Subscribers(ClarionDebuggerService svc, string evt) {
      var f = typeof(ClarionDebuggerService).GetField(evt, System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
      var d = f == null ? null : f.GetValue(svc) as Delegate;
      return d == null ? 0 : d.GetInvocationList().Length;
    }
  }
}
"@

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('attach-probe-' + [guid]::NewGuid().ToString('N') + '.cs')
[IO.File]::WriteAllText($tmp, $padProbe)
try {
  $paths = @($ServicePath, $RedPath, $VersionPath, $ReaderPath, $PageMessagesPath, $HostGrantsPath) | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
  Add-Type -Path ($paths + $tmp) -IgnoreWarnings -WarningAction SilentlyContinue -ReferencedAssemblies @(
    'System.Xml', 'System.Xml.ReaderWriter', 'System.Diagnostics.Process', 'System.Diagnostics.FileVersionInfo',
    'System.ComponentModel.Primitives', 'System.Text.RegularExpressions', 'System.Collections', 'System.Linq',
    'System.Threading', 'System.Threading.Thread', 'System.Runtime.InteropServices') | Out-Null
} finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }

# The engine's REAL writers - procs, loaded (with attached), detached, and the attach error - so every payload
# that stands for what the engine sends TODAY is one the engine's own code produced (3f2d747f seam: a hand-written
# "restored":true passed here while the engine sends a COUNT, and every clean detach warned). The few hand-written
# lines below are deliberately OFF-contract - an older engine's shape, a malformed or hostile line - which no
# current writer can produce, and each says so where it is used.
$engineJson = Get-Content -Raw -LiteralPath $EngineJsonPath
$procsCmd = Get-Content -Raw -LiteralPath $ProcsCommandPath
$xLoaded = Get-Method 'public static string Loaded(uint pid, uint loadBase)' $engineJson
$xLoadedAttached = Get-Method 'public static string Loaded(uint pid, uint loadBase, bool attached)' $engineJson
$xDetachedW = Get-Method 'public static string Detached(uint pid, int drained, int restored, string error)' $engineJson
$xAttachError = Get-Method 'public static string AttachError(string message, int code)' $engineJson
$engineProbe = @"
using System;
using System.Collections.Generic;
using System.Text;
namespace AttachEngineSide {
  $((Get-Method 'internal sealed class ProcEntry' $procsCmd) -replace '^internal', 'public')
  $((Get-Method 'internal sealed class ProcSkip' $procsCmd) -replace '^internal', 'public')
  public static class EngineJson {
    $(Get-Method 'public static string Str(string s)' $engineJson)
    $(Get-Method 'public static string Procs(List<ProcEntry> procs, List<ProcSkip> skips, bool verbose)' $engineJson)
    $xLoaded
    $xLoadedAttached
    $xDetachedW
    $xAttachError
  }
}
"@
Add-Type -TypeDefinition $engineProbe -Language CSharp | Out-Null

$SvcT = [ClarionDebugger.Services.ClarionDebuggerService]
$SF = [Reflection.BindingFlags]'NonPublic,Static'
$IF = [Reflection.BindingFlags]'NonPublic,Instance'
# Reflection wants the objects themselves; PowerShell hands over PSObject wrappers.
function Unwrap { param($v) if ($v -is [psobject]) { $v.psobject.BaseObject } else { $v } }
function Invoke-Static { param([string] $Name, [object[]] $A)
  $raw = New-Object object[] $A.Count
  for ($i = 0; $i -lt $A.Count; $i++) { $raw[$i] = Unwrap $A[$i] }
  return ,($SvcT.GetMethod($Name, $SF).Invoke($null, $raw)) }
# A listed process as the host holds it. $Started is the creation FILETIME the listing reported; pass '' for an
# entry from an engine that did not report one.
function Proc { param([uint32] $Id, [string] $Name, [string] $Path, [string] $Started = '133987654321098765')
  $p = New-Object ClarionDebugger.Terminal.AttachableProcess; $p.Pid = $Id; $p.Name = $Name; $p.Path = $Path; $p.Tswd = $true
  $p.Started = if ($Started) { $Started } else { $null }; $p }

# The engine's procs line from ITS OWN writer. The start time is additive (Kit, item 3d): when the compiled
# ProcEntry has a `Started` field the writer emits it itself. Until then the writer cannot, and ONE check in section
# 2 fails saying so; the rest of the suite still runs, on the writer's output with "started" spliced in after each
# entry's "tswd" (the only change), so the host's handling is exercised either way.
$StartedField = [AttachEngineSide.ProcEntry].GetField('Started')
$script:WriterHasStarted = $null -ne $StartedField
function New-EngineEntry { param([uint32] $Id, [string] $Name, [string] $Path, [string] $Started)
  $e = New-Object AttachEngineSide.ProcEntry; $e.Pid = $Id; $e.Name = $Name; $e.Path = $Path; $e.Tswd = $true
  if ($StartedField -and $Started) { $StartedField.SetValue($e, [Convert]::ChangeType($Started, $StartedField.FieldType, [Globalization.CultureInfo]::InvariantCulture)) }
  $e }
function Engine-ProcsLine { param($Entries, $Skips, [bool] $Verbose, [string[]] $Started)
  $line = [AttachEngineSide.EngineJson]::Procs($Entries, $Skips, $Verbose)
  if (-not $script:WriterHasStarted) {
    $script:spliceAt = 0
    $line = [regex]::Replace($line, '("tswd":(?:true|false))\}', [Text.RegularExpressions.MatchEvaluator] {
      param($m) $v = $Started[$script:spliceAt]; $script:spliceAt++
      if ($v) { $m.Groups[1].Value + ',"started":"' + $v + '"}' } else { $m.Value } })
  }
  $line }
$ClearJson = '{"type":"clear"}'

# ================================================================================================ 1. DTOs
Invoke-CheckSection '1. the attach request and the host-issued pid table (PageMessages.cs)' {
  $AR = $SvcT.Assembly.GetType('ClarionDebugger.Terminal.AttachRequest', $true)   # internal: reached through reflection
  $parse = { param($d) $AR.GetMethod('Parse').Invoke($null, @($d)) }
  $ok = & $parse '4242'
  Check 'a decimal pid parses' (($null -ne $ok) -and ($ok.GetType().GetField('Pid').GetValue($ok) -eq 4242)) ''
  Check 'the largest pid parses (uint, not int)' ((& $parse '4294967295') -ne $null) ''
  foreach ($bad in @($null, '', '0', '-1', '+5', ' 5', '5 ', '12 34', '0x10', '1e3', '4294967296', 'abc', '5;quit')) {
    Check "`"$(ShowVal $bad)`" does not parse" ($null -eq (& $parse $bad)) ''
  }

  $LP = $SvcT.Assembly.GetType('ClarionDebugger.Terminal.ListedProcesses', $true)
  $t = [Activator]::CreateInstance($LP, $true)
  $call = { param($name, [object[]] $a) $LP.GetMethod($name).Invoke($t, $a) }
  $list = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new()
  $list.Add((Proc 10 'a.exe' 'C:\a.exe')); $list.Add((Proc 20 'b.exe' 'C:\b.exe'))
  Check 'CONTROL: an empty table resolves nothing' ($null -eq (& $call 'Take' @([uint32] 10))) ''
  & $call 'Begin' @(1) | Out-Null
  Check 'the current generation installs' ((& $call 'Replace' @(1, $list)) -eq $true) ''
  Check 'an unlisted pid resolves to nothing' ($null -eq (& $call 'Take' @([uint32] 30))) ''
  Check 'and a miss consumes nothing' (($LP.GetProperty('Count').GetValue($t)) -eq 2) ''
  $hit = & $call 'Take' @([uint32] 20)
  Check 'a listed pid resolves to its listed process' (($null -ne $hit) -and ($hit.Name -eq 'b.exe')) ''
  Check 'one listing authorises ONE attach: a hit empties the table' (($LP.GetProperty('Count').GetValue($t)) -eq 0) ''
  Check 'so the other listed pid no longer resolves either' ($null -eq (& $call 'Take' @([uint32] 10))) ''
  & $call 'Begin' @(2) | Out-Null
  & $call 'Begin' @(3) | Out-Null
  Check 'an OLDER listing arriving late is refused' ((& $call 'Replace' @(2, $list)) -eq $false) ''
  Check 'and installs nothing' ($null -eq (& $call 'Take' @([uint32] 10))) ''
  $zero = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new(); $zero.Add((Proc 0 'z.exe' 'C:\z.exe'))
  & $call 'Replace' @(3, $zero) | Out-Null
  Check 'a pid-0 entry is never listed' (($LP.GetProperty('Count').GetValue($t)) -eq 0) ''
}

# ================================================================================================ 2. procs reader
Invoke-CheckSection '2. the engine''s procs line, read by the host (ParseProcsJson against the REAL engine writer)' {
  $entries = [System.Collections.Generic.List[AttachEngineSide.ProcEntry]]::new()
  $skips = [System.Collections.Generic.List[AttachEngineSide.ProcSkip]]::new()
  $hostile = @(
    @{ Pid = 4242; Name = '<img src=x onerror=alert(1)>.exe'; Path = 'C:\"quoted"\<b>\app.exe'; Started = '133987654321098765' },
    @{ Pid = 77; Name = "line`nbreak.exe"; Path = "C:\tab`there\x.exe"; Started = '1' },
    @{ Pid = 4294967295; Name = 'max.exe'; Path = 'C:\max.exe'; Started = '18446744073709551615' }
  )
  foreach ($h in $hostile) { $entries.Add((New-EngineEntry $h.Pid $h.Name $h.Path $h.Started)) }
  $s = New-Object AttachEngineSide.ProcSkip; $s.Pid = 9; $s.Name = 'skipped.exe'; $s.Reason = 'no-tswd'; $skips.Add($s)
  $raw = [AttachEngineSide.EngineJson]::Procs($entries, $skips, $true)
  Check 'the engine''s Procs writer emits "started" for each entry (the additive contract, Kit item 3d)' `
    (($script:WriterHasStarted -and ([regex]::Matches($raw, '"started":"\d+"').Count -eq 3)) -or ($PendingStartedOk -and -not $script:WriterHasStarted)) `
    $(if ($script:WriterHasStarted) { $raw } else { 'ProcEntry has no Started field yet: the rest of this suite runs on the writer''s output with "started" spliced in' })
  $line = Engine-ProcsLine $entries $skips $true @($hostile | ForEach-Object { $_.Started })
  $got = Invoke-Static 'ParseProcsJson' @("noise before`r`n" + $line + "`r`n")
  Check 'every listed entry is read, and the --verbose skip entry is NOT' (($null -ne $got) -and ($got.Count -eq 3)) "$(if ($got) { $got.Count } else { '(null)' }) entries"
  for ($i = 0; $i -lt $hostile.Count -and $got -and $i -lt $got.Count; $i++) {
    Check "entry $i reads back exactly: pid, name, path and start time" (($got[$i].Pid -eq $hostile[$i].Pid) -and ($got[$i].Name -ceq $hostile[$i].Name) -and ($got[$i].Path -ceq $hostile[$i].Path) -and ($got[$i].Started -ceq $hostile[$i].Started)) "$($got[$i].Pid) $($got[$i].Name) $($got[$i].Path) $(ShowVal $got[$i].Started)"
  }
  # The shape an engine from before item 3d writes: no "started" at all. It is read, with no start time, and
  # the attach is then refused (section 5).
  $old = Invoke-Static 'ParseProcsJson' @('{"event":"procs","procs":[{"pid":5,"name":"old.exe","path":"C:\\old.exe","tswd":true}],"skipped":0}')
  Check 'an entry with no "started" (an older engine) is listed with NO start time' (($old.Count -eq 1) -and ($null -eq $old[0].Started)) ''
  $bad = Invoke-Static 'ParseProcsJson' @('{"event":"procs","procs":[{"pid":5,"name":"x.exe","path":"C:\\x.exe","tswd":true,"started":"12 --all"},{"pid":6,"name":"y.exe","path":"C:\\y.exe","tswd":true,"started":133}],"skipped":0}')
  Check 'a start time that is not a decimal STRING of digits is dropped, never passed on' (($bad.Count -eq 2) -and ($null -eq $bad[0].Started) -and ($null -eq $bad[1].Started)) "$(ShowVal $bad[0].Started) $(ShowVal $bad[1].Started)"
  Check 'no entry is the skipped process' (-not ($got | Where-Object { $_.Pid -eq 9 })) ''
  Check 'no procs line at all reads as null (an error), not as an empty list' ($null -eq (Invoke-Static 'ParseProcsJson' @('procs: --exclude needs a process id'))) ''
  Check 'a malformed procs line reads as null' ($null -eq (Invoke-Static 'ParseProcsJson' @('{"event":"procs","procs":[{"pid":1,'))) ''
  $noEntries = [System.Collections.Generic.List[AttachEngineSide.ProcEntry]]::new()
  $noSkips = [System.Collections.Generic.List[AttachEngineSide.ProcSkip]]::new()
  $empty = Invoke-Static 'ParseProcsJson' @([AttachEngineSide.EngineJson]::Procs($noEntries, $noSkips, $false))
  Check 'an empty listing reads as an empty list' (($null -ne $empty) -and ($empty.Count -eq 0)) ''
  # The engine BINARY is deliberately not run here: test-engine-session.ps1 holds every script that launches
  # it to the shared lifecycle, and test-procs.ps1 already checks what the built engine prints. The writer
  # above is the engine's own code, which is what makes this a check of both sides.
}

# A pad attached to pid 4242 ('app.exe'), holding the state a session end must clear.
function New-AttachedPad {
  $p = New-Object ClarionDebugger.Terminal.AttachPad
  $l = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new(); $l.Add((Proc 4242 'app.exe' 'C:\app.exe'))
  [ClarionDebugger.Terminal.FakeLists]::Next = $l; $p.CmdListProcs(); $p.CmdAttach('4242')
  $p.GrantOne(); $p._transientBps.Add('x.clw:1') | Out-Null; $p._pendingRtcKey = 'x.clw:1'
  $p.Posts.Clear(); $p.ClearedLine = 0
  $p
}
# Engine payloads, from the engine's own writers (Json.cs), framed the way the engine prints events.
# [NullString]::Value, because PowerShell hands a .NET string parameter "" for $null - and the writer would then
# emit "error":"", which is not what the engine sends for a clean detach.
function Engine-Detached { param([int] $Restored = 3, $Err = $null, [int] $Drained = 0)
  if ($null -eq $Err) { $Err = [NullString]::Value }
  [AttachEngineSide.EngineJson]::Detached([uint32] 4242, $Drained, $Restored, $Err) }
# A DebugDetach as the host really gets one: the ENGINE's detached line through the host's real ParseDetached.
# $Err is untyped on purpose: a [string] parameter turns $null into "", which the writer would emit as "error":"".
function New-Detach { param([int] $Restored = 3, $Err = $null, [bool] $Named = $true)
  $target = if ($Named) { Proc 4242 'app.exe' 'C:\app.exe' } else { $null }
  Invoke-Static 'ParseDetached' @((Engine-Detached $Restored $Err), $target) }

# ================================================================================================ 3. detached + Stop
# A stand-in engine: reads one command line, records it, then exits or hangs as told.
$fakeEngine = Join-Path ([IO.Path]::GetTempPath()) ('attach-fake-engine-' + [guid]::NewGuid().ToString('N') + '.ps1')
[IO.File]::WriteAllText($fakeEngine, @'
param([string] $Out, [string] $Mode, [string] $Say = '')
$l = [Console]::In.ReadLine()
[IO.File]::WriteAllText($Out, [string] $l)
# 'say': answer with one engine line (base64 of what the engine's own writer produced), then exit like the engine.
if ($Mode -eq 'say') { [Console]::Out.WriteLine([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Say))); [Console]::Out.Flush() }
elseif ($Mode -eq 'slow') { Start-Sleep -Milliseconds 3000 }
elseif ($Mode -eq 'never') { Start-Sleep -Seconds 60 }
exit 0
'@)
function Start-FakeEngine { param([string] $Mode, [string] $SayLine = '')
  $out = [IO.Path]::GetTempFileName()
  $say = if ($SayLine) { ' -Say ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($SayLine)) } else { '' }
  $psi = New-Object System.Diagnostics.ProcessStartInfo 'pwsh', "-NoProfile -File `"$fakeEngine`" -Out `"$out`" -Mode $Mode$say"
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  [pscustomobject]@{ Process = $p; Out = $out }
}
function New-Service { param($Engine, $AttachTo)
  $svc = New-Object ClarionDebugger.Services.ClarionDebuggerService
  $SvcT.GetField('_proc', $IF).SetValue($svc, $Engine)
  $SvcT.GetField('_attachTarget', $IF).SetValue($svc, (Unwrap $AttachTo))
  $svc
}
function Invoke-OnLine { param($Svc, $Source, [string] $Line) $SvcT.GetMethod('OnLine', $IF).Invoke($Svc, @($Source, $Line)) | Out-Null }

try {
Invoke-CheckSection '3. the engine''s detached event (the service''s real OnLine)' {
  # The writer compiled here IS the shape the engine sends: protocolcheck pins its output to this literal.
  $pc = Get-Content -Raw -LiteralPath $ProtocolCheckPath
  $pin = [regex]::Match($pc, '"attach wire: detached", Json\.Detached\(1234, 2, 3, null\),\s*"((?:[^"\\]|\\.)*)"\)')
  Check 'the compiled writer produces exactly the detached line protocolcheck pins (restored is a COUNT)' `
    ($pin.Success -and ([AttachEngineSide.EngineJson]::Detached([uint32] 1234, 2, 3, [NullString]::Value) -ceq ($pin.Groups[1].Value -replace '\\"', '"'))) `
    "$([AttachEngineSide.EngineJson]::Detached([uint32] 1234, 2, 3, [NullString]::Value)) vs $($pin.Groups[1].Value)"
  $d = Invoke-Static 'ParseDetached' @((Engine-Detached 3 $null 2), (Proc 4242 'app.exe' 'C:\app.exe'))
  Check 'a clean detach: pid, drained, the restored COUNT, no error, and the listed name' `
    (($d.Pid -eq 4242) -and ($d.Drained -eq 2) -and ($d.Restored -eq 3) -and ($null -eq $d.Error) -and ($d.Name -eq 'app.exe')) "$($d.Pid) $($d.Drained) $($d.Restored) $(ShowVal $d.Error) $($d.Name)"
  $d0 = Invoke-Static 'ParseDetached' @((Engine-Detached 0 $null), $null)
  Check 'restored 0 with no error reads as 0 and no error (nothing was planted: a clean detach)' (($d0.Restored -eq 0) -and ($null -eq $d0.Error)) "$($d0.Restored) $(ShowVal $d0.Error)"
  $d2 = Invoke-Static 'ParseDetached' @((Engine-Detached 1 'bp 0x401000: "denied"'), $null)
  Check 'a failed restore: the count and the error text, unescaped' (($d2.Restored -eq 1) -and ($d2.Error -ceq 'bp 0x401000: "denied"')) (ShowVal $d2.Error)
  # Not an engine shape (the writer always sends the count): a missing or non-numeric count is UNKNOWN (-1).
  $dm = Invoke-Static 'ParseDetached' @('{"event":"detached","pid":4242,"drained":0}', $null)
  $db = Invoke-Static 'ParseDetached' @('{"event":"detached","pid":4242,"drained":0,"restored":true}', $null)
  Check 'a missing or non-numeric restored reads as -1 (unknown), never as a failure' (($dm.Restored -eq -1) -and ($db.Restored -eq -1) -and ($null -eq $dm.Error)) "$($dm.Restored) $($db.Restored)"

  $engine = Start-FakeEngine 'never'
  $svc = New-Service $engine.Process (Proc 4242 'app.exe' 'C:\app.exe')
  $script:dets = [System.Collections.Generic.List[object]]::new()
  $svc.add_Detached([Action[ClarionDebugger.Services.DebugDetach]] { param($x) $script:dets.Add($x) })
  Check 'an attached engine counts as an attach session' ($svc.IsAttachSession) ''
  Invoke-OnLine $svc $engine.Process ('@JSON ' + [AttachEngineSide.EngineJson]::Loaded([uint32] 4242, [uint32] 0x400000, $true))
  Check 'loaded (with the additive attached:true) runs the session' ($svc.State -eq 'Running') "$($svc.State)"
  Invoke-OnLine $svc $engine.Process ('@JSON ' + (Engine-Detached 3 $null 2))
  Check 'detached ends the session at once' ($svc.State -eq 'Idle') "$($svc.State)"
  Check 'and raises Detached once, naming the app' (($script:dets.Count -eq 1) -and ($script:dets[0].Name -eq 'app.exe') -and ($script:dets[0].Pid -eq 4242)) "$($script:dets.Count)"

  # An OLDER engine's buffered line, read after a new session began, must not end the new session.
  $old = $engine.Process
  $newer = Start-FakeEngine 'never'
  $svc2 = New-Service $newer.Process (Proc 5 'new.exe' 'C:\new.exe')
  $SvcT.GetMethod('SetState', $IF).Invoke($svc2, @([ClarionDebugger.Services.DebugSessionState]::Running)) | Out-Null
  $script:dets2 = [System.Collections.Generic.List[object]]::new()
  $script:logs2 = [System.Collections.Generic.List[string]]::new()
  $svc2.add_Detached([Action[ClarionDebugger.Services.DebugDetach]] { param($x) $script:dets2.Add($x) })
  $svc2.add_LogReceived([Action[string]] { param($x) $script:logs2.Add($x) })
  Invoke-OnLine $svc2 $old ('@JSON ' + (Engine-Detached 3))
  Check 'an older engine''s detached leaves the new session running' ($svc2.State -eq 'Running') "$($svc2.State)"
  Check 'raises no Detached for it' ($script:dets2.Count -eq 0) ''
  Check 'and says so in the log instead' (($script:logs2 -join '|') -match 'previous session''s engine detached from pid 4242') ($script:logs2 -join '|')
  foreach ($p in $engine.Process, $newer.Process) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
}

Invoke-CheckSection '3b. a refused attach: an error, even with code 0, is a failure (engine contract from Kit, 7e9f67e)' {
  # The engine's refusal codes are not all Win32 errors: no TSWD / an unreadable image is code 0. Success is
  # decided by `loaded` arriving, never by an error's code. Driven through the real OnLine and the real
  # process-exit handler, with a real process that has exited with the engine's refusal code 2.
  $psi = New-Object System.Diagnostics.ProcessStartInfo 'cmd.exe', '/c exit 2'
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $dead = [System.Diagnostics.Process]::Start($psi); $dead.WaitForExit()
  $svc = New-Service $dead (Proc 4242 'app.exe' 'C:\app.exe')
  $SvcT.GetMethod('SetState', $IF).Invoke($svc, @([ClarionDebugger.Services.DebugSessionState]::Launching)) | Out-Null
  $script:errs = [System.Collections.Generic.List[string]]::new(); $script:exits = [System.Collections.Generic.List[int]]::new()
  $svc.add_EngineError([Action[string]] { param($x) $script:errs.Add($x) })
  $svc.add_Exited([Action[int]] { param($x) $script:exits.Add($x) })
  Invoke-OnLine $svc $dead ('@JSON ' + [AttachEngineSide.EngineJson]::AttachError('attach failed: no TSWD debug info in C:\app.exe <b>x</b>', 0))
  Check 'the error reaches the host as its message text, unchanged' `
    (($script:errs.Count -eq 1) -and ($script:errs[0] -ceq 'attach failed: no TSWD debug info in C:\app.exe <b>x</b>')) ($script:errs -join '|')
  Check 'code 0 is NOT success: the session does not become Running' ($svc.State -eq 'Launching') "$($svc.State)"
  $SvcT.GetMethod('OnEngineProcessExited', $IF).Invoke($svc, @($dead)) | Out-Null
  Check 'the engine''s exit (code 2) returns the session to Idle and reports the code' (($svc.State -eq 'Idle') -and ($script:exits.Count -eq 1) -and ($script:exits[0] -eq 2)) "$($svc.State) $($script:exits -join ',')"
  Check 'and no attached state remains' (-not $svc.IsAttachSession) ''

  # The engine's refusal of a REUSED pid (--expect-start mismatch): the same error shape, code 0, then exit 2.
  $reused = 'attach failed: process 4242 is not the one listed (pid reused)'
  $dead2 = [System.Diagnostics.Process]::Start($psi); $dead2.WaitForExit()
  $svc = New-Service $dead2 (Proc 4242 'app.exe' 'C:\app.exe')
  $SvcT.GetMethod('SetState', $IF).Invoke($svc, @([ClarionDebugger.Services.DebugSessionState]::Launching)) | Out-Null
  $script:errs = [System.Collections.Generic.List[string]]::new()
  $svc.add_EngineError([Action[string]] { param($x) $script:errs.Add($x) })
  Invoke-OnLine $svc $dead2 ('@JSON ' + [AttachEngineSide.EngineJson]::AttachError($reused, 0))
  Check 'a reused pid: the refusal reaches the host as its text, and the session does not run' `
    (($script:errs.Count -eq 1) -and ($script:errs[0] -ceq $reused) -and ($svc.State -eq 'Launching')) "$($svc.State) $($script:errs -join '|')"
  $SvcT.GetMethod('OnEngineProcessExited', $IF).Invoke($svc, @($dead2)) | Out-Null
  Check 'and the exit returns it to Idle with nothing attached' (($svc.State -eq 'Idle') -and -not $svc.IsAttachSession) "$($svc.State)"
  $pad = New-AttachedPad
  $pad.OnSvcEngineError($reused)
  $pad.Posts.Clear(); $pad.OnSvcExited(2)
  Check 'the pad says why after the clear: the pid was reused' ($pad.Posts -contains ('console|err|engine: ' + $reused)) ($pad.Posts -join ' / ')

  # After a detach, too, nothing attached remains.
  $e = Start-FakeEngine 'never'
  $svc = New-Service $e.Process (Proc 4242 'app.exe' 'C:\app.exe')
  Invoke-OnLine $svc $e.Process ('@JSON ' + (Engine-Detached 0))
  Check 'after detached, no attached state remains either' (-not $svc.IsAttachSession) ''
  try { if (-not $e.Process.HasExited) { $e.Process.Kill() } } catch { }

  # The pad: a code-0 refusal is said again, as text, after the exit's clear, and nothing attached is left.
  $pad = New-AttachedPad
  $pad.OnSvcEngineError('attach failed: no TSWD debug info in C:\app.exe')
  $pad.Posts.Clear(); $pad.OnSvcExited(2)
  Check 'the pad repeats the refusal after the clear, and holds no attach session' `
    (($pad.Posts[0] -ceq $ClearJson) -and ($pad.Posts[1] -ceq 'console|err|engine: attach failed: no TSWD debug info in C:\app.exe') -and -not $pad.HasAttach) ($pad.Posts -join ' / ')
}

Invoke-CheckSection '4. Stop: detach in attach mode, quit otherwise, kill only as the last resort' {
  Check 'TeardownCommand: attached -> detach' ((Invoke-Static 'TeardownCommand' @($true)) -ceq 'detach') ''
  Check 'TeardownCommand: launched -> quit' ((Invoke-Static 'TeardownCommand' @($false)) -ceq 'quit') ''
  $detachMs = $SvcT.GetField('DetachWaitMs', $SF).GetValue($null); $quitMs = $SvcT.GetField('QuitWaitMs', $SF).GetValue($null)
  Check "the detach wait ($detachMs ms) is the contract's 8 s, longer than quit's ($quitMs ms)" (($detachMs -eq 8000) -and ($quitMs -eq 1500)) ''

  # attached, and the engine detaches promptly
  $e = Start-FakeEngine 'obey'
  $svc = New-Service $e.Process (Proc 4242 'app.exe' 'C:\app.exe')
  $logs = [System.Collections.Generic.List[string]]::new(); $svc.add_LogReceived([Action[string]] { param($x) $logs.Add($x) }.GetNewClosure())
  $ok = $svc.Stop()
  Check 'attached: Stop sends detach' (((Get-Content -Raw -LiteralPath $e.Out) -replace '\s') -ceq 'detach') (Get-Content -Raw -LiteralPath $e.Out)
  Check 'and, the engine having exited, reports the session over with no kill' ($ok -and ($svc.State -eq 'Idle') -and -not (($logs -join '|') -match 'kill')) ($logs -join '|')

  # attached, and the detach takes longer than a quit is given (a pause round-trip first): no kill
  $e = Start-FakeEngine 'slow'
  $svc = New-Service $e.Process (Proc 4242 'app.exe' 'C:\app.exe')
  $logs = [System.Collections.Generic.List[string]]::new(); $svc.add_LogReceived([Action[string]] { param($x) $logs.Add($x) }.GetNewClosure())
  $sw = [Diagnostics.Stopwatch]::StartNew(); $ok = $svc.Stop(); $sw.Stop()
  Check "attached: a detach that takes about 3 s is waited for, not killed at $quitMs ms" `
    ($ok -and ($sw.ElapsedMilliseconds -gt $quitMs) -and -not (($logs -join '|') -match 'kill')) "$($sw.ElapsedMilliseconds) ms $($logs -join '|')"

  # attached, and the engine never exits: the last resort, said out loud
  $e = Start-FakeEngine 'never'
  $svc = New-Service $e.Process (Proc 4242 'app.exe' 'C:\app.exe')
  $logs = [System.Collections.Generic.List[string]]::new(); $svc.add_LogReceived([Action[string]] { param($x) $logs.Add($x) }.GetNewClosure())
  $sw = [Diagnostics.Stopwatch]::StartNew(); $ok = $svc.Stop(); $sw.Stop()
  Check 'attached, engine wedged: Stop waited the full detach time before killing' ($sw.ElapsedMilliseconds -ge ($detachMs - 100)) "$($sw.ElapsedMilliseconds) ms"
  Check 'and warned that the app may crash' (($logs -join '|') -match 'did not detach.*being killed.*may crash') ($logs -join '|')
  Check 'and the engine is gone' ($ok -and $e.Process.HasExited) ''

  # CONTROL: a launched session still quits
  $e = Start-FakeEngine 'obey'
  $svc = New-Service $e.Process $null
  $ok = $svc.Stop()
  Check 'CONTROL: launched: Stop sends quit' (((Get-Content -Raw -LiteralPath $e.Out) -replace '\s') -ceq 'quit') (Get-Content -Raw -LiteralPath $e.Out)
}
Invoke-CheckSection '9. a CLOSING pad still warns: Dispose''s TeardownLive observes Stop to the end (3f2d747f run 2)' {
  # Dispose unsubscribes the pad's own handlers before it stops the session, and its page is going. The risky
  # outcomes must still reach the user, through the durable channel (here: the recorder standing in for the
  # log + dialog). Each case runs the REAL TeardownLive and TeardownObserver over the REAL service Stop, against
  # a stand-in engine whose answer is the ENGINE's own writer output.
  function Invoke-Teardown { param([string] $Mode, [string] $Say = '', $AttachTo = (Proc 4242 'app.exe' 'C:\app.exe'))
    [ClarionDebugger.Terminal.ProbeWire]::Warns.Clear()
    $e = Start-FakeEngine $Mode $Say
    $svc = New-Service $e.Process $AttachTo
    [ClarionDebugger.Terminal.ProbeWire]::Wire($svc, $e.Process)
    $ok = [ClarionDebugger.Terminal.AttachPad]::TeardownLive($svc, 'app.exe', [ClarionDebugger.Terminal.ProbeWire]::Collector())
    [pscustomobject]@{ Ok = $ok; Warns = @([ClarionDebugger.Terminal.ProbeWire]::Warns); Sent = ((Get-Content -Raw -LiteralPath $e.Out) -replace '\s')
      Left = [ClarionDebugger.Terminal.ProbeWire]::Subscribers($svc, 'Detached') + [ClarionDebugger.Terminal.ProbeWire]::Subscribers($svc, 'DetachAbandoned') }
  }
  $r = Invoke-Teardown 'say' ('@JSON ' + (Engine-Detached 2 '1 breakpoint byte(s) could not be restored'))
  Check 'detach answered WITH AN ERROR: the durable warning is given, once, in the agreed words' `
    (($r.Sent -ceq 'detach') -and ($r.Warns.Count -eq 1) -and ($r.Warns[0] -ceq 'CA Debugger could not detach cleanly from app.exe (pid 4242): 1 breakpoint byte(s) could not be restored. Save your work in app.exe and restart it.')) `
    "sent=$($r.Sent) $($r.Warns -join ' | ')"
  Check 'and the observer is gone once Stop has returned' ($r.Left -eq 0) "$($r.Left) left"
  $r = Invoke-Teardown 'never'
  Check 'detach never answered (the engine is KILLED): the durable warning is given, once' `
    (($r.Warns.Count -eq 1) -and ($r.Warns[0] -match '^CA Debugger could not detach cleanly from app\.exe \(pid 4242\): the engine did not detach in time and had to be killed.*Save your work in app\.exe and restart it\.$')) ($r.Warns -join ' | ')
  Check 'and the observer is gone' ($r.Left -eq 0) "$($r.Left) left"
  $r = Invoke-Teardown 'say' ('@JSON ' + (Engine-Detached 3))
  Check 'a CLEAN detach on close needs no warning' (($r.Sent -ceq 'detach') -and ($r.Warns.Count -eq 0)) ($r.Warns -join ' | ')
  $r = Invoke-Teardown 'obey' '' $null
  Check 'CONTROL: a launched session''s close warns about nothing' (($r.Sent -ceq 'quit') -and ($r.Warns.Count -eq 0)) "sent=$($r.Sent) $($r.Warns -join ' | ')"
}
} finally { Remove-Item -LiteralPath $fakeEngine -ErrorAction SilentlyContinue }

# ================================================================================================ 5. the pad
Invoke-CheckSection '5. the pad lists, and attaches only to what it listed' {
  [ClarionDebugger.Terminal.DebugSessionController]::State = 'Idle'
  $pad = New-Object ClarionDebugger.Terminal.AttachPad
  $next = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new()
  $next.Add((Proc 4242 '<b>"evil"</b>.exe' 'C:\"x"\app.exe')); $next.Add((Proc 77 'ok.exe' 'C:\ok.exe'))
  [ClarionDebugger.Terminal.FakeLists]::Next = $next; [ClarionDebugger.Terminal.FakeLists]::NextError = $null
  $pad.CmdListProcs()
  Check 'the listing excludes this process (the IDE)' ([ClarionDebugger.Terminal.FakeLists]::LastExclude -eq $PID) "$([ClarionDebugger.Terminal.FakeLists]::LastExclude)"
  $msg = $pad.Posts[$pad.Posts.Count - 1] | ConvertFrom-Json
  Check 'the page gets a procs message with every listed process' (($msg.type -eq 'procs') -and (@($msg.procs).Count -eq 2)) $pad.Posts[$pad.Posts.Count - 1]
  Check 'a hostile name and path arrive byte for byte (escaped JSON, not markup)' (($msg.procs[0].name -ceq '<b>"evil"</b>.exe') -and ($msg.procs[0].path -ceq 'C:\"x"\app.exe')) $pad.Posts[$pad.Posts.Count - 1]

  $pad.Posts.Clear()
  $pad.CmdAttach('999')
  Check 'an UNLISTED pid is refused' ($pad._svc.Attached.Count -eq 0) ''
  Check 'with a console line saying so' (($pad.Posts -join "`n") -match 'console\|err\|attach: pid 999 was not in the process list') ($pad.Posts -join ' / ')
  Check 'and the refusal consumes nothing' ($pad.ListedCount -eq 2) ''
  foreach ($bad in @('abc', '0', '-1', '4242;quit', $null)) {
    $pad.Posts.Clear(); $pad.CmdAttach($bad)
    Check "malformed `"$(ShowVal $bad)`": dropped with a console line" (($pad._svc.Attached.Count -eq 0) -and (($pad.Posts -join '') -match 'console\|err\|attach: dropped')) ($pad.Posts -join ' / ')
  }
  $pad._svc.State = 'Running'; $pad.Posts.Clear()
  $pad.CmdAttach('4242')
  Check 'a session already running: nothing is attached' ($pad._svc.Attached.Count -eq 0) ''
  Check 'and the listing is not spent' ($pad.ListedCount -eq 2) ''
  $pad._svc.State = 'Idle'
  [ClarionDebugger.Terminal.DebugSessionController]::State = 'Running'
  $pad.CmdAttach('4242')
  Check 'another pad''s session live (controller not idle): nothing is attached' ($pad._svc.Attached.Count -eq 0) ''
  [ClarionDebugger.Terminal.DebugSessionController]::State = 'Idle'

  $pad.Posts.Clear()
  $pad.CmdAttach('4242')
  Check 'a LISTED pid attaches to exactly that listed process' (($pad._svc.Attached.Count -eq 1) -and ($pad._svc.Attached[0].Pid -eq 4242) -and ($pad._svc.Attached[0].Path -ceq 'C:\"x"\app.exe')) ''
  Check 'the page is told Stop now detaches' ($pad.Posts -contains '{"type":"attachmode","on":true}') ($pad.Posts -join ' / ')
  Check 'the pad remembers it is attached' ($pad.HasAttach) ''
  Check 'the session steps a launch takes are taken (hooks re-armed, gutter merged)' (($pad.Rearms -eq 1) -and ($pad.Merges -eq 1)) ''
  $pad._svc.Attached.Clear()
  $pad.CmdAttach('77')
  Check 'one listing, ONE attach: the other listed pid is now refused' ($pad._svc.Attached.Count -eq 0) ''

  # A pid is not an identity: the listed start time goes with the attach, and without one there is no attach.
  $pS = New-Object ClarionDebugger.Terminal.AttachPad
  $ls = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new()
  $ls.Add((Proc 31 'timed.exe' 'C:\timed.exe' '133000000000000001')); $ls.Add((Proc 32 'old.exe' 'C:\old.exe' ''))
  [ClarionDebugger.Terminal.FakeLists]::Next = $ls; $pS.CmdListProcs(); $pS.Posts.Clear()
  $pS.CmdAttach('32')
  Check 'a listed entry with NO start time (an older engine) is refused, not attached blind' `
    (($pS._svc.Attached.Count -eq 0) -and (($pS.Posts -join "`n") -match 'console\|err\|attach: the process list gave no start time for old\.exe \(pid 32\)')) ($pS.Posts -join ' / ')
  [ClarionDebugger.Terminal.FakeLists]::Next = $ls; $pS.CmdListProcs()
  $pS.CmdAttach('31')
  Check 'a listed entry WITH a start time attaches, carrying exactly the listed start time' `
    (($pS._svc.Attached.Count -eq 1) -and ($pS._svc.Attached[0].Started -ceq '133000000000000001')) ''

  # The command line the service would launch (BuildAttachArgs; the real AttachSession would start an engine).
  $args1 = Invoke-Static 'BuildAttachArgs' @((Proc 4242 'app.exe' 'C:\app.exe' '133000000000000001'), $null, $null)
  Check 'the attach command line carries --expect-start with the listed start time' `
    ($args1 -ceq 'attach 4242 --interactive --json --expect-start 133000000000000001') $args1
  $threw = $false
  try { Invoke-Static 'BuildAttachArgs' @((Proc 4242 'app.exe' 'C:\app.exe' ''), $null, $null) | Out-Null } catch { $threw = $true }
  Check 'and the service refuses to build one without a start time (nothing is launched)' $threw ''

  # Refresh retires the previous listing's pids at once, and a late older listing never installs.
  $p2 = New-Object ClarionDebugger.Terminal.AttachPad
  $p2.HoldWork = $true
  $a = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new(); $a.Add((Proc 11 'old.exe' 'C:\old.exe'))
  [ClarionDebugger.Terminal.FakeLists]::Next = $a; $p2.CmdListProcs()
  $b = [System.Collections.Generic.List[ClarionDebugger.Terminal.AttachableProcess]]::new(); $b.Add((Proc 22 'new.exe' 'C:\new.exe'))
  [ClarionDebugger.Terminal.FakeLists]::Next = $b; $p2.CmdListProcs()
  $p2.Release(1); $p2.Release(0)   # the newer listing lands first, the older one late
  $p2.CmdAttach('11')
  Check 'a pid only in an OLDER listing that arrived late is refused' ($p2._svc.Attached.Count -eq 0) ''
  Check 'and the older listing was never posted to the page' (@($p2.Posts | Where-Object { $_ -like '*old.exe*' }).Count -eq 0) ($p2.Posts -join ' / ')
  $p3 = New-Object ClarionDebugger.Terminal.AttachPad
  [ClarionDebugger.Terminal.FakeLists]::Next = $a; $p3.CmdListProcs()
  $p3.HoldWork = $true
  [ClarionDebugger.Terminal.FakeLists]::Next = $b; $p3.CmdListProcs()   # a refresh, still being read
  $p3.CmdAttach('11')
  Check 'a refresh in flight retires the previous listing''s pids at once' ($p3._svc.Attached.Count -eq 0) ''
  [ClarionDebugger.Terminal.FakeLists]::Next = $null; [ClarionDebugger.Terminal.FakeLists]::NextError = 'boom'
  $p4 = New-Object ClarionDebugger.Terminal.AttachPad
  $p4.CmdListProcs()
  $m4 = $p4.Posts[0] | ConvertFrom-Json
  Check 'a listing that failed posts an empty list with the error' ((@($m4.procs).Count -eq 0) -and ($m4.error -eq 'boom')) $p4.Posts[0]
  [ClarionDebugger.Terminal.FakeLists]::NextError = $null
}

Invoke-CheckSection '6. the pad: attached, then detached, then the engine exits' {
  $pad = New-AttachedPad
  Check 'CONTROL: the attached pad holds state a session end must clear' (($pad.GrantCount -eq 1) -and ($pad._transientBps.Count -eq 1) -and ($null -ne $pad._pendingRtcKey)) ''
  $pad.OnSvcDetached((New-Detach))
  Check 'detached clears the edit grants, the transient breakpoints and the run-to-cursor key' `
    (($pad.GrantCount -eq 0) -and ($pad._transientBps.Count -eq 0) -and ($null -eq $pad._pendingRtcKey)) ''
  Check 'and the execution line' ($pad.ClearedLine -eq 1) ''
  Check 'it clears the page FIRST, then says the app is still running, with the engine''s restored count' `
    (($pad.Posts.Count -eq 2) -and ($pad.Posts[0] -ceq $ClearJson) -and ($pad.Posts[1] -ceq 'console|info|Detached; app.exe is still running (3 breakpoints restored).')) ($pad.Posts -join ' / ')
  Check 'a clean detach (the ENGINE''s payload: a count, no error) warns about nothing' (-not (($pad.Posts -join "`n") -match 'console\|err\|')) ($pad.Posts -join ' / ')
  $pad = New-AttachedPad
  $pad.OnSvcDetached((New-Detach 0))
  Check 'restored 0 with no error is a clean detach too: no warning, and the count is shown' `
    ((-not (($pad.Posts -join "`n") -match 'console\|err\|')) -and ($pad.Posts -contains 'console|info|Detached; app.exe is still running (0 breakpoints restored).')) ($pad.Posts -join ' / ')
  $pad = New-AttachedPad
  $pad.OnSvcDetached((New-Detach 1))
  Check 'one breakpoint is "1 breakpoint", singular' ($pad.Posts -contains 'console|info|Detached; app.exe is still running (1 breakpoint restored).') ($pad.Posts -join ' / ')
  $pad = New-AttachedPad
  $pad.OnSvcDetached((Invoke-Static 'ParseDetached' @('{"event":"detached","pid":4242,"drained":0}', (Proc 4242 'app.exe' 'C:\app.exe'))))
  Check 'an unknown count (-1) is left out of the line, and is not a failure' `
    (($pad.Posts -contains 'console|info|Detached; app.exe is still running.') -and -not (($pad.Posts -join "`n") -match 'console\|err\|')) ($pad.Posts -join ' / ')
  $pad = New-AttachedPad
  $pad.OnSvcDetached((New-Detach))
  $pad.Posts.Clear()
  $pad.OnSvcExited(0)
  Check 'the engine''s exit after a detach posts nothing, so the Detached line survives' ($pad.Posts.Count -eq 0) ($pad.Posts -join ' / ')
  Check 'and the attach session is over' (-not $pad.HasAttach) ''

  # The other order: the process exit is handled before the buffered detached line.
  # By then the service has dropped its attach target, so the event carries no name (the service clears it on
  # exit); the pad still names the app it attached to.
  $pad = New-AttachedPad
  $pad.OnSvcExited(0)
  $pad.OnSvcDetached((New-Detach -Named $false))
  $last = $pad.Posts[$pad.Posts.Count - 1]
  Check 'exit first, detached second (no name on the event): the Detached line still names the app, and is last' ($last -ceq 'console|info|Detached; app.exe is still running (3 breakpoints restored).') ($pad.Posts -join ' / ')
  Check 'and it follows a clear' ($pad.Posts[$pad.Posts.Count - 2] -ceq $ClearJson) ($pad.Posts -join ' / ')

  # The warning is driven by the engine's `error` alone.
  $pad = New-AttachedPad
  $pad.OnSvcDetached((New-Detach 2 '1 breakpoint byte(s) could not be restored'))
  $txt = $pad.Posts -join "`n"
  Check 'detached with an error (the ENGINE''s payload): an ERR line warns the app may crash, with the reason' `
    ($txt -match 'console\|err\|detach could not restore every breakpoint \(1 breakpoint byte\(s\) could not be restored\): app\.exe will probably crash') ($pad.Posts -join ' / ')
  Check 'and the info line still reports what WAS restored' ($pad.Posts -contains 'console|info|Detached; app.exe is still running (2 breakpoints restored).') ($pad.Posts -join ' / ')
}

Invoke-CheckSection '7. the pad: an attach that fails, and a launch''s exit (unchanged)' {
  $pad = New-AttachedPad
  $pad.OnSvcEngineError('attach failed: Access is denied. (5)')
  $pad.Posts.Clear()
  $pad.OnSvcExited(2)
  Check 'a failed attach: the exit clears the page, THEN repeats why the attach failed' `
    (($pad.Posts.Count -eq 3) -and ($pad.Posts[0] -ceq $ClearJson) -and ($pad.Posts[1] -ceq 'console|err|engine: attach failed: Access is denied. (5)') -and ($pad.Posts[2] -match 'session ended \(exit 2\)')) ($pad.Posts -join ' / ')
  $pad = New-AttachedPad
  $pad.OnSvcEngineError('thread 12: not found')
  $pad.Posts.Clear(); $pad.OnSvcExited(0)
  Check 'an unrelated engine error is not repeated at the exit' (-not (($pad.Posts -join "`n") -match 'thread 12')) ($pad.Posts -join ' / ')

  $launch = New-Object ClarionDebugger.Terminal.AttachPad
  $launch.OnSvcExited(0)
  Check 'CONTROL: a launch''s exit is unchanged: the session-ended line, then clear' `
    (($launch.Posts.Count -eq 2) -and ($launch.Posts[0] -match 'session ended \(exit 0\)') -and ($launch.Posts[1] -ceq $ClearJson)) ($launch.Posts -join ' / ')
}

Invoke-CheckSection '8. where the pieces are wired (position and text pins)' {
  $onMsg = Get-CSharpCodeOnly (Get-Method 'private void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)')
  Check 'the page''s procs action lists processes' ($onMsg -match 'case "procs": CmdListProcs\(\); break;') ''
  Check 'the page''s attach action goes through CmdAttach with its data' ($onMsg -match 'case "attach": CmdAttach\(data\); break;') ''
  Check 'Detached is subscribed and unsubscribed, once each' `
    ((([regex]::Matches($web, '_svc\.Detached\s*\+=\s*OnSvcDetached;')).Count -eq 1) -and (([regex]::Matches($web, '_svc\.Detached\s*-=\s*OnSvcDetached;')).Count -eq 1)) ''
  $dispose = Get-CSharpCodeOnly (Get-Method 'protected override void Dispose(bool disposing)')
  Check 'closing a LIVE session tears down through TeardownLive, with the durable warner, and never kills the engine itself' `
    (($dispose -match 'var warn = DurableWarning\.ForCurrentThread\(\);') -and ($dispose -match 'TeardownLive\(svc, attachedName, warn\)') -and ($dispose -notmatch '\.Kill\(')) ''
  $dw = Get-CSharpCodeOnly (Get-Method 'internal static class DurableWarning')
  Check 'the durable warning delivers through Deliver: %LOCALAPPDATA% log first, %TEMP% log second, the real dialog' `
    (($dw -match 'return Deliver\(text, new\[\] \{ LogPath, FallbackLogPath \}, ui, StartStaThread, ShowBox\);') -and `
     ($dw -match 'SpecialFolder\.LocalApplicationData\), "CA Debugger", "detach\.log"') -and ($dw -match 'Path\.GetTempPath\(\), "CA Debugger", "detach\.log"') -and `
     ($dw -match 'MessageBox\.Show\(text, "CA Debugger"') -and ($dw -match 'SetApartmentState\(System\.Threading\.ApartmentState\.STA\)')) ''
  Check 'DetachAbandoned is subscribed and unsubscribed by the pad, once each' `
    ((([regex]::Matches($web, '_svc\.DetachAbandoned\s*\+=\s*OnSvcDetachAbandoned;')).Count -eq 1) -and (([regex]::Matches($web, '_svc\.DetachAbandoned\s*-=\s*OnSvcDetachAbandoned;')).Count -eq 1)) ''
  $cmdStop = Get-CSharpCodeOnly (Get-Method 'public void CmdStop()')
  Check 'the Stop command tears down through Stop too' (($cmdStop -match 'svc\.Stop\(\)') -and ($cmdStop -notmatch '\.Kill\(')) ''
  $attachSvc = Get-CSharpCodeOnly (Get-Method 'public void AttachSession(AttachableProcess target, IEnumerable<DebugBreakpoint> breakpoints, IEnumerable<string> solutionDlls)' $svcSrc)
  Check 'the service builds its command line through BuildAttachArgs, first, before anything is started' `
    (($attachSvc -match 'string args = BuildAttachArgs\(target, breakpoints, solutionDlls\);') -and ($attachSvc.IndexOf('BuildAttachArgs') -lt $attachSvc.IndexOf('Launch('))) ''
  Check 'with the same --bp / --solution-dll options as a launch (one shared builder)' `
    (([regex]::Matches((Get-CSharpCodeOnly $svcSrc), 'AppendSessionOptions\(args, breakpoints, solutionDlls\);')).Count -eq 2) ''
  Check 'and marks the engine as attached, so Stop detaches' ($attachSvc -match 'Launch\(target\.Path, args, true, target\);') ''
  $stop = Get-CSharpCodeOnly (Get-Method 'public bool Stop()' $svcSrc)
  Check 'Stop picks its verb and its wait from IsAttachSession' `
    (($stop -match 'bool attached = IsAttachSession;') -and ($stop -match 'SendCommand\(TeardownCommand\(attached\)\)')) ''
  Check 'the only literal "quit" in the service is TeardownCommand''s' (([regex]::Matches((Get-CSharpCodeOnly $svcSrc), '"quit"')).Count -eq 1) ''
}

Invoke-CheckSection '10. the durable warning survives its own failures (DurableWarning.Deliver, fault-injected)' {
  # The real Deliver, with each channel made to fail in turn. A log location is made UNWRITABLE by putting it
  # under an existing FILE, so its directory cannot be created. The dialog and the STA thread are recorders.
  $dir = Join-Path ([IO.Path]::GetTempPath()) ('attach-durable-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $dir | Out-Null
  try {
    $blocker = Join-Path $dir 'not-a-dir'; [IO.File]::WriteAllText($blocker, 'x')
    $bad1 = Join-Path $blocker 'a\detach.log'; $bad2 = Join-Path $blocker 'b\detach.log'
    $good1 = Join-Path $dir 'primary\detach.log'; $good2 = Join-Path $dir 'fallback\detach.log'
    $DP = [ClarionDebugger.Terminal.DurableProbe]
    $L = 1; $FB = 2; $PD = 4; $TD = 8
    $msg = 'CA Debugger could not detach cleanly from app.exe (pid 4242): x. Save your work in app.exe and restart it.'

    $ctx = New-Object ClarionDebugger.Terminal.InlineContext
    $ch = $DP::Run($msg, [string[]] @($good1, $good2), $ctx)
    Check 'CONTROL: all well: the primary log and the posted dialog, nothing else' `
      (($ch -eq ($L + $PD)) -and ($ctx.Posts -eq 1) -and ($DP::Boxes.Count -eq 1) -and ($DP::Boxes[0] -ceq $msg) -and ($DP::Threads -eq 0)) "channels=$ch"
    Check 'the log line is dated and carries the warning' ((Get-Content -Raw -LiteralPath $good1) -match "^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  $([regex]::Escape($msg))") ''
    Check 'and the fallback log was not touched' (-not (Test-Path -LiteralPath $good2)) ''

    $ch = $DP::Run($msg, [string[]] @($bad1, $good2), (New-Object ClarionDebugger.Terminal.InlineContext))
    Check 'the primary log unwritable: the FALLBACK log gets the line, and the dialog still goes' `
      (($ch -eq ($FB + $PD)) -and ((Get-Content -Raw -LiteralPath $good2) -match [regex]::Escape($msg)) -and ($DP::Boxes.Count -eq 1)) "channels=$ch"

    $ch = $DP::Run($msg, [string[]] @($good1, $good2), (New-Object ClarionDebugger.Terminal.DeadContext))
    Check 'the UI post THROWS (a destroyed handle): the dialog falls back to its own STA thread' `
      (($ch -eq ($L + $TD)) -and ($DP::Threads -eq 1) -and ($DP::Boxes.Count -eq 1) -and ($DP::Boxes[0] -ceq $msg)) "channels=$ch threads=$($DP::Threads)"

    $ch = $DP::Run($msg, [string[]] @($bad1, $bad2), $null)
    Check 'BOTH logs unwritable and no UI context: the dialog still shows, on its own thread' `
      (($ch -eq $TD) -and ($DP::Boxes.Count -eq 1)) "channels=$ch"
    $ch = $DP::Run($msg, [string[]] @($bad1, $bad2), (New-Object ClarionDebugger.Terminal.DeadContext))
    Check 'both logs unwritable AND the post throws: the dialog still shows' (($ch -eq $TD) -and ($DP::Boxes.Count -eq 1)) "channels=$ch"
  } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

# Runtime counts on a clean run, per section (in run order): 25, 11, 12, 9 (3b), 10, 6 (9), 27, 14, 3, 12, 7 (10).
$EXPECTED_CHECKS = 136
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
