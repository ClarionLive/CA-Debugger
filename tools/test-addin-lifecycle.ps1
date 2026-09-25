# Regression check: the engine outliving its own "exited" event (ticket 0449e5c9, Owner's decision: option C).
#
#   pwsh -NoProfile -File tools\test-addin-lifecycle.ps1
#
# When the DEBUGGEE finishes, the engine reports "exited" and the host goes Idle at once, so a run-to-completion
# reads as over immediately. The engine PROCESS can outlive that by a moment. A Start pressed inside that window
# used to throw "A debug session is already running." for a session the user had just been told was over. Now:
#   - Launch asks DecideLaunch first, and a lingering engine is REFUSED with a true console line, not thrown;
#   - the "exited" arm reaps the engine: ReapGraceMs to exit on its own, then Stop().
#
# FORCED, NOT TIMED. The reap is driven against a REAL process that is certain to linger (a 30-second ping),
# and against one that is certain to have exited, so neither result can come from the engine happening to die
# fast. DecideLaunch is a pure function and is run over its whole input space. Launch itself and the "exited"
# arm drive a real engine and are pinned by POSITION below, not run.
#
# ASCII only, for Windows PowerShell 5.1.

param(
  # Defaulted in the body: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $ServicePath = '',
  [string] $WebViewPath = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
if (-not $ServicePath) { $ServicePath = Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs' }
if (-not $WebViewPath) { $WebViewPath = Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs' }
$svc = Get-Content -Raw -LiteralPath $ServicePath
$web = Get-Content -Raw -LiteralPath $WebViewPath
Set-ExtractSource $svc

$probe = @"
using System;
using System.Diagnostics;
$(Get-Method 'public enum DebugSessionState')
public static class Lifecycle {
  $((Get-Method 'internal enum LaunchGate') -replace 'internal enum', 'public enum')
  $((Get-Method 'internal static LaunchGate DecideLaunch(bool engineAlive, DebugSessionState state)') -replace 'internal static', 'public static')
  $((Get-Method 'internal static bool ReapLingeringEngine(Process engine, int graceMs, Func<bool> stop)') -replace 'internal static', 'public static')
}
"@
Add-Type -TypeDefinition $probe -Language CSharp | Out-Null

Write-Host 'a Start while the last engine is still closing is REFUSED, not thrown'
$states = [Enum]::GetNames([DebugSessionState])
foreach ($s in $states) {
  $st = [DebugSessionState] $s
  Check "no engine alive, $s -> Proceed" ([Lifecycle]::DecideLaunch($false, $st) -eq [Lifecycle+LaunchGate]::Proceed) ([Lifecycle]::DecideLaunch($false, $st))
  $want = if ($s -eq 'Idle') { 'RefuseClosing' } else { 'AlreadyRunning' }
  Check "engine alive, $s -> $want" ([Lifecycle]::DecideLaunch($true, $st) -eq [Lifecycle+LaunchGate]::$want) ([Lifecycle]::DecideLaunch($true, $st))
}

$launch = Get-CSharpCodeOnly (Get-Method 'private void Launch(string targetExe, string args, bool interactive, AttachableProcess attachTo)')
$iGate = $launch.IndexOf('DecideLaunch(IsRunning, State)')
$iProc = $launch.IndexOf('new ProcessStartInfo')
Check 'Launch asks DecideLaunch before it starts anything' (($iGate -ge 0) -and ($iProc -gt $iGate)) "gate=$iGate start=$iProc"
$refuse = if ($launch -match '(?s)case LaunchGate\.RefuseClosing:(.*?)case LaunchGate\.AlreadyRunning:') { $Matches[1] } else { '' }
Check 'the refusal logs the shared message and returns, with no throw' `
  (($refuse -match 'LogReceived\?\.Invoke\(EngineClosingMessage\)') -and ($refuse -match 'return;') -and ($refuse -notmatch 'throw')) ''
Check 'a genuinely live session still throws "already running"' `
  ($launch -match '(?s)case LaunchGate\.AlreadyRunning:\s*throw new InvalidOperationException\("A debug session is already running\."\)') ''

# The pad asks FIRST, so it never announces a start that is not going to happen.
$padStart = Get-CSharpCodeOnly (Get-Method 'private void StartSession()' $web)
$iAsk = $padStart.IndexOf('_svc.IsEngineStillClosing')
$iResolve = $padStart.IndexOf('ResolveTargetForStart()')
$iStarting = $padStart.IndexOf('"starting: "')
Check 'the pad refuses before resolving the target or announcing a start' `
  (($iAsk -ge 0) -and ($iResolve -gt $iAsk) -and ($iStarting -gt $iAsk)) "ask=$iAsk resolve=$iResolve starting=$iStarting"
# The WHOLE statement, not the name: a position pin alone passes against `if (false && _svc.IsEngineStillClosing)`,
# which is how this check was first written and how it was caught (mutation L5).
Check 'and the guard is live: it refuses with the service''s message and returns' `
  ($padStart -match 'if \(_svc\.IsEngineStillClosing\) \{ Console\("err", ClarionDebuggerService\.EngineClosingMessage\); return; \}') ''

Write-Host ''
Write-Host 'the engine is reaped after "exited": given its grace, then stopped'
# A process that WILL linger far past the grace period, so a stop is certain to be needed.
$psi = New-Object System.Diagnostics.ProcessStartInfo 'ping.exe', '-n 30 127.0.0.1'
$psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardOutput = $true
$lingering = [System.Diagnostics.Process]::Start($psi)
$stopCalls = 0
try {
  $stop = [Func[bool]] { $script:stopCalls++; $lingering.Kill(); $lingering.WaitForExit(5000) }
  $reaped = [Lifecycle]::ReapLingeringEngine($lingering, 300, $stop)
  Check 'a lingering engine is stopped once its grace runs out' (($reaped -eq $true) -and ($stopCalls -eq 1)) "reaped=$reaped stops=$stopCalls"
  Check 'and it really is gone afterwards' ($lingering.HasExited) ''
} finally {
  if (-not $lingering.HasExited) { try { $lingering.Kill() } catch { } }
}
# CONTROL: an engine that exits on its own within its grace is left alone.
$psi2 = New-Object System.Diagnostics.ProcessStartInfo 'cmd.exe', '/c exit 0'
$psi2.UseShellExecute = $false; $psi2.CreateNoWindow = $true
$quick = [System.Diagnostics.Process]::Start($psi2)
$stopCalls2 = 0
$reaped2 = [Lifecycle]::ReapLingeringEngine($quick, 10000, [Func[bool]] { $script:stopCalls2++; $true })
Check 'CONTROL: an engine that exits within its grace is not stopped' (($reaped2 -eq $false) -and ($stopCalls2 -eq 0)) "reaped=$reaped2 stops=$stopCalls2"

Write-Host ''
Write-Host 'an OLD engine''s late "exited" or Exited cannot end or reap a NEW session (0449e5c9, pipeline run 1)'
# THE RACE: the engine writes "exited" and dies; its Process.Exited sets Idle before the buffered line is
# read; the user presses Start and a NEW engine becomes _proc; THEN the old line is handled. The first version
# captured `_proc` there - the NEW engine - reaped it, and killed the new session 1.5s later.
#
# DETERMINISTIC: the two handlers are compiled out of the service and driven with REAL processes in exactly
# that order. The old engine has already exited (or, second case, is still lingering); the new one is a 30s
# ping, so "it survived the grace period" cannot be timing luck. TWO SUBSTITUTIONS: the probe's ReapGraceMs is
# 300 instead of the shipped 1500, so the run is short (the shipped value is pinned separately); and the two
# ?.Invoke event raises go through probe helpers, for Windows PowerShell 5.1's C# 5 compiler.
$reportedExitSrc = ((Get-Method 'private void OnEngineReportedExit(Process source)') -replace '^private void', 'public void') -replace 'LogReceived\?\.Invoke\(', 'RaiseLog('
$processExitedSrc = ((Get-Method 'private void OnEngineProcessExited(Process source)') -replace '^private void', 'public void') -replace 'Exited\?\.Invoke\(', 'RaiseExited('
$raceSrc = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
namespace Race {
$(Get-Method 'public enum DebugSessionState')
$(Get-Method 'public enum ThreadSelectionCause')
public sealed class RaceProbe {
  public Process _proc;
  public List<DebugSessionState> States = new List<DebugSessionState>();
  public DebugSessionState State = DebugSessionState.Launching;
  public int ExitedRaised = -999;
  public string CurrentVa = "0x1";
  public object _attachTarget;   // the attach target (3f2d747f) both handlers clear; not what this race is about
  public event Action<string> LogReceived;
  public event Action<int> Exited;
  public RaceProbe() { Exited += c => ExitedRaised = c; LogReceived += s => { }; }
  private void SetState(DebugSessionState s) { State = s; States.Add(s); }
  internal const int ReapGraceMs = 300;
  $((Get-Method 'internal static bool ReapLingeringEngine(Process engine, int graceMs, Func<bool> stop)') -replace 'internal static', 'public static')
  $((Get-Method 'internal static bool KillEngine(Process engine)') -replace 'internal static', 'public static')
  $reportedExitSrc
  $processExitedSrc
  // Windows PowerShell 5.1's Add-Type compiles C# 5, which has no ?. - so the two event raises above are
  // routed through these. The substitution is textual and names the same events; nothing else is edited.
  private void RaiseLog(string s) { var h = LogReceived; if (h != null) h(s); }
  private void RaiseExited(int c) { var h = Exited; if (h != null) h(c); }
  // Both handlers end the host's thread selection (49538b78 8b); tools/test-addin-selection.ps1 runs that.
  public int SelectionEnds;
  private void MoveSelection(uint? tid, uint? stoppedTid, ThreadSelectionCause cause, bool onlyIfChanged) { SelectionEnds++; }
}
}
"@
Add-Type -TypeDefinition $raceSrc -Language CSharp | Out-Null

function Start-Lingering { $s = New-Object System.Diagnostics.ProcessStartInfo 'ping.exe', '-n 30 127.0.0.1'
  $s.UseShellExecute = $false; $s.CreateNoWindow = $true; $s.RedirectStandardOutput = $true; [System.Diagnostics.Process]::Start($s) }
function Start-Exited { $s = New-Object System.Diagnostics.ProcessStartInfo 'cmd.exe', '/c exit 0'
  $s.UseShellExecute = $false; $s.CreateNoWindow = $true; $p = [System.Diagnostics.Process]::Start($s); [void]$p.WaitForExit(10000); $p }
$spawned = New-Object System.Collections.ArrayList
try {
  # 1. Diana's sequence exactly: old engine already dead, new one launched, THEN the old "exited" line.
  $old = Start-Exited; $new = Start-Lingering; [void]$spawned.Add($new)
  $rp = New-Object Race.RaceProbe; $rp._proc = $new
  $rp.OnEngineReportedExit($old)
  Start-Sleep -Milliseconds 1200          # four times the probe's grace
  Check 'the NEW engine survives the old engine''s late "exited" past the grace period' (-not $new.HasExited) ''
  Check 'and the new session is not forced Idle' (($rp.States.Count -eq 0) -and ($rp.State -eq [Race.DebugSessionState]::Launching)) "states: $($rp.States -join ',')"

  # 2. The old engine is STILL alive when its line arrives: it, and only it, is reaped.
  $old2 = Start-Lingering; $new2 = Start-Lingering; [void]$spawned.Add($old2); [void]$spawned.Add($new2)
  $rp2 = New-Object Race.RaceProbe; $rp2._proc = $new2
  $rp2.OnEngineReportedExit($old2)
  [void]$old2.WaitForExit(5000)
  Check 'a still-lingering OLD engine is reaped' ($old2.HasExited) ''
  Check 'and the new one is untouched' (-not $new2.HasExited) ''

  # 3. CONTROL: the CURRENT engine's own "exited" still ends the session at once, and still reaps it.
  $cur = Start-Lingering; [void]$spawned.Add($cur)
  $rp3 = New-Object Race.RaceProbe; $rp3._proc = $cur
  $rp3.OnEngineReportedExit($cur)
  Check 'CONTROL: the current engine''s "exited" sets Idle at once' ($rp3.State -eq [Race.DebugSessionState]::Idle) "$($rp3.State)"
  [void]$cur.WaitForExit(5000)
  Check 'CONTROL: and a current engine that lingers is reaped' ($cur.HasExited) ''

  # 4. The pre-existing LOW: an old engine's late Process.Exited cannot end the new session either.
  $rp4 = New-Object Race.RaceProbe; $rp4._proc = $new
  $rp4.OnEngineProcessExited($old)
  Check 'an OLD engine''s Process.Exited neither sets Idle nor raises Exited' `
    (($rp4.States.Count -eq 0) -and ($rp4.ExitedRaised -eq -999)) "states: $($rp4.States -join ','); exited=$($rp4.ExitedRaised)"
  $rp5 = New-Object Race.RaceProbe; $rp5._proc = $old
  $rp5.OnEngineProcessExited($old)
  Check 'CONTROL: the current engine''s Process.Exited sets Idle and raises Exited with its code' `
    (($rp5.State -eq [Race.DebugSessionState]::Idle) -and ($rp5.ExitedRaised -eq 0)) "state=$($rp5.State) exited=$($rp5.ExitedRaised)"
} finally {
  foreach ($p in $spawned) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
}

# Wiring: every handler Launch attaches is bound to ITS process, and the "exited" arm hands over the source.
$launchCode = Get-CSharpCodeOnly (Get-Method 'private void Launch(string targetExe, string args, bool interactive, AttachableProcess attachTo)')
Check 'Launch binds output and Exited to the process it created, not to _proc' `
  (($launchCode -match 'OnLine\(p, e\.Data\)') -and ($launchCode -match 'p\.Exited \+= \(s, e\) => OnEngineProcessExited\(p\)') -and `
   ($launchCode -notmatch '_proc\.(ExitCode|OutputDataReceived|Exited)')) ''
$exitedAt = $svc.IndexOf('case "exited":')
$exitedArm = if ($exitedAt -ge 0) { Get-CSharpCodeOnly ($svc.Substring($exitedAt, $svc.IndexOf('break;', $exitedAt) - $exitedAt)) } else { '' }
Check 'the "exited" arm hands the SOURCE process to its handler' ($exitedArm -match 'OnEngineReportedExit\(source\)') ''
$reportedExit = Get-CSharpCodeOnly (Get-Method 'private void OnEngineReportedExit(Process source)')
Check 'the reap runs off the reader thread and kills the source, never via Stop()' `
  (($reportedExit -match 'Task\.Run\(') -and ($reportedExit -match 'KillEngine\(source\)') -and ($reportedExit -notmatch 'Stop\(\)')) ''
Check 'the shipped grace is 1500ms (the probe above uses 300)' ($svc -match 'internal const int ReapGraceMs = 1500;') ''

Assert-CheckTotal 28
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
