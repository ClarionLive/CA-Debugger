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

$launch = Get-CSharpCodeOnly (Get-Method 'private void Launch(string targetExe, string args, bool interactive)')
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

$exitedAt = $svc.IndexOf('case "exited":')
$exitedArm = if ($exitedAt -ge 0) { $svc.Substring($exitedAt, $svc.IndexOf('break;', $exitedAt) - $exitedAt) } else { '' }
$exitedArm = Get-CSharpCodeOnly $exitedArm
$iIdle = $exitedArm.IndexOf('SetState(DebugSessionState.Idle)')
$iReap = $exitedArm.IndexOf('ReapLingeringEngine(')
Check 'the "exited" arm goes Idle at once, then starts the reap' (($iIdle -ge 0) -and ($iReap -gt $iIdle)) "idle=$iIdle reap=$iReap"
Check 'the reap runs off the reader thread' ($exitedArm -match 'Task\.Run\(') ''
Check 'and stops only the engine it was started for, never a newer session''s' `
  ($exitedArm -match 'ReferenceEquals\(_proc, exitedEngine\) && Stop\(\)') ''

Assert-CheckTotal 19
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
