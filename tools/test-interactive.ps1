# Paced interactive smoke test for the Phase 2 engine.
# Launches ClarionDbg break --interactive, waits for the paused event, then issues
# step / stepover / stepout / continue with real delays, printing all output.
#
# The launch, the output pump and Wait-Paused come from engine-session.ps1, shared with
# test-watch-threaded.ps1 (337b3222 item 10).
param(
    [string]$Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
    [string]$Target = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe",
    [string]$BreakArgs = "--bp clbrws001.clw:11",
    [string[]]$Commands = @("step", "step", "stepover", "stepout", "quit"),
    [int]$PauseTimeoutSec = 20
)
. "$PSScriptRoot\engine-session.ps1"

$session = New-EngineSession -Engine $Engine -Target $Target -BreakArgs $BreakArgs

function Drain {
    foreach ($line in (Read-EngineLines $session)) { Write-Host $line }
}
function Wait-Paused([int]$timeoutSec) {
    return (Wait-EnginePaused $session $timeoutSec -OnLine { param($line) Write-Host $line })
}

if (-not (Wait-Paused $PauseTimeoutSec)) {
    Drain
    Write-Host "!! never paused (breakpoint not reached) — killing"
    Stop-EngineSession $session -QuitWaitMs 5000
    Stop-EngineTarget $session
    Remove-EngineSession $session
    exit 3
}

foreach ($cmd in $Commands) {
    Write-Host ">>> $cmd"
    $session.Proc.StandardInput.WriteLine($cmd)
    if ($cmd -eq "quit") { break }
    if ($cmd -in @("step", "stepover", "stepout", "continue")) {
        if (-not (Wait-Paused $PauseTimeoutSec)) {
            Drain
            Write-Host "!! did not pause again after '$cmd' — killing"
            try { $session.Proc.StandardInput.WriteLine("quit") } catch {}
            break
        }
    }
    else {
        Start-Sleep -Milliseconds 300
        Drain
    }
}

[void]$session.Proc.WaitForExit(10000)
if (-not $session.Proc.HasExited) { $session.Proc.Kill(); Write-Host "!! force-killed" }
Start-Sleep -Milliseconds 300
Drain
Write-Host "=== exit code: $($session.Proc.ExitCode) ==="
Stop-EngineTarget $session
Remove-EngineSession $session
