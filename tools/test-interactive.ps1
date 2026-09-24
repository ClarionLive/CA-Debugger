# Paced interactive smoke test for the Phase 2 engine.
# Launches ClarionDbg break --interactive, waits for the paused event, then issues
# step / stepover / stepout / continue with real delays, printing all output.
#
# The launch, the output pump and Wait-Paused come from engine-session.ps1, shared with
# test-watch-threaded.ps1 (337b3222 item 10).
param(
    [string]$Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
    [string]$Target = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe",
    # A STARTUP line, and that is the whole requirement: this suite runs unattended, so its breakpoint must
    # be one the target reaches on its own. The old default was clbrws001.clw:11, a DATA DECLARATION inside
    # BrowseAuthors, which only executes when a human clicks "Filtered Locator (Authors)" — so the run
    # always timed out at "never paused" and read as an engine or harness fault for as long as it sat red.
    # It was neither: Piper2 re-ran this suite unchanged against SPLASHSCREEN and got EXIT=0 in 4.7s with
    # step / step / stepover / stepout all working. clbrws026.clw:42 is the same line test-watch-threaded.ps1
    # already relies on, so the two suites stand or fall together on it.
    # NOT a skip. A skip would hide a suite that runs here perfectly well.
    [string]$BreakArgs = "--bp clbrws026.clw:42",
    [string[]]$Commands = @("step", "step", "stepover", "stepout", "quit"),
    [int]$PauseTimeoutSec = 20,
    # Run only the ACCEPT step-over case below (0f16e12c), skipping the paced smoke run.
    [switch]$AcceptOnly,
    [switch]$SkipAccept
)
. "$PSScriptRoot\engine-session.ps1"

# Step Over across ACCEPT's two event-loop calls (0f16e12c). clbrws026.clw is SplashScreen: line 42 is
# `DO PrepareProcedure`, 43 `ACCEPT`, 44 `CASE EVENT()` (the body's first statement), 88 the ACCEPT's `END`
# (the back-edge, `call [Cla$EndEventLoop]`), and the splash runs its loop with nobody at the keyboard.
#   - ACCEPT line: before the fix it never paused. Cla$StartEventLoop returns with ESP below its call site,
#     so the call-skip return read as a deeper frame and the step ran on.
#   - END line, with the loop going round: before the fix the step ran a whole pass and the breakpoint on 88
#     fired again. When the loop continues, EndEventLoop resumes at the loop head, not at its call site.
#     (A breakpoint straight on 88 reaches it before the splash's 1s timer closes the window: 6 of 6 runs
#     went round, 2026-09-24. If the loop exits instead, the stop is line 89 and the case fails loudly.)
# Each stepover must pause as a "step" on the line given; no stop, a step-limit stop or another line fails.
# Returns $null on a pass, or the reason it failed.
function Invoke-StepOverCase([string]$Bp, [int[]]$ExpectLines, [string]$Label) {
    $s = New-EngineSession -Engine $Engine -Target $Target -BreakArgs "--bp $Bp"
    # A hashtable, because $onLine runs in its own scope: assigning a plain variable there sets a local.
    $caseSeen = @{ Paused = $null }
    $onLine = { param($line) Write-Host $line; if ($line -cmatch '"event":"paused"') { $caseSeen.Paused = $line } }
    try {
        if (-not (Wait-EnginePaused $s $PauseTimeoutSec -OnLine $onLine)) { return "never reached $Bp" }
        foreach ($want in $ExpectLines) {
            Write-Host ">>> stepover ($Label, expecting line $want)"
            $caseSeen.Paused = $null
            $s.Proc.StandardInput.WriteLine('stepover')
            if (-not (Wait-EnginePaused $s $PauseTimeoutSec -OnLine $onLine)) { return "stepover expecting line $want never paused within ${PauseTimeoutSec}s" }
            $p = $caseSeen.Paused
            if ($p -notmatch '"reason":"step",') { return "stepover expecting line $want paused, but not as a step: $p" }
            if ($p -notmatch "`"line`":$want,") { return "stepover expecting line $want stopped elsewhere: $p" }
        }
        return $null
    }
    finally {
        Stop-EngineSession $s -QuitWaitMs 5000
        Stop-EngineTarget $s
        Remove-EngineSession $s
    }
}

# Both cases; returns the number that failed.
function Invoke-AcceptCases {
    $failed = 0
    foreach ($c in @(@{ Bp = 'clbrws026.clw:42'; Lines = @(43, 44); Label = 'ACCEPT line' },
                     @{ Bp = 'clbrws026.clw:88'; Lines = @(44);     Label = 'ACCEPT END, loop continues' })) {
        Write-Host ">>> case: $($c.Label)"
        $why = Invoke-StepOverCase $c.Bp $c.Lines $c.Label
        if ($why) { Write-Host "!! $($c.Label): $why"; $failed++ }
        else { Write-Host "== $($c.Label): stopped at line $($c.Lines[-1]) (step)" }
    }
    return $failed
}

if ($AcceptOnly) {
    $n = Invoke-AcceptCases
    Write-Host "=== exit code: $(if ($n) { 1 } else { 0 }) ==="
    exit $(if ($n) { 1 } else { 0 })
}

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
$exitCode = $session.Proc.ExitCode
Write-Host "== paced run: engine exit code $exitCode"
Stop-EngineTarget $session
Remove-EngineSession $session

if (-not $SkipAccept) {
    Write-Host '>>> ACCEPT step-over cases (0f16e12c)'
    if ((Invoke-AcceptCases) -and $exitCode -eq 0) { $exitCode = 1 }
}
Write-Host "=== exit code: $exitCode ==="
