# Shared machinery for the interactive engine harnesses (test-interactive.ps1, test-watch-threaded.ps1).
#
# Both launch `ClarionDbg break <target> --interactive --json`, pump its stdout through a synchronized
# sink, and wait for a "paused" event. test-watch-threaded.ps1 used to carry its own compressed copy of
# all of that - Wait-Paused as a single ~600 character line, with Drain's body spelled out again inside
# it - which is how the two drifted apart (337b3222 item 10). One copy lives here now.
#
# The session also learns the DEBUGGEE's pid from the engine's own output, so a harness can poke and
# clean up the process THIS RUN started rather than every process that happens to share its name
# (337b3222 item 9).
#
#   . "$PSScriptRoot\engine-session.ps1"

# The state bag, separable from the launch so the pump can be exercised with a fake sink and no engine
# (see test-engine-session.ps1). Cursor lives in here because PowerShell functions cannot share a
# caller's `$script:` variable across a dot-sourced file boundary without surprises.
function New-EngineSessionState {
    param($Proc, $Sink, $Handlers = @(), [string]$Target)
    $name = $null
    if ($Target) { $name = [IO.Path]::GetFileNameWithoutExtension($Target) }
    return @{
        Proc       = $Proc
        Sink       = $Sink
        Handlers   = @($Handlers)
        Cursor     = 0
        Target     = $Target
        TargetName = $name
        TargetPid  = $null
        # Captured BEFORE the engine starts, so it is always earlier than the debuggee's own start time.
        # That ordering is what makes the pid-reuse check below meaningful.
        StartedAt  = (Get-Date)
    }
}

function New-EngineSession {
    param(
        [Parameter(Mandatory = $true)][string]$Engine,
        [Parameter(Mandatory = $true)][string]$Target,
        [string]$BreakArgs = '',
        [string]$WorkingDirectory = '',
        [switch]$CaptureStdErr
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Engine
    $psi.Arguments = "break `"$Target`" $BreakArgs --interactive --json"
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    # filled from the OutputDataReceived event, which runs on a threadpool thread
    $sink = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $handlers = @()
    $handlers += Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -MessageData $sink -Action {
        if ($EventArgs.Data -ne $null) { [void]$Event.MessageData.Add($EventArgs.Data) }
    }
    if ($CaptureStdErr) {
        $handlers += Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -MessageData $sink -Action {
            if ($EventArgs.Data -ne $null) { [void]$Event.MessageData.Add('STDERR: ' + $EventArgs.Data) }
        }
    }

    $session = New-EngineSessionState -Proc $proc -Sink $sink -Handlers $handlers -Target $Target
    [void]$proc.Start()
    $proc.BeginOutputReadLine()
    if ($CaptureStdErr) { $proc.BeginErrorReadLine() }
    return $session
}

# Every line that has arrived since the last call, in order. Also records the debuggee pid the first
# time the engine names it - the engine prints it twice, as JSON and in its plain startup line, and
# either will do.
function Read-EngineLines {
    param($Session)
    $out = @()
    while ($Session.Cursor -lt $Session.Sink.Count) {
        $line = $Session.Sink[$Session.Cursor]
        $Session.Cursor++
        if ($null -eq $Session.TargetPid -and $null -ne $line) {
            # -cmatch: a WIRE spelling, case-sensitive JSON (09207c17). Same rule as Wait-EnginePaused below.
            if ($line -cmatch '"event":"loaded"[^}]*"pid":\s*(\d+)') { $Session.TargetPid = [int]$matches[1] }
            elseif ($line -match '^launched\s+\S+\s+\(pid\s+(\d+)\)') { $Session.TargetPid = [int]$matches[1] }
        }
        $out += $line
    }
    return , $out
}

# Wait for the engine to report a stop. $OnLine sees every line (each harness prints and parses it its
# own way); $EachTick runs once per poll, which is where the menu poking hangs.
function Wait-EnginePaused {
    param($Session, [int]$TimeoutSec, [scriptblock]$OnLine, [scriptblock]$EachTick)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        foreach ($line in (Read-EngineLines $Session)) {
            if ($OnLine) { & $OnLine $line }
            # -cmatch, not -match (09207c17): these are WIRE event names, which the pad switches on exactly.
            # -match is case-insensitive, so it would report a stop for "event":"Paused" that the pad ignores.
            if ($line -cmatch '"event":"paused"') { return $true }
            if ($line -cmatch '"event":"exited"') { return $false }
        }
        if ($Session.Proc -and $Session.Proc.HasExited -and $Session.Cursor -ge $Session.Sink.Count) { return $false }
        if ($EachTick) { & $EachTick }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

# The debuggee, found by the pid the ENGINE reported and never by name.
#
# `Get-Process <basename>` returns EVERY process sharing that name, so the old lookup could poke - and
# the old cleanup could KILL - a copy of the example app a developer had opened by hand on their own
# machine. Returns $null when this run has no pid to point at, and the callers treat that as "signal
# nothing": doing nothing is the correct answer to "which of these is mine?", guessing is not.
function Get-EngineTargetProcess {
    param($Session)
    if ($null -eq $Session.TargetPid) { return $null }
    $p = Get-Process -Id $Session.TargetPid -ErrorAction SilentlyContinue
    if (-not $p) { return $null }
    # Windows recycles pids. A pid that now belongs to a process with a different name, or to one that
    # was already running before this session started, is not the process this run launched.
    if ($Session.TargetName -and $p.ProcessName -ne $Session.TargetName) { return $null }
    # Failing to READ the start time is an IDENTITY FAILURE, and it is refused EXPLICITLY.
    #
    # A .NET property getter that throws does NOT raise a catchable error from PowerShell - in both editions,
    # and whatever $ErrorActionPreference is set to, the read simply answers $null (a protected process such
    # as pid 4 reads exactly this way). So the `catch { }` that used to sit here never fired, and what
    # actually rejected such a process was `$null -lt <date>` happening to evaluate True. The right answer by
    # accident: nothing in the file said that was the mechanism, and a change to -ge, or to comparing .Ticks,
    # would have turned it into "return the process" with no test and no comment objecting.
    #
    # Both shapes are now refused in their own right, and fail CLOSED, because Stop-EngineTarget is what this
    # answer arms: not killing a stray debuggee is a nuisance, killing a developer's unrelated process is
    # data loss.
    $started = $null
    try { $started = $p.StartTime } catch { return $null }
    if ($null -eq $started) { return $null }
    if ($started -lt $Session.StartedAt) { return $null }
    return $p
}

# The pid a harness may SIGNAL, re-verified at the moment of use, or $null when the target cannot be
# verified right now.
#
# EnumWindows keyed on a bare pid reaches whatever process owns that pid AT THAT INSTANT. If the debuggee
# exits and Windows recycles its pid between one poke and the next, a harness posting WM_COMMAND or WM_NULL
# by the pid the engine once reported is posting into an unrelated GUI process - the same "a pid is not an
# identity" defect as the old cleanup, on the signalling side rather than the killing side. So the rule lives
# here, next to Stop-EngineTarget's copy of it, and a poke site calls this IMMEDIATELY before it pokes rather
# than caching an answer.
function Get-EngineTargetPid {
    param($Session)
    $p = Get-EngineTargetProcess $Session
    if ($null -eq $p) { return $null }
    return [int]$p.Id
}

function Stop-EngineSession {
    param($Session, [int]$QuitWaitMs = 8000)
    try { $Session.Proc.StandardInput.WriteLine('quit') } catch { }
    [void]$Session.Proc.WaitForExit($QuitWaitMs)
    if (-not $Session.Proc.HasExited) {
        $Session.Proc.Kill()
        Write-Host '!! engine force-killed'
    }
}

# Kill the debuggee this run started, if it outlived the engine. Scoped to the one verified pid.
function Stop-EngineTarget {
    param($Session)
    $p = Get-EngineTargetProcess $Session
    if ($p) {
        Write-Host "!! killing leftover $($p.ProcessName) pid $($p.Id)"
        try { $p.Kill() } catch { }
        return
    }
    if ($null -eq $Session.TargetPid) {
        Write-Host '## the engine never reported a debuggee pid — leaving any stray process alone'
    }
}

function Remove-EngineSession {
    param($Session)
    foreach ($h in $Session.Handlers) {
        if ($h) { Unregister-Event -SourceIdentifier $h.Name -ErrorAction SilentlyContinue }
    }
}
