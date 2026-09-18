# Checks the shared harness machinery in engine-session.ps1 WITHOUT an engine, a debuggee or Clarion.
#
# The two interactive harnesses can only be run by hand against a real target, so the parts of them
# that are easy to get quietly wrong - which pid gets signalled, and whether the output pump loses or
# repeats a line - had no coverage at all. This drives those parts against a fake sink.
#
#   pwsh -File tools\test-engine-session.ps1
# Exit code 0 = all checks passed.
. "$PSScriptRoot\engine-session.ps1"

$script:fails = 0
$script:checks = 0
function Check([string]$label, [bool]$cond, $detail) {
    $script:checks++
    if ($cond) { Write-Host "  PASS  $label" }
    else { $script:fails++; Write-Host "  FAIL  $label$(if ($null -ne $detail) { '  ->  ' + $detail })" }
}

# A session with no process behind it: a plain list stands in for the synchronized sink the real
# OutputDataReceived handler fills.
function New-FakeSession([string]$target = 'C:\apps\clbrws.exe') {
    $sink = New-Object System.Collections.ArrayList
    return (New-EngineSessionState -Proc $null -Sink $sink -Target $target)
}
function Emit($session, [string]$line) { [void]$session.Sink.Add($line) }

Write-Host '1) the pump returns each line exactly once'
{
    $s = New-FakeSession
    Emit $s 'one'; Emit $s 'two'
    $first = Read-EngineLines $s
    Check 'both queued lines come back' ($first.Count -eq 2 -and $first[0] -eq 'one' -and $first[1] -eq 'two') ($first -join '|')
    $second = Read-EngineLines $s
    Check 'and a second call returns nothing, rather than repeating them' ($second.Count -eq 0) ($second -join '|')
    Emit $s 'three'
    $third = Read-EngineLines $s
    Check 'a line arriving later is picked up' ($third.Count -eq 1 -and $third[0] -eq 'three') ($third -join '|')
}.Invoke()

Write-Host '2) the debuggee pid is learned from the engine''s own output'
{
    $s = New-FakeSession
    Check 'no pid before the engine has said anything' ($null -eq $s.TargetPid) $s.TargetPid
    [void](Read-EngineLines $s)
    Emit $s '@JSON {"event":"loaded","pid":4242,"loadBase":"0x400000"}'
    [void](Read-EngineLines $s)
    Check 'the loaded event names it' ($s.TargetPid -eq 4242) $s.TargetPid

    $s2 = New-FakeSession
    Emit $s2 'launched clbrws.exe (pid 777); 1 breakpoint(s)'
    [void](Read-EngineLines $s2)
    Check 'the plain startup line names it too' ($s2.TargetPid -eq 777) $s2.TargetPid

    # a later line must not move the target: the FIRST pid is the process this run created
    Emit $s2 '@JSON {"event":"loaded","pid":999,"loadBase":"0x400000"}'
    [void](Read-EngineLines $s2)
    Check 'a later pid does not replace it' ($s2.TargetPid -eq 777) $s2.TargetPid
}.Invoke()

Write-Host '3) Wait-EnginePaused reports the stop, the exit, and the timeout'
{
    $s = New-FakeSession
    Emit $s 'noise'
    Emit $s '@JSON {"event":"paused","ebp":"0x18FF00","va":"0x847A76"}'
    $seen = New-Object System.Collections.ArrayList
    $ok = Wait-EnginePaused $s 5 -OnLine { param($l) [void]$seen.Add($l) }
    Check 'a paused event is a stop' $ok
    Check 'every line up to it reached OnLine' ($seen.Count -eq 2) ($seen.Count)

    $s2 = New-FakeSession
    Emit $s2 '@JSON {"event":"exited","code":0}'
    Check 'an exited event is not a stop' (-not (Wait-EnginePaused $s2 5))

    $s3 = New-FakeSession
    $script:tickCount = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = Wait-EnginePaused $s3 1 -EachTick { $script:tickCount++ }
    Check 'silence times out rather than hanging' (-not $timedOut)
    Check 'and it actually waited the timeout' ($sw.Elapsed.TotalSeconds -ge 0.9) $sw.Elapsed.TotalSeconds
    Check 'EachTick ran while it waited' ($script:tickCount -gt 1) $script:tickCount
}.Invoke()

Write-Host '4) the target process is identified by pid, never by name (337b3222 item 9)'
{
    # The live PowerShell process stands in for a debuggee: a real pid, with a real name and start time.
    $me = Get-Process -Id $PID
    $s = New-FakeSession
    Check 'with no pid reported, there is no target to signal' ($null -eq (Get-EngineTargetProcess $s))

    # pid + name + start time all agree -> this is ours
    $s.TargetPid = $PID
    $s.TargetName = $me.ProcessName
    $s.StartedAt = $me.StartTime.AddSeconds(-1)
    Check 'a pid whose name and start time agree is the target' ($null -ne (Get-EngineTargetProcess $s))

    # the pid-reuse guards: either one failing means the pid is no longer ours
    $s.TargetName = 'something-else'
    Check 'a pid now holding a DIFFERENT process name is not the target' ($null -eq (Get-EngineTargetProcess $s))

    $s.TargetName = $me.ProcessName
    $s.StartedAt = $me.StartTime.AddSeconds(60)
    Check 'a pid belonging to a process older than the session is not the target' ($null -eq (Get-EngineTargetProcess $s))

    # a pid nothing is using at all
    $s.StartedAt = $me.StartTime.AddSeconds(-1)
    $s.TargetPid = 999999
    Check 'a pid that no longer exists is not the target' ($null -eq (Get-EngineTargetProcess $s))
}.Invoke()

Write-Host ''
if ($script:fails) { Write-Host "$($script:fails) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
