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

Write-Host '4b) a start time that cannot be READ is an identity failure, not a detail to skip'
# ISOLATED on purpose. In section 4 the StartTime guard sits behind the name check and in front of its own
# comparison, so a SWALLOWED read failure hides between them: pid and name still agreed, and the helper
# returned the process. Everything below agrees except that the start time cannot be read.
#
# Get-Process is shadowed for the length of this block only - no real process can be made to fail a
# StartTime read on demand - and the CONTROLS are what say the shadow is in effect and that nothing else
# about the stand-in is why it gets rejected.
#
# WHAT THIS DOES AND DOES NOT PROVE, said plainly. It passes against the version that swallowed the read
# failure in a catch block, because that catch was DEAD: a .NET getter that throws does not raise a catchable
# error from PowerShell in either edition - the read answers $null - so what rejected the process was
# `$null -lt <date>` evaluating True. This case pins the OUTCOME so that it is no longer an accident of null
# coercion; it fails against a helper that swallows the failure and returns the process, which is what the
# guard is there to prevent. Run under both $ErrorActionPreference values because the helper is dot-sourced
# into whatever the harness has set (test-bp-threaded.ps1 sets 'Stop') and neither may behave differently.
{
    if (-not ('FakeStartTimeProc' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
// The shape Get-EngineTargetProcess reads off a process, with a StartTime that can be made unreadable the
// way the real one is when the process is protected or has already exited.
public class FakeStartTimeProc {
    public int Id { get; set; }
    public string ProcessName { get; set; }
    public bool Readable { get; set; }
    public DateTime Started { get; set; }
    public DateTime StartTime {
        get {
            if (!Readable) throw new System.ComponentModel.Win32Exception(5);   // Access is denied
            return Started;
        }
    }
}
'@
    }

    function Get-Process { param([int]$Id, $ErrorAction) return $script:fakeProc }

    $script:fakeProc = New-Object FakeStartTimeProc
    $script:fakeProc.Id = 4242
    $script:fakeProc.ProcessName = 'clbrws'
    $script:fakeProc.Started = (Get-Date)
    $script:fakeProc.Readable = $true

    $s = New-FakeSession                 # target C:\apps\clbrws.exe, so TargetName is 'clbrws'
    $s.TargetPid = 4242
    $s.StartedAt = (Get-Date).AddMinutes(-5)

    Check 'CONTROL: the stand-in IS accepted while its start time is readable' `
        ($null -ne (Get-EngineTargetProcess $s)) 'rejected - the shadowed lookup is not in effect'
    $s.TargetName = 'something-else'
    Check 'CONTROL: and it is still rejected on a name mismatch' ($null -eq (Get-EngineTargetProcess $s))
    $s.TargetName = 'clbrws'

    # THE RULE: now the ONLY thing wrong is that the start time cannot be read.
    $script:fakeProc.Readable = $false
    foreach ($eap in 'Continue', 'Stop') {
        $ErrorActionPreference = $eap
        $r = Get-EngineTargetProcess $s
        $ErrorActionPreference = 'Continue'
        Check "a process whose StartTime cannot be read is NOT the target (ErrorActionPreference $eap)" `
            ($null -eq $r) 'returned a process Stop-EngineTarget would then Kill()'
    }

    # ...and the guard is not simply rejecting everything now: readable again, accepted again.
    $script:fakeProc.Readable = $true
    Check 'CONTROL: a readable start time is accepted again afterwards' ($null -ne (Get-EngineTargetProcess $s))
}.Invoke()

Write-Host '5) every harness that launches the engine cleans up THROUGH this lifecycle'
# Section 4 proves the identity check is right. It says nothing about whether the harnesses use it, and a
# harness that resolves a pid itself gets no benefit from it: the third recorded instance of "a pid is not
# an identity" in this repo was a NEW harness doing `Get-Process -Id $targetPid; $p.Kill()` in its finally
# block, one wave after the same defect was fixed here.
#
# The harness list is SCANNED rather than typed out, so a harness added tomorrow is covered tomorrow and not
# whenever someone remembers to list it. A harness is a script that names the engine BINARY - the scan cannot
# key on the word "interactive" because this file contains it while launching nothing.
# Get-Process is detected through the PowerShell PARSER, not a text match: test-watch-threaded.ps1 mentions
# `Get-Process clbrws` in a comment explaining why it must not do that, and a comment is not a call.
{
    function Get-CalledCommands([string]$path) {
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tok, [ref]$err)
        if ($err.Count) { return @('<unparseable>') }
        $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        return @($calls | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    }

    $all = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Sort-Object Name)
    $harnesses = @($all | Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match 'ClarionDbg\.exe' })
    # A number, not "every": if a fourth harness appears this says so instead of quietly covering three.
    Check 'exactly 3 scripts here launch the engine binary' ($harnesses.Count -eq 3) (($harnesses.Name) -join ', ')

    foreach ($h in $harnesses) {
        $text = Get-Content -Raw -LiteralPath $h.FullName
        $cmds = Get-CalledCommands $h.FullName
        Check "$($h.Name) dot-sources engine-session.ps1" ($text -match 'engine-session\.ps1')
        Check "$($h.Name) launches through New-EngineSession" ($cmds -contains 'New-EngineSession')
        Check "$($h.Name) cleans the debuggee up through Stop-EngineTarget" ($cmds -contains 'Stop-EngineTarget')
        # THE RULE. Get-EngineTargetProcess is the one place a pid is turned into a process, because it is
        # the only place that also checks the name and the start time.
        Check "$($h.Name) never resolves a pid to a process itself" ($cmds -notcontains 'Get-Process') `
            (($cmds | Where-Object { $_ -eq 'Get-Process' }) -join ', ')
    }

    # CONTROL: the rule is worth nothing if the scan cannot see a violation. engine-session.ps1 is the one
    # file that MAY call Get-Process, so it doubles as proof that the detector fires at all.
    $own = Get-CalledCommands (Join-Path $PSScriptRoot 'engine-session.ps1')
    Check 'the detector does see a real Get-Process call (engine-session.ps1, the one place allowed)' `
        ($own -contains 'Get-Process')
    # ... and that it does NOT fire on the comment that merely names it.
    $watch = Join-Path $PSScriptRoot 'test-watch-threaded.ps1'
    Check 'and it does not fire on a comment that only mentions Get-Process' `
        (((Get-Content -Raw -LiteralPath $watch) -match 'Get-Process') -and ((Get-CalledCommands $watch) -notcontains 'Get-Process'))
}.Invoke()

Write-Host ''
if ($script:fails) { Write-Host "$($script:fails) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
