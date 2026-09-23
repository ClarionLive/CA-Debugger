# LIVE: set next statement (task a77abd94) against clbrws.exe's SplashScreen.
#
# What only a live run can show, and protocolcheck cannot (ProtocolCheck.SetIp.cs covers the decision, the
# ACCEPT-region finder and the wire shapes over hand-built inputs):
#   - a successful setip really moves EIP, and re-announces the stop as `paused` reason "setip" at the new line;
#   - a Step after a setip starts from the NEW line (the pause loop's locals were recomputed, risk 6);
#   - THE RE-ARM HANDOVER (risk 5): from a breakpoint stop at line 44, setip onto line 45, which carries its
#     own breakpoint. The engine keeps ONE re-arm per thread; without the handover the origin breakpoint at 44
#     is never re-planted and silently stops firing, so the next continue stops at 45. With it, at 44.
#     Measured 2026-09-23: disabling the handover turned that stop into "breakpoint line=45";
#   - the refusals a real image produces: ACCEPT boundary both ways, the entry record, a ROUTINE, a line
#     with no code, another module, bad arguments, and a Pause stop that is not on a statement.
#
# SplashScreen (clbrws026.clw, exe line numbering): 8 is the entry record, 33/34 run before the ACCEPT, 43 is
# the ACCEPT itself, 44..88 are its body (88 is the back-edge line), 89 follows the loop, 92 is in the
# PrepareProcedure ROUTINE. The splash loops on a 1 s timer, so line 44 is reached again after a continue.
param(
    [string]$Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
    [string]$Target = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe",
    [int]$TimeoutSec = 20
)
. "$PSScriptRoot\engine-session.ps1"
. "$PSScriptRoot\lib-check.ps1"

$session = New-EngineSession -Engine $Engine -Target $Target `
    -BreakArgs '--bp clbrws026.clw:34 --bp clbrws026.clw:44 --bp clbrws026.clw:45' -WorkingDirectory (Split-Path $Target)

# The next paused / setip event, in arrival order. Read-EngineLines hands over EVERYTHING that has arrived, and
# a successful setip writes its reply and the re-announced `paused` back to back, so the events are queued:
# returning on the first one and dropping the rest of the batch loses the `paused` (measured 2026-09-23).
$script:pending = New-Object System.Collections.Queue
function Wait-Event {
    param([string]$Kind)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        foreach ($l in (Read-EngineLines $session)) {
            if ($l -cmatch '^@JSON .*"event":"(paused|setip|exited)"') {
                Write-Host "    $l"
                $script:pending.Enqueue((($l -replace '^@JSON ', '') | ConvertFrom-Json))
            }
        }
        while ($script:pending.Count) {
            $j = $script:pending.Dequeue()
            if ($j.event -eq $Kind -or $j.event -eq 'exited') { return $j }
        }
        if ($session.Proc.HasExited) { return $null }
        Start-Sleep -Milliseconds 50
    }
    return $null
}
function Send([string]$c) { Write-Host ">>> $c"; $session.Proc.StandardInput.WriteLine($c) }
function Show($j) { if ($null -eq $j) { '(no event)' } else { ($j | ConvertTo-Json -Compress -Depth 3) } }

# A setip that must be refused with $Code, leaving EIP where it was.
function Expect-Refusal([string]$Spec, [string]$Code) {
    Send "setip $Spec"
    $r = Wait-Event 'setip'
    Check "setip $Spec is refused as $Code, with a sentence for the user" `
        ($null -ne $r -and $r.ok -eq $false -and $r.reason -ceq $Code -and $r.error) (Show $r)
}

try {
    Invoke-CheckSection 'setip before the ACCEPT: re-run a line, then step from it' {
        $p = Wait-Event 'paused'
        Check 'stopped at the breakpoint on line 34' ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 34) (Show $p)
        $script:baseEsp = if ($p) { $p.regs.esp } else { $null }

        Send 'setip clbrws026.clw:33'
        $r = Wait-Event 'setip'
        Check 'setip to line 33 succeeds, from line 34' ($null -ne $r -and $r.ok -eq $true -and $r.line -eq 33 -and $r.fromLine -eq 34) (Show $r)
        $p = Wait-Event 'paused'
        Check 'the stop is re-announced as paused reason setip on line 33, ESP unchanged' `
            ($null -ne $p -and $p.reason -ceq 'setip' -and $p.line -eq 33 -and $p.exact -eq $true -and $p.regs.esp -eq $script:baseEsp) (Show $p)

        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step after the setip stops at line 34 (it started from the NEW line)' ($null -ne $p -and $p.reason -eq 'step' -and $p.line -eq 34) (Show $p)
    }

    Invoke-CheckSection 'refusals from a statement stop before the ACCEPT' {
        Expect-Refusal 'clbrws026.clw:44' 'accept-boundary'   # into the loop
        Expect-Refusal 'clbrws026.clw:8' 'prologue'           # the entry record
        Expect-Refusal 'clbrws026.clw:92' 'other-proc'        # a ROUTINE of this procedure
        Expect-Refusal 'clbrws026.clw:9999' 'no-code'
        Expect-Refusal 'nosuch.clw:3' 'other-module'
        Expect-Refusal 'garbage' 'bad-args'
    }

    Invoke-CheckSection 'the re-arm handover: setip from one breakpoint onto another' {
        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'continue reaches the breakpoint on line 44, inside the ACCEPT' ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 44) (Show $p)

        Send 'setip clbrws026.clw:45'
        $r = Wait-Event 'setip'
        Check 'setip 44 -> 45 inside one ACCEPT succeeds' ($null -ne $r -and $r.ok -eq $true -and $r.line -eq 45) (Show $r)
        [void](Wait-Event 'paused')

        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'the next continue stops at the ORIGIN breakpoint, line 44: it was re-planted' `
            ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 44) (Show $p)

        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'and the target breakpoint, line 45, still fires too' ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 45) (Show $p)
    }

    Invoke-CheckSection 'inside the ACCEPT: stay in, never leave' {
        Send 'setip clbrws026.clw:88'
        $r = Wait-Event 'setip'
        Check 'setip to the back-edge line 88, inside the same loop, succeeds' ($null -ne $r -and $r.ok -eq $true -and $r.line -eq 88) (Show $r)
        [void](Wait-Event 'paused')
        Expect-Refusal 'clbrws026.clw:89' 'accept-boundary'   # past the loop end: what a BREAK would do
        Expect-Refusal 'clbrws026.clw:34' 'accept-boundary'   # back out to before the ACCEPT
    }

    Invoke-CheckSection 'a Pause stop is not on a statement' {
        Send 'bp del clbrws026.clw:44'
        Send 'bp del clbrws026.clw:45'
        Send 'continue'
        Start-Sleep -Milliseconds 800
        Send 'pause'
        $p = Wait-Event 'paused'
        Check 'pause stops the target' ($null -ne $p -and $p.reason -eq 'pause') (Show $p)
        Expect-Refusal 'clbrws026.clw:34' 'not-on-statement'
    }
}
finally {
    Stop-EngineSession $session
    Start-Sleep -Milliseconds 500
    Stop-EngineTarget $session
    Remove-EngineSession $session
}

# 4 + 6 + 4 + 3 + 2, measured on a clean run 2026-09-23.
$EXPECTED_CHECKS = 19
Assert-CheckTotal $EXPECTED_CHECKS
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
