# LIVE: set next statement (task a77abd94) against clbrws.exe's SplashScreen.
#
# What only a live run can show, and protocolcheck cannot (ProtocolCheck.SetIp.cs covers the decision, the
# ACCEPT-region finder, the call proof, the observation store and the wire shapes over hand-built inputs):
#   - a successful setip really moves EIP, and re-announces the stop as `paused` reason "setip" at the new line;
#   - a Step after a setip starts from the NEW line (the pause loop's locals were recomputed, risk 6);
#   - THE OBSERVED PATH (a77abd94 item 3): SplashScreen calls runtime entries whose stack effect was never
#     measured (Cla$pmopen, Cla$BEEP, ...), so its moves cannot be PROVEN (census 2026-09-23: 683 of 2003
#     clbrws symbols provable). A move BACK to a line this frame already stopped on, at the same ESP, is allowed
#     "via observed"; a move FORWARD to a line not yet reached is refused as stack-unproven;
#   - THE RE-ARM HANDOVER (risk 5): from a stop on armed line 35, setip back onto armed line 33. The engine keeps
#     ONE re-arm per thread; without the handover the origin breakpoint at 35 is never re-planted and silently
#     stops firing, so the continue that follows runs on to the ACCEPT's breakpoint at 44 instead of stopping at
#     35. (Measured 2026-09-23 on the earlier 44->45 form of this case: disabling the handover turned the stop
#     into the wrong line.)
#   - NO OBSERVATION SURVIVES A FREE RUN (item 4, pipeline run 2): after a continue, a move back to a line seen
#     on the previous ACCEPT pass - same frame, same steady ESP - refuses; so does one after a step-out, which
#     ends as a "step" stop and so is caught only by the resume rule at ArmResume;
#   - THE ACCEPT RULES BIND BOTH PATHS (item 4): into or out of the loop refuses as accept-boundary even where
#     the target was observed. The sibling-loops case (equal ESP ACROSS a boundary) cannot happen in
#     SplashScreen's single ACCEPT, so only protocolcheck's fixture covers it;
#   - the refusals a real image produces: the entry record, a ROUTINE, a line with no code, another module,
#     bad arguments, and a Pause stop that is not on a statement.
#
# SplashScreen (clbrws026.clw, exe line numbering): 8 is the entry record, 32..42 run before the ACCEPT, 43 is
# the ACCEPT itself, 44..88 are its body, 89 follows the loop, 92 is in the PrepareProcedure ROUTINE.
param(
    [string]$Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
    [string]$Target = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe",
    [int]$TimeoutSec = 20
)
. "$PSScriptRoot\engine-session.ps1"
. "$PSScriptRoot\lib-check.ps1"

$session = New-EngineSession -Engine $Engine -Target $Target `
    -BreakArgs '--bp clbrws026.clw:33 --bp clbrws026.clw:35 --bp clbrws026.clw:44' -WorkingDirectory (Split-Path $Target)

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
# A setip that must succeed via $Via, re-announced as paused reason setip on $Line.
function Expect-Move([string]$Spec, [int]$Line, [string]$Via) {
    Send "setip $Spec"
    $r = Wait-Event 'setip'
    Check "setip $Spec succeeds via $Via" ($null -ne $r -and $r.ok -eq $true -and $r.line -eq $Line -and $r.via -ceq $Via) (Show $r)
    $p = Wait-Event 'paused'
    Check "...and the stop is re-announced as paused reason setip on line $Line" `
        ($null -ne $p -and $p.reason -ceq 'setip' -and $p.line -eq $Line -and $p.exact -eq $true) (Show $p)
    return $p
}

try {
    Invoke-CheckSection 'observed: step forward, then go back to a line this frame stopped on' {
        $p = Wait-Event 'paused'
        Check 'stopped at the breakpoint on line 33' ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 33) (Show $p)
        $script:baseEsp = if ($p) { $p.regs.esp } else { $null }
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step reaches line 34' ($null -ne $p -and $p.reason -eq 'step' -and $p.line -eq 34) (Show $p)
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step reaches line 35 (it carries a breakpoint: the step stop restores its byte)' ($null -ne $p -and $p.line -eq 35) (Show $p)

        # The forward move first, while 36/37 have never been reached in this frame.
        Send 'setip clbrws026.clw:37'
        $r = Wait-Event 'setip'
        Check 'a FORWARD setip to line 37, never reached, is refused as stack-unproven and says to step there first' `
            ($null -ne $r -and $r.ok -eq $false -and $r.reason -ceq 'stack-unproven' -and $r.error -match 'Step to that line first') (Show $r)

        $p = Expect-Move 'clbrws026.clw:33' 33 'observed'
        Check 'ESP after the move back is the ESP line 33 had' ($null -ne $p -and $p.regs.esp -eq $script:baseEsp) (Show $p)
    }

    Invoke-CheckSection 'the re-arm handover: from armed line 35 back onto armed line 33' {
        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'continue stops at the ORIGIN breakpoint on line 35: it was re-planted (without the handover this runs to 44)' `
            ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 35) (Show $p)
    }

    Invoke-CheckSection 'a step after a setip starts from the new line' {
        # The continue above was a FREE RUN, so every observation before it is gone (a move back to 34 now
        # refuses). The breakpoint stop on 35 is a fresh observation; step on to 36 and come back to it.
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step from the breakpoint on 35 reaches line 36' ($null -ne $p -and $p.reason -eq 'step' -and $p.line -eq 36) (Show $p)
        [void](Expect-Move 'clbrws026.clw:35' 35 'observed')
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step after setip 36 -> 35 stops at line 36' ($null -ne $p -and $p.reason -eq 'step' -and $p.line -eq 36) (Show $p)
    }

    Invoke-CheckSection 'a step-out runs free, so it drops the observations too' {
        # Step on to line 42 (DO PrepareProcedure), into the routine, and out again. The step-out ends as a
        # "step" stop, so only the RESUME rule (ArmResume's first statement) can drop what was seen before it:
        # the routine ran at full speed and could have returned into anything. Line 42 was observed, at the
        # same ESP, in the same frame - and must still refuse.
        $script:reached42 = $false
        for ($i = 0; $i -lt 8 -and -not $script:reached42; $i++) {
            Send 'step'
            $p = Wait-Event 'paused'
            if ($null -ne $p -and $p.line -eq 42) { $script:reached42 = $true }
        }
        Check 'steps reach line 42 (DO PrepareProcedure)' $script:reached42 (Show $p)
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step goes INTO the PrepareProcedure routine' ($null -ne $p -and $p.proc -eq 'PREPAREPROCEDURE') (Show $p)
        Send 'stepout'
        $p = Wait-Event 'paused'
        Check 'step-out returns to SplashScreen' ($null -ne $p -and $p.proc -eq 'SPLASHSCREEN' -and $p.line -gt 42) (Show $p)
        Expect-Refusal 'clbrws026.clw:42' 'stack-unproven'
    }

    Invoke-CheckSection 'refusals from a statement stop before the ACCEPT' {
        Expect-Refusal 'clbrws026.clw:44' 'accept-boundary'   # into the loop: the ACCEPT rules bind both paths
        Expect-Refusal 'clbrws026.clw:8' 'prologue'           # the entry record
        Expect-Refusal 'clbrws026.clw:92' 'other-proc'        # a ROUTINE of this procedure
        Expect-Refusal 'clbrws026.clw:9999' 'no-code'
        Expect-Refusal 'nosuch.clw:3' 'other-module'
        Expect-Refusal 'garbage' 'bad-args'
    }

    Invoke-CheckSection 'inside the ACCEPT: back to an observed line, never out' {
        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'continue reaches the breakpoint on line 44, inside the ACCEPT' ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 44) (Show $p)
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step moves on inside the loop' ($null -ne $p -and $p.reason -eq 'step' -and $p.line -gt 44 -and $p.line -lt 89) (Show $p)
        [void](Expect-Move 'clbrws026.clw:44' 44 'observed')
        Expect-Refusal 'clbrws026.clw:89' 'accept-boundary'   # past the loop end (what a BREAK does)
        Expect-Refusal 'clbrws026.clw:34' 'accept-boundary'   # back out before the ACCEPT, although line 34 WAS observed

        # The TARGET side of the re-arm: line 44 is armed, and the setip above moved EIP onto it, so its byte
        # was restored and a re-plant scheduled for after it runs. The loop comes round again (the splash's
        # timer), so a continue must stop at 44's breakpoint once more. If the re-plant were lost, the loop
        # would run on without stopping there.
        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'continue from the setip target stops at ITS breakpoint, line 44, on the next pass: the target was re-planted' `
            ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 44) (Show $p)
    }

    Invoke-CheckSection 'no observation survives a free run' {
        # Now on a STEADY pass (the first pass runs deeper). Step 44 -> 45, then continue to the next pass's
        # breakpoint on 44: same frame, same EBP, same return address, and the same steady ESP, so line 45's
        # observation would match - but the thread ran FREE to get here, and the procedure could have returned
        # and been re-entered on the way. The continue must have dropped it.
        Send 'step'
        $p = Wait-Event 'paused'
        Check 'a step on the steady pass reaches line 45' ($null -ne $p -and $p.reason -eq 'step' -and $p.line -eq 45) (Show $p)
        $script:steadyEsp = if ($p) { $p.regs.esp } else { $null }
        Send 'continue'
        $p = Wait-Event 'paused'
        Check 'continue reaches line 44 on the next pass, at the same steady ESP' `
            ($null -ne $p -and $p.reason -eq 'breakpoint' -and $p.line -eq 44 -and $p.regs.esp -eq $script:steadyEsp) (Show $p)
        Expect-Refusal 'clbrws026.clw:45' 'stack-unproven'   # observed before the continue: no longer counts
    }

    Invoke-CheckSection 'a Pause stop is not on a statement' {
        Send 'bp del clbrws026.clw:33'
        Send 'bp del clbrws026.clw:35'
        Send 'bp del clbrws026.clw:44'
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

# 7 + 1 + 4 + 4 + 6 + 7 + 3 + 2, measured on a clean run 2026-09-23.
$EXPECTED_CHECKS = 34
Assert-CheckTotal $EXPECTED_CHECKS
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
