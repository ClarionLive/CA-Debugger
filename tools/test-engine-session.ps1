# Checks the shared harness machinery in engine-session.ps1 WITHOUT an engine, a debuggee or Clarion.
#
# The two interactive harnesses can only be run by hand against a real target, so the parts of them
# that are easy to get quietly wrong - which pid gets signalled, and whether the output pump loses or
# repeats a line - had no coverage at all. This drives those parts against a fake sink.
#
#   pwsh -File tools\test-engine-session.ps1
# Exit code 0 = all checks passed.
. "$PSScriptRoot\engine-session.ps1"
# Check / ShowVal / Invoke-CheckSection / Assert-CheckTotal. lib-check.ps1 DIRECTLY and not lib-extract.ps1:
# this suite scans PowerShell, not C#, so it has nothing to extract - and lib-extract imposes
# Set-StrictMode on its callers, under which this file throws (see EXPECTED_CHECKS below).
. "$PSScriptRoot\lib-check.ps1"

# A session with no process behind it: a plain list stands in for the synchronized sink the real
# OutputDataReceived handler fills.
function New-FakeSession([string]$target = 'C:\apps\clbrws.exe') {
    $sink = New-Object System.Collections.ArrayList
    return (New-EngineSessionState -Proc $null -Sink $sink -Target $target)
}
function Emit($session, [string]$line) { [void]$session.Sink.Add($line) }

Invoke-CheckSection '1) the pump returns each line exactly once' {
    $s = New-FakeSession
    Emit $s 'one'; Emit $s 'two'
    $first = Read-EngineLines $s
    Check 'both queued lines come back' ($first.Count -eq 2 -and $first[0] -eq 'one' -and $first[1] -eq 'two') ($first -join '|')
    $second = Read-EngineLines $s
    Check 'and a second call returns nothing, rather than repeating them' ($second.Count -eq 0) ($second -join '|')
    Emit $s 'three'
    $third = Read-EngineLines $s
    Check 'a line arriving later is picked up' ($third.Count -eq 1 -and $third[0] -eq 'three') ($third -join '|')
}

Invoke-CheckSection '2) the debuggee pid is learned from the engine''s own output' {
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
}

Invoke-CheckSection '3) Wait-EnginePaused reports the stop, the exit, and the timeout' {
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

    # CASE IS PART OF THE TOKEN (09207c17). The pad switches on "paused" exactly, so a line the pad would
    # not treat as a stop must not be one here either. Pins the -cmatch in Wait-EnginePaused: with -match
    # this line is a stop, and every check above still passes.
    $sCase = New-FakeSession
    Emit $sCase '@JSON {"event":"Paused","ebp":"0x18FF00","va":"0x847A76"}'
    Check 'a case-drifted "Paused" is not a stop' (-not (Wait-EnginePaused $sCase 1))

    $s3 = New-FakeSession
    $script:tickCount = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = Wait-EnginePaused $s3 1 -EachTick { $script:tickCount++ }
    Check 'silence times out rather than hanging' (-not $timedOut)
    Check 'and it actually waited the timeout' ($sw.Elapsed.TotalSeconds -ge 0.9) $sw.Elapsed.TotalSeconds
    Check 'EachTick ran while it waited' ($script:tickCount -gt 1) $script:tickCount
}

Invoke-CheckSection '4) the target process is identified by pid, never by name (337b3222 item 9)' {
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
}

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
Invoke-CheckSection '4b) a start time that cannot be READ is an identity failure, not a detail to skip' {
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
}

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
Invoke-CheckSection '5) every harness that launches the engine cleans up THROUGH this lifecycle' {
    # One parse per file, shared by both scans below. A file that will not parse is NOT "a file with no
    # Get-Process call" and NOT "a file that is not a harness" - those are the two silent passes this
    # section exists to prevent - so it fails closed and says which file and why.
    function Get-Ast([string]$path) {
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tok, [ref]$err)
        if ($err.Count) {
            throw ("the harness scan cannot read $(Split-Path -Leaf $path): " +
                   "$($err[0].Message) (line $($err[0].Extent.StartLineNumber))")
        }
        return $ast
    }

    function Get-CalledCommands([string]$path) {
        $calls = (Get-Ast $path).FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        return @($calls | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    }

    # WHICH files are harnesses is decided by the parser too, for the reason given three lines above the
    # opening brace. Until wave 2 this line read `(Get-Content -Raw) -match 'ClarionDbg\.exe'` - a text
    # match sitting directly under the comment that rejects text matches. It classified correctly only by
    # luck, twice over: engine-session.ps1 happens to write "ClarionDbg break" with no extension, and the
    # regex literal itself carried a backslash that kept the line from matching its own file. Neither is a
    # property anyone editing these files would know they had to preserve.
    #
    # A harness NAMES the engine binary in CODE - a string literal, which in all three is the $Engine
    # parameter's default. A comment is not a string literal, so the same mention that must not count as a
    # Get-Process CALL does not count as launching the engine either.
    $ENGINE_BINARY = 'ClarionDbg.exe'
    function Test-NamesEngineBinary([string]$path) {
        $strings = (Get-Ast $path).FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
        }, $true)
        foreach ($s in $strings) { if ($s.Value -like "*$ENGINE_BINARY*") { return $true } }
        return $false
    }

    # THIS file is the single exclusion, and it is by name because the reason is particular to it: it holds
    # the binary's name in $ENGINE_BINARY, and writes it again in the probe harness below, in order to go
    # looking for it. engine-session.ps1 gets NO exemption - it passes the classifier on its own merits,
    # which is asserted as a rule further down rather than left as the accident it used to be.
    $self = Split-Path -Leaf $PSCommandPath
    $all = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Sort-Object Name)
    Check 'every .ps1 here parses, so nothing is classified by failing to be read' `
        ($self.Length -gt 0 -and @($all | Where-Object { $null -ne (Get-Ast $_.FullName) }).Count -eq $all.Count) `
        "$($all.Count) file(s)"
    $harnesses = @($all | Where-Object { $_.Name -ne $self -and (Test-NamesEngineBinary $_.FullName) })
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

    # CONTROL: the harness CLASSIFIER has to fire on something, or "exactly 3" is a count of nothing and a
    # fourth harness escapes every check in this loop silently. A brand-new one, written to a temp directory
    # so the scan above is untouched, is what proves it would be caught.
    $probeDir = Join-Path ([System.IO.Path]::GetTempPath()) ('harness-detect-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
    try {
        $newHarness = Join-Path $probeDir 'test-brand-new.ps1'
        Set-Content -LiteralPath $newHarness -Encoding ASCII -Value @(
            'param([string]$Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe")'
            '. "$PSScriptRoot\engine-session.ps1"'
            '$s = New-EngineSession $Engine'
            'try { Start-Sleep -Milliseconds 1 } finally { Stop-EngineTarget $s }'
        )
        Check 'CONTROL: a newly added harness IS detected, by the engine path in its param default' `
            (Test-NamesEngineBinary $newHarness)

        # ...and this is what the retired text match got wrong. It called a file that merely TALKS about the
        # binary a harness, and would then have demanded it dot-source the library and call Stop-EngineTarget.
        $mention = Join-Path $probeDir 'test-mentions-only.ps1'
        Set-Content -LiteralPath $mention -Encoding ASCII -Value @(
            '# Explains at length why it must never go near ClarionDbg.exe, and then does not.'
            'Write-Host ''launches nothing'''
        )
        Check 'CONTROL: ...and a file naming the engine only in a COMMENT is not a harness' `
            (-not (Test-NamesEngineBinary $mention))

        # The shared library is IN the scan and stays out of the harness list on its own merits, not on an
        # exemption: it names the engine in prose only. Pinned as a rule because it used to be an accident -
        # "ClarionDbg break" with no extension was the only thing keeping it out of the old text match. If it
        # ever names the binary in code this fails, which is the moment to decide what the library is.
        $lib = Join-Path $PSScriptRoot 'engine-session.ps1'
        Check 'the shared library needs no exemption: it names the engine in prose, not in code' `
            (((Get-Content -Raw -LiteralPath $lib) -match 'ClarionDbg') -and -not (Test-NamesEngineBinary $lib))
    } finally {
        Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue
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
}

# EnumWindows keyed on a bare pid posts WM_COMMAND / WM_NULL to every visible window that pid owns AT THAT
# INSTANT. Commit a29b613 removed the bare-pid KILL path but left the poke sites resolving nothing: if the
# debuggee exited and Windows recycled its pid, the harness typed into an unrelated developer's GUI.
#
# Section 5's rule is about resolving a pid to a PROCESS. This one is about the pid a harness hands to a
# window poke, which is a different thing to get wrong and was got wrong separately.
Invoke-CheckSection '6) a POKE is a signal too, so it goes through the same identity check' {
    $hasResolver = $null -ne (Get-Command Get-EngineTargetPid -ErrorAction SilentlyContinue)
    Check 'Get-EngineTargetPid exists as the one shared answer to "which pid may I signal?"' $hasResolver
    if ($hasResolver) {
        $me = Get-Process -Id $PID
        $s = New-FakeSession
        Check 'with no pid reported there is no pid to signal' ($null -eq (Get-EngineTargetPid $s))

        $s.TargetPid = $PID
        $s.TargetName = $me.ProcessName
        $s.StartedAt = $me.StartTime.AddSeconds(-1)
        Check 'a verified target answers with its pid, as an int' `
            ((Get-EngineTargetPid $s) -eq $PID -and (Get-EngineTargetPid $s) -is [int]) (Get-EngineTargetPid $s)

        # It must refuse for EVERY reason Get-EngineTargetProcess refuses, or a poke site would be verifying
        # less than the cleanup does.
        $s.TargetName = 'something-else'
        Check 'a recycled pid now holding a different name is not signallable' ($null -eq (Get-EngineTargetPid $s))
        $s.TargetName = $me.ProcessName
        $s.StartedAt = $me.StartTime.AddSeconds(60)
        Check 'a process older than the session is not signallable' ($null -eq (Get-EngineTargetPid $s))
        $s.StartedAt = $me.StartTime.AddSeconds(-1)
        $s.TargetPid = 999999
        Check 'a pid nothing is using is not signallable' ($null -eq (Get-EngineTargetPid $s))
    } else {
        # Pointed at a copy of engine-session.ps1 that predates the resolver. Say so and go on to the
        # structural scan, which is the half that reports on the harnesses' own poke sites.
        Write-Host '  ....  behavioural checks skipped: this engine-session.ps1 has no Get-EngineTargetPid'
    }

    # ---- and every poke site in every harness goes through it ----------------------------------------
    # The pid argument of a window poke must be a variable this file assigned from the shared resolver, not a
    # pid expression. Read through the PARSER: these are method invocations, not commands, so section 5's
    # command scan cannot see them at all.
    #
    # TWO KNOWN BLIND SPOTS, so the site COUNT below is the real anchor rather than this scan:
    #   1. Get-ResolvedPidVars matches the ASSIGNMENT text, not dataflow. A variable assigned from the
    #      resolver and later RE-assigned from a bare pid still passes.
    #   2. $POKE_METHODS is a fixed name list. A future [Poke]::Click would be invisible to this scan.
    # Both are caught by the asserted number of poke sites failing, not by the scan noticing the new shape —
    # which is why that count is asserted as an exact number and must be updated deliberately.
    $POKE_METHODS = @('Menu', 'Wake', 'Poke')
    function Get-PokePidArgs([string]$path) {
        $tok = $null; $err = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tok, [ref]$err)
        if ($err.Count) { return @('<unparseable>') }
        $calls = $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $POKE_METHODS -contains $n.Member.Value
        }, $true)
        return @($calls | ForEach-Object {
            if ($_.Arguments -and $_.Arguments.Count -ge 1) { $_.Arguments[0].Extent.Text } else { '<no arguments>' }
        })
    }
    # Which variables in a file hold a resolver's answer. $x = Get-EngineTargetPid ... or Get-EngineTargetProcess ...
    function Get-ResolvedPidVars([string]$text) {
        return @([regex]::Matches($text, '\$(\w+)\s*=\s*\(?\s*Get-EngineTarget(?:Pid|Process)\b') |
                 ForEach-Object { $_.Groups[1].Value })
    }
    # A poke argument is acceptable as $var or $var.Id, where $var came from a resolver in the same file.
    function Test-PokeArg([string]$arg, [string[]]$vars) {
        if ($arg -notmatch '^\$(\w+)(\.Id)?$') { return $false }
        return ($vars -contains $matches[1])
    }

    $pokers = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Sort-Object Name |
                # @() around the call: a ONE-element result unrolls to a scalar, and `.Count` on a scalar
                # is a convenience PowerShell withdraws under Set-StrictMode 3.0+. The count was right
                # either way, so this is an idiom fix, not a behaviour fix - but it was the only thing
                # making this file unloadable alongside a strict library (see tools/lib-check.ps1).
                Where-Object { @(Get-PokePidArgs $_.FullName).Count -gt 0 })
    # A number, not "every": a harness that grows a third poke site says so here.
    $allArgs = @($pokers | ForEach-Object { Get-PokePidArgs $_.FullName })
    Check 'exactly 4 window-poke sites across the harnesses, in 2 files' `
        ($allArgs.Count -eq 4 -and $pokers.Count -eq 2) `
        (($pokers.Name) -join ', ')

    foreach ($f in $pokers) {
        $text = Get-Content -Raw -LiteralPath $f.FullName
        $vars = Get-ResolvedPidVars $text
        foreach ($arg in (Get-PokePidArgs $f.FullName)) {
            Check "$($f.Name): the poke pid $arg comes from the shared resolver" (Test-PokeArg $arg $vars) `
                ("resolved-pid variables in this file: " + (($vars | ForEach-Object { '$' + $_ }) -join ', '))
        }
    }

    # CONTROL: the detector is worth nothing if it cannot see the shape this section exists to ban. The
    # pre-fix line is the fixture, so this fails the day the detector stops firing on it.
    $banned = Join-Path ([IO.Path]::GetTempPath()) ('poke-detector-' + [Guid]::NewGuid().ToString('N') + '.ps1')
    Set-Content -LiteralPath $banned -Encoding ASCII -Value @(
        'function TargetPid { 42 }',
        '$r = [Poke]::Menu((TargetPid), $path)',
        '[void][Poke]::Wake((TargetPid))'
    )
    try {
        $bannedArgs = Get-PokePidArgs $banned
        $bannedVars = Get-ResolvedPidVars (Get-Content -Raw -LiteralPath $banned)
        Check 'CONTROL: the detector finds both poke sites in the pre-fix shape' ($bannedArgs.Count -eq 2) `
            ($bannedArgs -join ', ')
        Check 'CONTROL: ...and rejects a bare pid expression as the poke argument' `
            (@($bannedArgs | Where-Object { Test-PokeArg $_ $bannedVars }).Count -eq 0) ($bannedArgs -join ', ')
        # ...and it accepts the resolved shape, so it is not simply rejecting everything.
        Check 'CONTROL: ...and accepts a pid that came from the resolver' `
            ((Test-PokeArg '$pokePid' @('pokePid')) -and (Test-PokeArg '$cp.Id' @('cp')))
    } finally { Remove-Item -LiteralPath $banned -Force -ErrorAction SilentlyContinue }
}

# THE SECTION RUNNER MUST NOT SHADOW ITS CALLER. PowerShell scoping is dynamic, so a section body sees
# Invoke-CheckSection's own locals ahead of the script's variables of the same name - found 2026-09-22 when
# test-bp-threaded.ps1's -Name read as the section's heading. Every name the runner uses internally is set
# here at SCRIPT scope, and the section must read the script's values back.
$script:Name = 'caller Name'; $script:Body = 'caller Body'; $script:before = 'caller before'
$script:returned = 'caller returned'; $script:err = 'caller err'
$script:sectionName = 'caller sectionName'; $script:sectionBody = 'caller sectionBody'
Invoke-CheckSection '7) a section reads its CALLER''s variables, never the section runner''s own' {
    $seen = "$Name|$Body|$before|$returned|$err|$sectionName|$sectionBody"
    Check 'every runner-internal name reads the script''s value inside a section' `
        ($seen -ceq 'caller Name|caller Body|caller before|caller returned|caller err|caller sectionName|caller sectionBody') $seen
}
Remove-Variable -Scope Script -Name Name, Body, before, returned, err, sectionName, sectionBody

# (b) THE BACKSTOP, in lib-check.ps1's terms. (a) - Invoke-CheckSection turning a thrown section into a
# failed check - is what actually closes ticket cb9324f2 and needs nothing maintained. This catches the
# remaining case (a) cannot: a section that returns EARLY without throwing raises nothing to catch, and
# its checks simply never happen. Update the number deliberately when adding or removing a check.
#
# It is also why this suite states a NUMBER rather than "all": before this, a section that died took its
# checks with it and the run still printed a success summary and exited 0 - 42 checks reported instead of
# 56, with nothing comparing the two.
$EXPECTED_CHECKS = 58
Assert-CheckTotal $EXPECTED_CHECKS

# $script:checks, NOT a value snapshotted before the line above. It used to be captured first, so a clean
# run printed "ALL 56 CHECKS PASSED" while 57 had run - the assertion does not count itself for the
# COMPARISON, but it is still a check, and it is still reported. A suite whose subject is silently missing
# checks should not mis-state its own count by one.
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
