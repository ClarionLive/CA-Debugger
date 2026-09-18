# Regression rig for 465a3873 -- a TRACEPOINT over a THREADed (.cwtls) name, hit REPEATEDLY WITHOUT
# PAUSING, then resumed and hit again.
#
# Why a tracepoint and not a conditional breakpoint: a tracepoint NEVER pauses (DebugEngine.BpAdvanced.cs
# logs and returns false), so every hit takes the DBG_CONTINUE path out of OnUserBp that never reaches
# PausedWait. That is the exact path the old code could not read .cwtls data on, and the exact path a
# cached instance base would go stale across. It also LOGS the value it read on each hit, so the test can
# see what the engine actually resolved instead of inferring it from whether a stop happened.
#
# A single-hit test passes while the stale-cache defect is fully present, so the run is deliberately
# structured as: many hits -> explicit pause -> watch (cross-check) -> resume -> many more hits.
#
# The launch, the output pump and the cleanup come from engine-session.ps1, shared with
# test-interactive.ps1 and test-watch-threaded.ps1. This file used to carry its own copy, and the copy got
# the cleanup wrong in the way a copy does: it killed whatever `Get-Process -Id $targetPid` returned, with
# no check of the process NAME or of its start time. A pid is not an identity -- Windows recycles them --
# so if the debuggee exited before the finally block ran, that killed an unrelated developer process. The
# shared Get-EngineTargetProcess verifies pid AND name AND "started after this session did" in one place
# (337b3222 item 9); Stop-EngineTarget is the only thing here that signals the debuggee.
#
#   e.g. tools\test-bp-threaded.ps1
#        tools\test-bp-threaded.ps1 -Name AUT:AU_LNAME -MenuItem "2/5" -Verbose2
param(
    [string]$Engine    = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
    [string]$Target    = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe",
    # clbrws001.clw:561 is the first line of BRW1::FillQueue, which runs once per row the browse displays.
    [string]$BpSite    = "clbrws001.clw:561",
    [string]$Name      = "AUT:AU_LNAME",
    [string]$MenuItem  = "2/5",            # Browse > Filtered Locator (Authors)
    [int]$OpenWaitSec  = 5,                # settle time after each browse open
    # Each open fills the browse once (one BRW1::FillQueue per row) AND runs it on a NEW Clarion thread,
    # so repeating the open is what turns "a few hits" into "hit many times without pausing" across
    # SEVERAL threads -- which is the case a single-hit, single-thread test cannot tell from the bug.
    [int]$OpensPerLeg  = 4,
    [int]$PauseTimeoutSec = 30,
    # Optional CONDITION leg. The condition gate runs BEFORE the tracepoint (ShouldPauseAtBp order:
    # condition -> hit count -> trace), so a trace that fires proves the condition was SATISFIED, and the
    # value it interpolates must be the one the condition selected for. That makes the two halves of this
    # ticket check each other. It is also the sharpest before/after available: an engine that cannot read
    # a THREADed name returns indeterminate from the gate, which PAUSES ("could not be evaluated") on the
    # very first hit -- so the old engine stops dead here where the fixed one never stops at all.
    [string]$Condition = "",
    [string]$Expect    = "",               # the value every fired trace must show (defaults to the RHS)
    [string]$LogFile   = "",
    [switch]$Verbose2                      # echo every engine line, not just the interesting ones
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\engine-session.ps1"

Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class Poke {
 [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr GetSubMenu(IntPtr m,int p);
 [DllImport("user32.dll")] public static extern uint GetMenuItemID(IntPtr m,int p);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h,uint msg,IntPtr w,IntPtr l);
 public delegate bool EnumProc(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 // pid is the one the ENGINE reported, so this can only ever reach the process under test.
 public static string Menu(int pid,string path){ string res=null; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var m=GetMenu(h); if(m==IntPtr.Zero) return true; var ps=path.Split('/'); var sm=GetSubMenu(m,int.Parse(ps[0])); uint id = sm==IntPtr.Zero?0:GetMenuItemID(sm,int.Parse(ps[1])); if(id!=0){ PostMessage(h,0x111,(IntPtr)id,IntPtr.Zero); res="WM_COMMAND id="+id+" hwnd=0x"+h.ToString("X"); return false;} return true; },IntPtr.Zero); return res; }
 public static int Wake(int pid){ int n=0; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p==pid && IsWindowVisible(h)){ PostMessage(h,0,IntPtr.Zero,IntPtr.Zero); n++; } return true; },IntPtr.Zero); return n; }
}
"@

function B64([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# The tracepoint message. {NAME} is what 465a3873 is about; the literal marker lets the test tell a
# rendered token from an unrendered one without guessing at the value.
$traceMsg = "TP name=$Name value=[{$Name}]"
$bpArg    = "$BpSite|t=" + (B64 $traceMsg)
if ($Condition) {
    $bpArg = "$BpSite|c=" + (B64 $Condition) + "|t=" + (B64 $traceMsg)
    if (-not $Expect) {
        # default: the quoted RHS of "LHS = 'RHS'"
        if ($Condition -match "=\s*'([^']*)'") { $Expect = $matches[1] }
    }
}

Write-Host "engine : $Engine"
Write-Host "target : $Target"
Write-Host "bp     : $bpArg"
Write-Host "trace  : $traceMsg"
Write-Host ""

$session = New-EngineSession -Engine $Engine -Target $Target -BreakArgs "--bp `"$bpArg`"" `
                             -WorkingDirectory (Split-Path $Target) -CaptureStdErr
$proc = $session.Proc

# --- collected evidence -------------------------------------------------------------------------
# The debuggee pid is learned by Read-EngineLines, from the engine's own output, and read back off the
# session. Nothing here derives it from a process name.
$script:announcedPid = $false
$script:events    = New-Object System.Collections.ArrayList   # ordered: @{Kind;Value;HitCount;Raw}
$script:watchLine = $null

function TargetPid { if ($null -eq $session.TargetPid) { 0 } else { [int]$session.TargetPid } }

function Note([string]$l) {
    if (-not $script:announcedPid -and $null -ne $session.TargetPid) {
        $script:announcedPid = $true
        Write-Host "## target pid = $($session.TargetPid) (from the engine, not by name)"
    }
    if ($l -match '"event":"trace"') {
        $v = if ($l -match 'value=\[([^\]]*)\]') { $matches[1] } else { '<unparsed>' }
        $hc = if ($l -match '"hitCount":(\d+)') { [int]$matches[1] } else { -1 }
        [void]$script:events.Add(@{ Kind='trace'; Value=$v; HitCount=$hc; Raw=$l })
    }
    elseif ($l -match '"event":"paused"')  { [void]$script:events.Add(@{ Kind='paused';  Raw=$l }) }
    elseif ($l -match '"event":"exited"')  { [void]$script:events.Add(@{ Kind='exited';  Raw=$l }) }
    elseif ($l -match '"event":"watch"' -and $l -match [regex]::Escape($Name)) { $script:watchLine = $l; [void]$script:events.Add(@{ Kind='watch'; Raw=$l }) }
}

function Show([string]$l) {
    if ($null -eq $l) { return }
    if ($Verbose2) { if ($l.Length -gt 400) { Write-Host ($l.Substring(0,400) + '...[trunc]') } else { Write-Host $l } }
    elseif ($l -match '"event":"(trace|paused|watch|bp-error|error)"') { if ($l.Length -gt 300) { Write-Host ($l.Substring(0,300)+'...') } else { Write-Host $l } }
    elseif ($l -match '^\s+threaded ') { Write-Host $l }   # NoteThreadedEmulation diagnostics
}

function Drain {
    foreach ($l in (Read-EngineLines $session)) { Note $l; Show $l }
}

function Run-For([int]$sec, [string]$what) {
    Write-Host "--- $what ($sec s) ---"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $sec) { Drain; if ($proc.HasExited) { return }; Start-Sleep -Milliseconds 150 }
    Drain
}

# The stop wait is the shared one: it pumps through the same Read-EngineLines, so a line cannot be
# consumed by one waiter and missed by the other. Note/Show still see every line.
function Wait-Paused([int]$t) {
    return (Wait-EnginePaused $session $t -OnLine { param($l) Note $l; Show $l })
}

function Poke-Menu([string]$path) {
    if ((TargetPid) -eq 0) { Write-Host "!! no target pid yet -- cannot poke"; return }
    for ($i = 0; $i -lt 40; $i++) {
        $r = [Poke]::Menu((TargetPid), $path)
        if ($r) { Write-Host "## menu $path -> $r"; return }
        Drain; Start-Sleep -Milliseconds 250
    }
    Write-Host "!! menu $path never posted"
}

function Run-Leg([string]$label) {
    for ($k = 1; $k -le $OpensPerLeg; $k++) {
        Poke-Menu $MenuItem
        Run-For $OpenWaitSec ("{0}: open {1}/{2}" -f $label, $k, $OpensPerLeg)
    }
}

try {
    # let the app come up and report its pid
    Run-For 4 "startup"

    # LEG 1 -- hits with no pause anywhere.
    $leg1Start = $script:events.Count
    Run-Leg "LEG 1: tracepoint hits, target never paused"
    $leg1End = $script:events.Count

    # explicit stop, cross-check the same name through the Watch path, then resume
    Write-Host ">>> pause"
    $proc.StandardInput.WriteLine("pause")
    $paused = Wait-Paused $PauseTimeoutSec
    if ($paused) {
        Write-Host ">>> watch $Name"
        $proc.StandardInput.WriteLine("watch $Name")
        Run-For 3 "watch reply"
        Write-Host ">>> continue"
        $proc.StandardInput.WriteLine("continue")
        Start-Sleep -Milliseconds 800; Drain
    } else { Write-Host "!! never paused" }

    # LEG 2 -- hits AFTER a stop and a resume. Anything cached at hit time in leg 1 is now a resume old.
    $leg2Start = $script:events.Count
    [void][Poke]::Wake((TargetPid))
    Run-For 2 "LEG 2: settling after the resume"
    Run-Leg "LEG 2: more tracepoint hits, after a pause and a resume"
    $leg2End = $script:events.Count
}
finally {
    Stop-EngineSession $session
    Start-Sleep -Milliseconds 400; Drain
    # The ONLY thing here that signals the debuggee: pid AND name AND started-after-this-session, checked
    # in one shared place. A recycled pid is not this run's target and is left alone.
    Stop-EngineTarget $session
    Remove-EngineSession $session
    if ($LogFile) { [IO.File]::WriteAllLines($LogFile, [string[]]$session.Sink.ToArray()) }
}

# --- verdict ------------------------------------------------------------------------------------
function Slice([int]$a, [int]$b) { if ($b -le $a) { return @() } ; return @($script:events[$a..($b-1)]) }
$leg1 = @(Slice $leg1Start $leg1End)
$leg2 = @(Slice $leg2Start $leg2End)
$t1 = @($leg1 | Where-Object { $_.Kind -eq 'trace' })
$t2 = @($leg2 | Where-Object { $_.Kind -eq 'trace' })
$v1 = @($t1 | ForEach-Object { $_.Value } | Sort-Object -Unique)
$v2 = @($t2 | ForEach-Object { $_.Value } | Sort-Object -Unique)
$unrendered = @(@($t1) + @($t2) | Where-Object { $_.Value -like '{?*' })

Write-Host ""
Write-Host "================ RESULT ================"
Write-Host ("leg 1 hits (no pause) : {0}   distinct values: {1}" -f $t1.Count, $v1.Count)
Write-Host ("leg 2 hits (post-resume): {0} distinct values: {1}" -f $t2.Count, $v2.Count)
Write-Host ("leg 1 values : " + (($v1 | Select-Object -First 8) -join ' | '))
Write-Host ("leg 2 values : " + (($v2 | Select-Object -First 8) -join ' | '))
Write-Host ("watch reply  : " + $(if ($script:watchLine) { $script:watchLine } else { '<none>' }))

$checks = @()
# The name under test must really BE threaded, or every other check below is vacuous.
$checks += @{ N="A the name is THREADed (watch says threaded:true)"; Ok = ($script:watchLine -ne $null -and $script:watchLine -match '"threaded":true') }
$checks += @{ N="B leg 1 hit the tracepoint many times, no pause (>= 8)"; Ok = ($t1.Count -ge 8) }
$checks += @{ N="C leg 1 took the NON-pausing path (no paused event among the hits)"; Ok = (@($leg1 | Where-Object { $_.Kind -eq 'paused' }).Count -eq 0) }
$checks += @{ N="D no hit rendered the name as {?...}";              Ok = ($unrendered.Count -eq 0) }
$checks += @{ N="E leg 1 read LIVE data (>= 2 distinct values)";     Ok = ($v1.Count -ge 2) }
$checks += @{ N="F the tracepoint still fired after pause+resume (>= 8)"; Ok = ($t2.Count -ge 8) }
$checks += @{ N="G leg 2 read LIVE data too (>= 2 distinct values)"; Ok = ($v2.Count -ge 2) }
if ($Condition) {
    $allT  = @(@($t1) + @($t2))
    $wrong = @($allT | Where-Object { $_.Value -ne $Expect })
    # E and G assert MORE than one value, which is true of an unconditional tracepoint and false of a
    # conditional one, so a condition leg replaces them rather than adding to them.
    $checks = @($checks | Where-Object { $_.N -notmatch '^(E|G) ' })
    $checks += @{ N="H the condition was satisfied at least once (a trace fired)"; Ok = ($allT.Count -ge 1) }
    $checks += @{ N="I every fired trace shows the value the condition selected ('$Expect')"; Ok = ($allT.Count -ge 1 -and $wrong.Count -eq 0) }
    if ($wrong.Count -gt 0) { Write-Host ("!! {0} trace(s) fired with a value the condition should have rejected: {1}" -f $wrong.Count, (($wrong | ForEach-Object { $_.Value } | Sort-Object -Unique) -join ' | ')) }
}

$fail = 0
foreach ($c in $checks) { $tag = if ($c.Ok) { "PASS" } else { "FAIL"; }; if (-not $c.Ok) { $fail++ }; Write-Host ("  [{0}] {1}" -f $(if($c.Ok){"PASS"}else{"FAIL"}), $c.N) }
Write-Host "========================================"
if ($fail -eq 0) { Write-Host "ALL CHECKS PASSED"; exit 0 } else { Write-Host "$fail CHECK(S) FAILED"; exit 1 }
