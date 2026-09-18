# Interactive engine harness for THREADed (.cwtls) data — the repro/regression rig for issue "table
# fields stuck on ...". Launches ClarionDbg break --interactive --json, optionally opens a browse by
# POSTING a menu command (Clarion menus are owner-drawn and carry no text, so -MenuItem takes a
# "topIndex/itemIndex" path), then feeds stdin commands and prints/logs every engine reply.
#
#   -Burst        send all commands at once (mimics the add-in's pause burst) instead of pacing them
#   -PrePauseSec  let the app run this long, then send `pause` — the break-all scenario
#   -MenuItem     "2/5" = 3rd menu, 6th item (clbrws Browse > Filtered Locator (Authors)).
#                 Comma-separate to open SEVERAL windows in order, e.g. "2/3,2/5" (Publishers then
#                 Authors) — each is posted once, spaced by -MenuGapMs, which is how the thread-selection
#                 work (task 0128a37e) gets a target with more than one Clarion thread to choose between.
#   -MenuGapMs    delay between successive -MenuItem posts (default 3000)
#   -LogFile      write every raw engine line here (console output is truncated for readability)
#   Pseudo-commands in -Commands: `wake` (post WM_NULL to the target's windows), `sleep <ms>`,
#                 `go` (resume WITHOUT waiting for the next stop) and `pause` (break in and wait for it).
#                 `go` + `pause` are how a scripted run reaches a SECOND stop, which is what proves the
#                 per-stop thread selection resets instead of surviving a resume.
#   Tokens usable in -Commands: {VA} {EBP} from the last pause, {WVA:NAME} = a watched name's instance VA,
#                 {TID:PROC} = the tid of the thread whose topmost Clarion frame is PROC, learned from the
#                 last `threads` reply (e.g. `thread {TID:MAIN}` switches to the frame thread). Thread ids
#                 change every run, so a scripted thread-selection test cannot hard-code one.
#
# The process launch, the output pump, Wait-Paused and the pid-scoped cleanup are shared with
# test-interactive.ps1 in engine-session.ps1 — this script used to carry its own compressed copy of all
# of them (337b3222 item 10).
#
# e.g. tools\test-watch-threaded.ps1 -BreakArgs "--bp clbrws001.clw:561" -MenuItem "2/5" `
#        -Commands @('watch AUT:AU_LNAME','watch AUTHORS$AUT:RECORD')
param(
    [string]$Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
    [string]$Target = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe",
    [string]$BreakArgs = "--bp clbrws026.clw:42",
    [string[]]$Commands = @("quit"),
    [int]$PauseTimeoutSec = 30,
    [int]$CmdWaitMs = 1500,
    [switch]$Burst,
    [string]$MenuItem = "",
    [int]$MenuGapMs = 3000,
    [int]$PrePauseSec = 0,
    [string]$LogFile = ""
)
. "$PSScriptRoot\engine-session.ps1"

Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class MenuPoke {
 [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
 [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr m);
 [DllImport("user32.dll")] public static extern IntPtr GetSubMenu(IntPtr m,int p);
 [DllImport("user32.dll")] public static extern uint GetMenuItemID(IntPtr m,int p);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetMenuString(IntPtr m,uint id,StringBuilder sb,int max,uint flags);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h,uint msg,IntPtr w,IntPtr l);
 public delegate bool EnumProc(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 static uint Find(IntPtr m,string text){ int n=GetMenuItemCount(m); for(int i=0;i<n;i++){ var sb=new StringBuilder(256); GetMenuString(m,(uint)i,sb,256,0x400); var sub=GetSubMenu(m,i); if(sub!=IntPtr.Zero){ uint r=Find(sub,text); if(r!=0) return r; } else if(sb.ToString().Replace("&","").StartsWith(text)) return GetMenuItemID(m,i); } return 0; }
 public static int Wake(int pid){ int n=0; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p==pid && IsWindowVisible(h)){ PostMessage(h,0,IntPtr.Zero,IntPtr.Zero); n++; } return true; },IntPtr.Zero); return n; }
 public static string Poke(int pid,string text){ string res=null; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var m=GetMenu(h); if(m==IntPtr.Zero) return true; uint id; if(text.Contains("/")){ var ps=text.Split('/'); var sm=GetSubMenu(m,int.Parse(ps[0])); id= sm==IntPtr.Zero?0:GetMenuItemID(sm,int.Parse(ps[1])); } else id=Find(m,text); if(id!=0){ PostMessage(h,0x111,(IntPtr)id,IntPtr.Zero); res="posted WM_COMMAND id="+id+" hwnd=0x"+h.ToString("X"); return false;} return true; },IntPtr.Zero); return res; }
}
"@

# -MenuItem is a QUEUE: each entry is posted once, in order, with $MenuGapMs between posts. A single
# entry behaves exactly as before ($script:pending empties after the first successful post).
$script:pending = @()
if ($MenuItem) { $script:pending = @($MenuItem.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$script:nextPokeAt = [DateTime]::MinValue
$script:wva = @{}
$script:tidByProc = @{}
$script:ebp = $null
$script:va = $null

# Post the next queued menu item, if one is due and the debuggee is up. Called on every poll tick, so
# it must be cheap and must not block. The window it pokes belongs to the pid the ENGINE reported —
# never to whatever `Get-Process clbrws` happened to return first (337b3222 item 9).
function Try-Poke {
    if ($script:pending.Count -eq 0) { return }
    if ([DateTime]::UtcNow -lt $script:nextPokeAt) { return }
    $cp = Get-EngineTargetProcess $script:session
    if (-not $cp) { return }

    $item = $script:pending[0]
    $result = [MenuPoke]::Poke($cp.Id, $item)
    if (-not $result) { return }

    Write-Host "## $item -> $result"
    $script:pending = @($script:pending | Select-Object -Skip 1)
    $script:nextPokeAt = [DateTime]::UtcNow.AddMilliseconds($MenuGapMs)
}

# Remember the facts later commands substitute into: a watched name's instance VA, and the tid whose
# topmost Clarion frame is a given procedure.
function Note-Line([string]$line) {
    if ($line -match '"event":"watch","name":"([^"]+)".*?"va":"(0x[0-9A-F]+)"') {
        $script:wva[$matches[1]] = $matches[2]
    }
    if ($line -match '"event":"threads"') {
        foreach ($m in [regex]::Matches($line, '"tid":(\d+),"clarionThread":[^,]+,"proc":"([^"]+)"')) {
            $script:tidByProc[$m.Groups[2].Value] = $m.Groups[1].Value
        }
    }
}

# One line, noted and printed. Console output is truncated for readability; -LogFile keeps it whole.
function Show-Line([string]$line) {
    Note-Line $line
    if ($line.Length -gt 600) { Write-Host ($line.Substring(0, 600) + '...[trunc]') }
    else { Write-Host $line }
}

function Drain {
    foreach ($line in (Read-EngineLines $script:session)) { Show-Line $line }
}

# Wait for the next stop, printing as it goes and keeping the menu queue moving. The pause event also
# carries the frame pointer and instance address that {EBP} / {VA} substitute.
function Wait-Paused([int]$timeoutSec) {
    return (Wait-EnginePaused $script:session $timeoutSec -OnLine {
            param($line)
            Show-Line $line
            if ($line -match '"event":"paused"') {
                if ($line -match '"ebp":"(0x[0-9A-F]+)"') { $script:ebp = $matches[1] }
                if ($line -match '"va":"(0x[0-9A-F]+)"') { $script:va = $matches[1] }
            }
        } -EachTick { Try-Poke })
}

# Resolve {EBP} / {VA} / {WVA:NAME} / {TID:PROC} against what this run has learned so far.
function Expand-Tokens([string]$command) {
    $out = $command.Replace('{EBP}', $script:ebp).Replace('{VA}', $script:va)
    $out = [regex]::Replace($out, '\{WVA:([^}]+)\}', { param($m) $script:wva[$m.Groups[1].Value] })
    $out = [regex]::Replace($out, '\{TID:([^}]+)\}', { param($m) $script:tidByProc[$m.Groups[1].Value] })
    return $out
}

$script:session = New-EngineSession -Engine $Engine -Target $Target -BreakArgs $BreakArgs `
    -WorkingDirectory (Split-Path $Target) -CaptureStdErr

# -PrePauseSec: let the app run (and the menu queue drain) before breaking in.
if ($PrePauseSec -gt 0) {
    $sw0 = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw0.Elapsed.TotalSeconds -lt $PrePauseSec) {
        Drain                      # also what teaches the session the debuggee pid Try-Poke needs
        Try-Poke
        Start-Sleep -Milliseconds 200
    }
    Drain
    if ($script:pending.Count -gt 0) {
        Write-Host ("!! " + $script:pending.Count + " menu item(s) never posted — raise -PrePauseSec")
    }
    Write-Host ">>> pause"
    $script:session.Proc.StandardInput.WriteLine("pause")
}

if (-not (Wait-Paused $PauseTimeoutSec)) {
    Write-Host "!! never paused"
}
elseif ($Burst) {
    # the add-in's pause burst: everything at once, then read whatever came back
    foreach ($c0 in $Commands) {
        $cmd = Expand-Tokens $c0
        if ($cmd -eq 'quit') { continue }
        Write-Host ">>> $cmd"
        $script:session.Proc.StandardInput.WriteLine($cmd)
    }
    Start-Sleep -Milliseconds ($CmdWaitMs * 2)
    Drain
}
else {
    foreach ($c0 in $Commands) {
        $cmd = Expand-Tokens $c0
        if ($cmd -eq 'quit') { continue }

        if ($cmd -eq 'go') {
            Write-Host ">>> continue (no wait)"
            $script:session.Proc.StandardInput.WriteLine('continue')
            Start-Sleep -Milliseconds $CmdWaitMs
            Drain
            continue
        }
        if ($cmd -eq 'pause') {
            Write-Host ">>> pause"
            $script:session.Proc.StandardInput.WriteLine('pause')
            if (-not (Wait-Paused $PauseTimeoutSec)) { Write-Host '!! never re-paused'; break }
            continue
        }
        if ($cmd -eq 'wake') {
            $cp = Get-EngineTargetProcess $script:session
            if ($cp) { Write-Host ("## woke " + [MenuPoke]::Wake($cp.Id) + " window(s)") }
            else { Write-Host "## wake skipped — no debuggee process to wake" }
            Start-Sleep -Milliseconds $CmdWaitMs
            Drain
            continue
        }
        if ($cmd -like 'sleep *') {
            Start-Sleep -Milliseconds ([int]$cmd.Substring(6))
            Drain
            continue
        }

        Write-Host ">>> $cmd"
        $script:session.Proc.StandardInput.WriteLine($cmd)
        if ($cmd -in @('step', 'stepover', 'stepout', 'continue')) {
            if (-not (Wait-Paused $PauseTimeoutSec)) { Write-Host '!! no pause'; break }
        }
        else {
            Start-Sleep -Milliseconds $CmdWaitMs
            Drain
        }
    }
}

Stop-EngineSession $script:session
Start-Sleep -Milliseconds 300
Drain
Stop-EngineTarget $script:session
Remove-EngineSession $script:session
if ($LogFile) { [IO.File]::WriteAllLines($LogFile, [string[]]$script:session.Sink.ToArray()) }
Write-Host "=== done ==="
