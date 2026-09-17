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
#   Tokens usable in -Commands: {VA} {EBP} from the last pause, {WVA:NAME} = a watched name's instance VA
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
function Poke-Next {
    if ($script:pending.Count -eq 0) { return }
    if ([DateTime]::UtcNow -lt $script:nextPokeAt) { return }
    $cp = Get-Process ([IO.Path]::GetFileNameWithoutExtension($Target)) -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cp) { return }
    $item = $script:pending[0]
    $r = [MenuPoke]::Poke($cp.Id, $item)
    if ($r) {
        Write-Host "## $item -> $r"
        $script:pending = @($script:pending | Select-Object -Skip 1)
        $script:nextPokeAt = [DateTime]::UtcNow.AddMilliseconds($MenuGapMs)
    }
}
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Engine
$psi.Arguments = "break `"$Target`" $BreakArgs --interactive --json"
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.WorkingDirectory = Split-Path $Target
$proc = New-Object System.Diagnostics.Process; $proc.StartInfo = $psi
$sink = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$h1 = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -MessageData $sink -Action { if ($EventArgs.Data -ne $null) { [void]$Event.MessageData.Add($EventArgs.Data) } }
$h2 = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -MessageData $sink -Action { if ($EventArgs.Data -ne $null) { [void]$Event.MessageData.Add("STDERR: " + $EventArgs.Data) } }
[void]$proc.Start(); $proc.BeginOutputReadLine(); $proc.BeginErrorReadLine()
$script:cursor = 0
function Note([string]$l) { if ($l -match '"event":"watch","name":"([^"]+)".*?"va":"(0x[0-9A-F]+)"') { $script:wva[$matches[1]] = $matches[2] } }
function Drain { while ($script:cursor -lt $sink.Count) { $l=$sink[$script:cursor]; $script:cursor++; Note $l; if ($l.Length -gt 600) { $l = $l.Substring(0,600) + '...[trunc]' }; Write-Host $l } }
function Wait-Paused([int]$t) { $sw=[Diagnostics.Stopwatch]::StartNew(); while ($sw.Elapsed.TotalSeconds -lt $t) { while ($script:cursor -lt $sink.Count) { $l=$sink[$script:cursor]; $script:cursor++; Note $l; if ($l.Length -gt 600) { Write-Host ($l.Substring(0,600)+'...[trunc]') } else { Write-Host $l }; if ($l -match '"event":"paused"') { if ($l -match '"ebp":"(0x[0-9A-F]+)"') { $script:ebp=$matches[1] }; if ($l -match '"va":"(0x[0-9A-F]+)"') { $script:va=$matches[1] }; return $true }; if ($l -match '"event":"exited"') { return $false } }; if ($proc.HasExited) { return $false }; Poke-Next; Start-Sleep -Milliseconds 100 }; return $false }
if ($PrePauseSec -gt 0) { $sw0=[Diagnostics.Stopwatch]::StartNew(); while ($sw0.Elapsed.TotalSeconds -lt $PrePauseSec) { Poke-Next; Start-Sleep -Milliseconds 200 }; Drain; if ($script:pending.Count -gt 0) { Write-Host ("!! " + $script:pending.Count + " menu item(s) never posted — raise -PrePauseSec") }; Write-Host ">>> pause"; $proc.StandardInput.WriteLine("pause") }
$ok = Wait-Paused $PauseTimeoutSec
if ($ok) {
  if ($Burst) {
    foreach ($c0 in $Commands) { $cmd = $c0.Replace('{EBP}',$script:ebp).Replace('{VA}',$script:va); $cmd = [regex]::Replace($cmd, '\{WVA:([^}]+)\}', { param($m) $script:wva[$m.Groups[1].Value] }); if ($cmd -eq 'quit') { continue }; Write-Host ">>> $cmd"; $proc.StandardInput.WriteLine($cmd) }
    Start-Sleep -Milliseconds ($CmdWaitMs * 2); Drain
  } else {
    foreach ($c0 in $Commands) {
      $cmd = $c0.Replace('{EBP}',$script:ebp).Replace('{VA}',$script:va)
      $cmd = [regex]::Replace($cmd, '\{WVA:([^}]+)\}', { param($m) $script:wva[$m.Groups[1].Value] })
      if ($cmd -eq 'quit') { continue }
      if ($cmd -eq 'wake') { $cp = Get-Process ([IO.Path]::GetFileNameWithoutExtension($Target)) -ErrorAction SilentlyContinue | Select-Object -First 1; Write-Host ("## woke " + [MenuPoke]::Wake($cp.Id) + " window(s)"); Start-Sleep -Milliseconds $CmdWaitMs; Drain; continue }
      if ($cmd -like 'sleep *') { Start-Sleep -Milliseconds ([int]$cmd.Substring(6)); Drain; continue }
      Write-Host ">>> $cmd"; $proc.StandardInput.WriteLine($cmd)
      if ($cmd -in @('step','stepover','stepout','continue')) { if (-not (Wait-Paused $PauseTimeoutSec)) { Write-Host '!! no pause'; break } } else { Start-Sleep -Milliseconds $CmdWaitMs; Drain }
    }
  }
} else { Write-Host "!! never paused" }
try { $proc.StandardInput.WriteLine("quit") } catch {}
$proc.WaitForExit(8000) | Out-Null
if (-not $proc.HasExited) { $proc.Kill(); Write-Host "!! engine force-killed" }
Start-Sleep -Milliseconds 300; Drain
Get-Process ([IO.Path]::GetFileNameWithoutExtension($Target)) -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "!! killing leftover clbrws pid $($_.Id)"; $_.Kill() }
Unregister-Event -SourceIdentifier $h1.Name; Unregister-Event -SourceIdentifier $h2.Name
if ($LogFile) { [IO.File]::WriteAllLines($LogFile, [string[]]$sink.ToArray()) }
Write-Host "=== done ==="
