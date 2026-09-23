# Attach to a running Clarion app and detach from it again (ticket 3f2d747f part A). LIVE: it starts the
# Clarion example app, attaches the engine to it, and after every detach asserts that the app is still alive,
# that no debugger is attached, and that every breakpoint byte in its memory matches the file on disk.
#
#   pwsh -NoProfile -File tools\test-attach.ps1                        # every leg (LIVE)
#   pwsh -NoProfile -File tools\test-attach.ps1 -SelfTest              # OFFLINE: planted detach faults turn
#                                                                      # protocolcheck red
#   pwsh -NoProfile -File tools\test-attach.ps1 -SelfTest -LiveMutant  # ...and report whether the LIVE stress
#                                                                      # leg sees a drain-less engine
# Exit code 0 = all checks passed.
#
# The legs, each on a fresh app and a fresh engine:
#   A  detach while paused at a breakpoint            D  detach inside a stream of silent breakpoint hits
#   B  detach while running                           E  `quit` while running detaches (attach mode)
#   C  detach straight after a step-over              F  closing stdin while paused detaches (attach mode)
#   G  --expect-start: a wrong creation time is refused with nothing planted; the listed one attaches
# plus the refusals (no --interactive, an x64 pid, a pid that does not exist), which start no debuggee.
#
# THIS SUITE CANNOT SEE THE DRAIN RACE (measured 2026-09-23). The drain answers debug events other threads
# queued before the detach froze the process. Leg D tries - a breakpoint whose hit count is never reached traps
# on every hit, and the detach lands while browses open - but in clbrws only 2 silent hits had happened when the
# detach went in, the engine's console line reported ours=0 (no queued INT3 or trap of ours) in every round, and
# an engine with the drain REMOVED survived 5 of 5 rounds. The drain's answers are therefore checked OFFLINE, by
# protocolcheck feeding it a queue (ProtocolCheck.Attach.cs), and -SelfTest proves that check fails when the
# drain is removed. -LiveMutant repeats the live measurement and reports it; it asserts nothing.
param(
  [string] $Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
  [string] $Target = 'C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe',
  # clbrws001.clw:561 is the first line of BRW1::FillQueue, which runs once per row the browse displays.
  [string] $BpSite = 'clbrws001.clw:561',
  [string] $MenuItem = '2/5',            # Browse > Filtered Locator (Authors)
  [int] $StressRounds = 1,
  [switch] $OnlyStress,
  [switch] $SelfTest,
  [switch] $LiveMutant
)

. "$PSScriptRoot\engine-session.ps1"
. "$PSScriptRoot\lib-check.ps1"

# ---------------------------------------------------------------------------------------------------------
if ($SelfTest) {
  Write-Host 'test-attach -SelfTest: each planted detach fault must turn protocolcheck red, on the check aimed at it'
  Write-Host ''
  $work = Join-Path ([IO.Path]::GetTempPath()) ('test-attach-mutant-' + [guid]::NewGuid().ToString('N'))
  # Each plant: name, anchor (must occur exactly once in its file), replacement, the
  # protocolcheck failure text that proves the RIGHT check caught it, and optionally the file.
  $plants = @(
    @('the drain never runs', 'internal const int DetachDrainCapEvents = 200;', 'internal const int DetachDrainCapEvents = 0;', 'detach drain: continued'),
    @('the drain does not rewind EIP on our INT3', 'if (rewind && !SetEip(Tid(ev), exAddr))', 'if (rewind && tid0 == 1 && !SetEip(Tid(ev), exAddr))', 'detach drain: EIP rewinds none'),
    @('the reseed keeps the injected break thread', 'foreach (var kv in created) if (kv.Key != breakTid) list.Add(kv);', 'foreach (var kv in created) list.Add(kv);', 'thread order: 99,'),
    @('the reseed breaks a creation-time tie the wrong way', 'a.Value.CompareTo(b.Value) : a.Key.CompareTo(b.Key)', 'a.Value.CompareTo(b.Value) : b.Key.CompareTo(a.Key)', 'thread order: 30,20,'),
    @('the reseed does not make the oldest thread main', 'if (order.Count > 0) _mainTid = order[0];', 'if (order.Count < 0) _mainTid = order[0];', 'thread order: _mainTid is'),
    # The 4b run 1 fault, restored exactly: commands read only when a wait times out (DebugEngine.cs).
    @('commands are read only when a wait times out', "if (_interactive) { PollHover(false); DrainCommandsWhileRunning(); }`n                if (!_loopWait(buf, pollMs))`n                {`n                    if (_interactive) continue;", "if (_interactive) PollHover(false);`n                if (!_loopWait(buf, pollMs))`n                {`n                    if (_interactive) { DrainCommandsWhileRunning(); continue; }", 'starved: `detach`', 'DebugEngine.cs'),
    # 4b run 2 (item 3): each hardening, removed.
    @('a TF-clear failure is not reported', 'foreach (uint t in _threads) if (!ClearTf(t)) tfFailed.Add(t);', 'foreach (uint t in _threads) ClearTf(t);', 'detach (a): two threads whose TF'),
    @('an EIP-rewind failure is not reported', 'rewindFailed.Add("0x" + exAddr.ToString("X") + " on " + Tid(ev));', 'rewindFailed.Clear();', 'detach (a): a queued hit whose EIP'),
    @('the drain forgets bytes removed before the detach', 'ours.UnionWith(_plantedEver);', 'ours.Clear();', 'detach (b):'),
    @('the debug loop pauses on a stale hit of ours', 'else if (IsStaleHitOfOurs(exAddr))', 'else if (tid0 == 1 && IsStaleHitOfOurs(exAddr))', 'stale hit: the debug loop', 'DebugEngine.cs'),
    @('an unreadable image is reported as not x86', 'if (!probeOk) return ImageArch.Unreadable;', 'if (!probeOk) return ImageArch.NotX86;', 'attach image (c): an x86 process whose image could not be read', 'ProcsCommand.cs'),
    @('--expect-start is never compared', 'if (StartTimeMatches(ExpectStart, read, actual)) return;', 'if (tid0 == 0) return;', 'expect-start (d): a creation-time MISMATCH'),
    @('a detach that throws sends nothing', ('catch (Exception ex)' + "`n" + '            {' + "`n" + '                aborted = '), ('catch (Exception ex) when (ex == null)' + "`n" + '            {' + "`n" + '                aborted = '), 'detach (e):')
  )
  try {
    $src = Join-Path $PSScriptRoot '..\src'
    foreach ($p in $plants) {
      Invoke-CheckSection "plant: $($p[0])" {
        $dir = Join-Path $work ([guid]::NewGuid().ToString('N'))
        foreach ($d in 'ClarionDbg.Cli', 'ClarionDbg.Core') {
          $to = Join-Path $dir "src\$d"
          New-Item -ItemType Directory -Path $to -Force | Out-Null
          Get-ChildItem -LiteralPath (Join-Path $src $d) -File | Where-Object { $_.Extension -in '.cs', '.csproj' } |
            ForEach-Object { [IO.File]::WriteAllBytes((Join-Path $to $_.Name), [IO.File]::ReadAllBytes($_.FullName)) }
        }
        # A plant names its file in a 5th element (default DebugEngine.Attach.cs). Line endings are normalized
        # to LF first, so a multi-line anchor matches whether the working copy is CRLF or LF.
        $file = if ($p.Count -ge 5) { $p[4] } else { 'DebugEngine.Attach.cs' }
        $f = Join-Path $dir "src\ClarionDbg.Cli\$file"
        $text = [IO.File]::ReadAllText($f).Replace("`r`n", "`n")
        $n = ([regex]::Matches($text, [regex]::Escape($p[1]))).Count
        Check "$($p[0]): the plant applies (anchor found exactly once)" ($n -eq 1) "found $n"
        $mut = $text.Replace($p[1], $p[2])
        # A plant that tests `tid0` gets it as a static field that is always 0 - NON-constant, so the compiler
        # neither folds the condition away nor warns that the code after it is unreachable.
        if ($p[2].Contains('tid0')) { $mut = [regex]::Replace($mut, '(partial class (DebugEngine|ProcsCommand)\b[^{]*\{)', ('$1' + "`n        private static uint tid0 = 0;"), 1) }
        [IO.File]::WriteAllText($f, $mut)
        $out = Join-Path $dir 'bin'
        $build = @(& dotnet build (Join-Path $dir 'src\ClarionDbg.Cli\ClarionDbg.Cli.csproj') --nologo -o $out 2>&1 | ForEach-Object { "$_" })
        $exe = Join-Path $out 'ClarionDbg.exe'
        $built = $LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $exe)
        # Fail closed: a mutant that did not build proves nothing, and is not counted as caught.
        Check "$($p[0]): the mutant built" $built (($build | Select-Object -Last 3) -join ' | ')
        $pc = if ($built) { @(& $exe protocolcheck 2>&1 | ForEach-Object { "$_" }) } else { @() }
        $code = if ($built) { $LASTEXITCODE } else { -1 }
        $hit = @($pc | Where-Object { $_ -match '^\s+FAIL\s+' -and $_.Contains($p[3]) })
        Check "$($p[0]): protocolcheck goes red on '$($p[3])'" ($built -and $code -ne 0 -and $hit.Count -ge 1) $(if ($hit.Count) { $hit[0].Trim().Substring(0, [Math]::Min(160, $hit[0].Trim().Length)) } else { "exit $code; $(($pc | Where-Object { $_ -match 'FAIL' } | Select-Object -First 2) -join ' | ')" })
        if ($p[0] -eq 'the drain never runs') { $script:drainless = if ($built) { $exe } else { $null } }
      }
    }
    if ($LiveMutant -and $script:drainless) {
      Write-Host ''
      Write-Host 'LIVE MEASUREMENT (reported, not asserted): the stress leg against the drain-less engine, 5 rounds'
      $o = @(& pwsh -NoProfile -File $PSCommandPath -Engine $script:drainless -Target $Target -OnlyStress -StressRounds 5 2>&1 | ForEach-Object { "$_" })
      $red = @($o | Where-Object { $_ -match '^\s+FAIL\s+D\d+: .*(alive|bytes)' })
      foreach ($l in ($o | Where-Object { $_ -match 'silent hits|drained=' })) { Write-Host "  $l" }
      if ($red.Count) { Write-Host "  the live suite DID see it: $($red[0].Trim())" }
      else { Write-Host '  the live suite did NOT see it: the drain-less engine survived every round (see the header note)' }
    }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
  Assert-CheckTotal (3 * $plants.Count)
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ---------------------------------------------------------------------------------------------------------
Write-Host 'test-attach: attach, break, detach, and the app survives with its code intact'
Write-Host ''

if (-not (Test-Path -LiteralPath $Target)) { Write-Host "test-attach needs $Target"; exit 1 }

Add-Type @"
using System; using System.Runtime.InteropServices;
public static class AttachPoke {
 [DllImport("user32.dll")] static extern IntPtr GetMenu(IntPtr h);
 [DllImport("user32.dll")] static extern IntPtr GetSubMenu(IntPtr m,int p);
 [DllImport("user32.dll")] static extern uint GetMenuItemID(IntPtr m,int p);
 [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h,uint msg,IntPtr w,IntPtr l);
 delegate bool EnumProc(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
 // Reaches every visible window owned by `pid` at the moment it runs. Verifying that the pid is still this
 // run's app is the CALLER's job (Get-EngineTargetPid, immediately before).
 public static string Menu(int pid,string path){ string res=null; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var m=GetMenu(h); if(m==IntPtr.Zero) return true; var ps=path.Split('/'); var sm=GetSubMenu(m,int.Parse(ps[0])); uint id = sm==IntPtr.Zero?0:GetMenuItemID(sm,int.Parse(ps[1])); if(id!=0){ PostMessage(h,0x111,(IntPtr)id,IntPtr.Zero); res="WM_COMMAND id="+id; return false;} return true; },IntPtr.Zero); return res; }
}
public static class AttachMem {
 [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] b, int n, out IntPtr read);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 // PROCESS_VM_READ | PROCESS_QUERY_INFORMATION. A FRESH handle per read: nothing of the engine's is reused.
 public static byte[] Read(int pid, long va, int n) { var h = OpenProcess(0x0410, false, pid); if (h==IntPtr.Zero) return null; try { var b=new byte[n]; IntPtr r; if(!ReadProcessMemory(h,new IntPtr(va),b,n,out r) || r.ToInt64()!=n) return null; return b; } finally { CloseHandle(h); } }
}
"@

# The file side of the byte check: PeImage compiled from source, as tools\test-procs.ps1 does (this process is
# 64-bit and ClarionDbg.Core.dll is built x86, so the DLL itself cannot be loaded here).
$coreWork = Join-Path ([IO.Path]::GetTempPath()) ('test-attach-core-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $coreWork | Out-Null
foreach ($f in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '..\src\ClarionDbg.Core') -Filter *.cs) {
  [IO.File]::WriteAllBytes((Join-Path $coreWork $f.Name), [IO.File]::ReadAllBytes($f.FullName))
}
Add-Type -Path (Get-ChildItem -LiteralPath $coreWork -Filter *.cs).FullName
Remove-Item -LiteralPath $coreWork -Recurse -Force -ErrorAction SilentlyContinue
$script:pe = [ClarionDbg.Core.PeImage]::Load($Target)

# ---- helpers ----------------------------------------------------------------------------------------------

# Every line this leg's engine printed goes into $script:log (the byte check reads it all); a wait scans it from
# its own cursor, so lines that arrived in the same batch as an earlier match are still seen by the next wait.
function Wait-Line($s, [string] $pattern, [int] $sec) {
  $sw = [Diagnostics.Stopwatch]::StartNew(); $exitAt = $null
  while ($sw.Elapsed.TotalSeconds -lt $sec) {
    foreach ($l in (Read-EngineLines $s)) { [void]$script:log.Add($l) }
    while ($script:logCursor -lt $script:log.Count) {
      $l = $script:log[$script:logCursor]; $script:logCursor++
      if ($l -cmatch $pattern) { return $l }
    }
    # The output pump can deliver the last lines after the process has gone: give it two seconds.
    if ($s.Proc.HasExited) { if ($null -eq $exitAt) { $exitAt = $sw.Elapsed.TotalSeconds } elseif ($sw.Elapsed.TotalSeconds - $exitAt -gt 2) { return $null } }
    Start-Sleep -Milliseconds 100
  }
  return $null
}

# The first line ANYWHERE in this leg's log that matches, whatever the waits have passed over. `--bp` resolves
# against the image before the attach, so its bp-set is printed BEFORE loaded.
function Find-Logged($s, [string] $pattern) {
  foreach ($l in (Read-EngineLines $s)) { [void]$script:log.Add($l) }
  foreach ($l in $script:log) { if ($l -cmatch $pattern) { return $l } }
  return $null
}

function Send([string] $cmd) { try { $script:s.Proc.StandardInput.WriteLine($cmd) } catch { } }

function Poke-Menu {
  for ($i = 0; $i -lt 40; $i++) {
    $pokePid = Get-EngineTargetPid $script:s
    if ($null -eq $pokePid) { Start-Sleep -Milliseconds 250; continue }
    if ([AttachPoke]::Menu($pokePid, $MenuItem)) { return $true }
    Start-Sleep -Milliseconds 250
  }
  return $false
}

# The breakpoint VAs this leg planted, from the engine's own loaded + bp-set events.
function Get-BpVas {
  $base = $null; $rvas = @()
  foreach ($l in $script:log) {
    if ($l -cmatch '"event":"loaded".*"loadBase":"0x([0-9A-Fa-f]+)"') { $base = [Convert]::ToUInt32($matches[1], 16) }
    if ($l -cmatch '"event":"bp-set".*"rvas":\[([^\]]*)\]') {
      foreach ($m in [regex]::Matches($matches[1], '0x([0-9A-Fa-f]+)')) { $rvas += [Convert]::ToUInt32($m.Groups[1].Value, 16) }
    }
  }
  if ($null -eq $base) { return @() }
  return @($rvas | Sort-Object -Unique | ForEach-Object { [pscustomobject]@{ Rva = $_; Va = [int64]$base + $_ } })
}

# '' when every bp's 16-byte window in the live app equals the file on disk; otherwise what differs.
function Compare-BpBytesWithDisk {
  $vas = @(Get-BpVas)
  if ($vas.Count -eq 0) { return 'no breakpoint address was reported, so there is nothing to compare' }
  foreach ($v in $vas) {
    $live = [AttachMem]::Read($script:app.Id, $v.Va, 16)
    if ($null -eq $live) { return ('could not read the app at 0x{0:X}' -f $v.Va) }
    $off = $script:pe.RvaToOffset([uint32]$v.Rva)
    $disk = $script:pe.Bytes[$off..($off + 15)]
    for ($i = 0; $i -lt 16; $i++) {
      if ($live[$i] -ne $disk[$i]) { return ('0x{0:X}+{1}: live {2:X2}, disk {3:X2}' -f $v.Va, $i, $live[$i], $disk[$i]) }
    }
  }
  return ''
}

# One leg: a fresh app, the engine attached to it, $Drive, and cleanup that runs whatever happened.
function Invoke-Leg([string] $Id, [string] $BpArgs, [scriptblock] $Drive, [scriptblock] $BeforeAttach = $null) {
  $script:log = New-Object System.Collections.ArrayList
  $script:logCursor = 0
  $t0 = Get-Date
  Start-Sleep -Milliseconds 50
  $script:app = Start-Process -FilePath $Target -WorkingDirectory (Split-Path $Target) -PassThru
  Start-Sleep -Seconds 2
  # Runs against the started app before the session attaches; whatever it returns is added to the attach args.
  $extra = if ($BeforeAttach) { "$(& $BeforeAttach)" } else { '' }
  $script:s = New-EngineSession -Engine $Engine -Target $Target -AttachPid $script:app.Id -StartedAt $t0 -BreakArgs "$BpArgs $extra"
  try {
    $loaded = Wait-Line $script:s '"event":"loaded"' 15
    Check "${Id}: attached (loaded carries attached:true)" ($null -ne $loaded -and $loaded -cmatch '"attached":true') "$loaded"
    & $Drive
  }
  finally {
    if (-not $script:s.Proc.HasExited) { Stop-EngineSession $script:s }
    Stop-EngineTarget $script:s
    Remove-EngineSession $script:s
  }
}

# The assertions every leg makes once the engine has let go.
function Assert-Detached([string] $Id, $detached) {
  $d = if ($detached) { ($detached -replace '^@JSON ', '') | ConvertFrom-Json } else { $null }
  Check "${Id}: detached, with no error" ($null -ne $d -and $null -eq $d.error) "$detached"
  # ours = drained events that were our INT3 or a trap: the ones the drain exists for (engine console line).
  $ours = @($script:log | Where-Object { $_ -match '^detached from pid .*\(ours=(\d+)\)' } | ForEach-Object { [regex]::Match($_, 'ours=(\d+)').Groups[1].Value })
  if ($d) { Write-Host "        drained=$($d.drained) ours=$(if ($ours.Count) { $ours[0] } else { '?' }) restored=$($d.restored)" }
  [void]$script:s.Proc.WaitForExit(10000)
  Check "${Id}: the engine exited with code 0" ($script:s.Proc.HasExited -and $script:s.Proc.ExitCode -eq 0) $(if ($script:s.Proc.HasExited) { "exit $($script:s.Proc.ExitCode)" } else { 'still running' })
  Check "${Id}: every breakpoint byte in the app matches the file on disk" ((Compare-BpBytesWithDisk) -eq '') (Compare-BpBytesWithDisk)
  $p = & $Engine procs --json --verbose | ConvertFrom-Json
  $row = @($p.procs | Where-Object { $_.pid -eq $script:app.Id })
  $skip = @($p.skips | Where-Object { $_.pid -eq $script:app.Id })
  Check "${Id}: no debugger is attached any more (procs lists it)" ($row.Count -eq 1) $(if ($row.Count -eq 1) { '' } elseif ($skip.Count) { "skipped: $($skip[0].reason)" } else { 'not listed' })
  # Run the breakpoint's code natively now: a byte left at 0xCC, or a trap flag left set, kills the app here.
  $poked = Poke-Menu
  Start-Sleep -Seconds 5
  $script:app.Refresh()
  Check "${Id}: alive 5 s after running the breakpoint's code with no debugger" ($poked -and -not $script:app.HasExited) $(if (-not $poked) { 'the menu was never posted' } elseif ($script:app.HasExited) { "exited with code $($script:app.ExitCode)" } else { '' })
}

$bpArgs = "--bp $BpSite"

try {

if (-not $OnlyStress) {

Invoke-CheckSection 'the refusals: nothing is attached' {
  $o = @(& $Engine attach $PID --json 2>&1 | ForEach-Object { "$_" }); $c = $LASTEXITCODE
  Check 'without --interactive: the error event, exit 2' ($c -eq 2 -and ($o -join "`n") -cmatch '"message":"attach requires --interactive"') "exit $c; $($o -join ' | ')"
  $o = @(& $Engine attach $PID --interactive --json 2>&1 | ForEach-Object { "$_" }); $c = $LASTEXITCODE
  Check 'an x64 process (this pwsh): refused as not x86, exit 2' ($c -eq 2 -and ($o -join "`n") -cmatch '"event":"error","message":"attach failed: [^"]*not an x86[^"]*","code":50') "exit $c; $($o -join ' | ')"
  $o = @(& $Engine attach 4294967292 --interactive --json 2>&1 | ForEach-Object { "$_" }); $c = $LASTEXITCODE
  Check 'a pid that does not exist: attach failed with a Win32 code, exit 2' ($c -eq 2 -and ($o -join "`n") -cmatch '"event":"error","message":"attach failed: [^"]*","code":[1-9]\d*\}') "exit $c; $($o -join ' | ')"
}

Invoke-CheckSection 'A: detach while paused at a breakpoint' {
  Invoke-Leg 'A' $bpArgs {
    [void](Poke-Menu)
    $p = Wait-Line $script:s '"event":"paused"' 20
    Check 'A: the breakpoint was hit' ($null -ne $p -and $p -cmatch '"reason":"breakpoint"') "$p"
    Send 'detach'
    Assert-Detached 'A' (Wait-Line $script:s '"event":"detached"' 15)
  }
}

Invoke-CheckSection 'B: detach while running' {
  Invoke-Leg 'B' $bpArgs {
    $b = Find-Logged $script:s '"event":"bp-set"'
    Check 'B: the breakpoint was planted' ($null -ne $b) ''
    Send 'detach'
    Assert-Detached 'B' (Wait-Line $script:s '"event":"detached"' 15)
  }
}

Invoke-CheckSection 'C: detach straight after a step-over' {
  Invoke-Leg 'C' $bpArgs {
    [void](Poke-Menu)
    $p = Wait-Line $script:s '"event":"paused"' 20
    Check 'C: the breakpoint was hit' ($null -ne $p) "$p"
    Send 'stepover'; Send 'detach'
    Assert-Detached 'C' (Wait-Line $script:s '"event":"detached"' 15)
  }
}

Invoke-CheckSection 'E: quit while running detaches, in attach mode' {
  Invoke-Leg 'E' $bpArgs {
    [void](Find-Logged $script:s '"event":"bp-set"')
    Send 'quit'
    Assert-Detached 'E' (Wait-Line $script:s '"event":"detached"' 15)
  }
}

Invoke-CheckSection 'F: stdin closing while paused detaches, in attach mode' {
  Invoke-Leg 'F' $bpArgs {
    [void](Poke-Menu)
    $p = Wait-Line $script:s '"event":"paused"' 20
    Check 'F: the breakpoint was hit' ($null -ne $p) "$p"
    try { $script:s.Proc.StandardInput.Close() } catch { }
    Assert-Detached 'F' (Wait-Line $script:s '"event":"detached"' 15)
  }
}

# G: --expect-start (4b run 2). On ONE app: first the WRONG creation time, which must be refused before anything
# is planted and leave the app exactly as it was; then the time `procs` lists, which must attach as usual.
Invoke-CheckSection 'G: --expect-start refuses a reused pid, and accepts the listed one' {
  Invoke-Leg 'G' $bpArgs {
    Send 'detach'
    Assert-Detached 'G' (Wait-Line $script:s '"event":"detached"' 15)
  } -BeforeAttach {
    $p = & $Engine procs --json | ConvertFrom-Json
    $row = @($p.procs | Where-Object { $_.pid -eq $script:app.Id })
    $started = if ($row.Count -eq 1) { [string]$row[0].started } else { '' }
    Check 'G: procs lists the app with its creation time' ($started -match '^\d+$') "started=$started"
    $wrong = if ($started -match '^\d+$') { ([uint64]$started + 1).ToString() } else { '1' }
    $o = @(& $Engine attach $script:app.Id --interactive --json --expect-start $wrong --bp $BpSite 2>&1 | ForEach-Object { "$_" }); $c = $LASTEXITCODE
    Check 'G: the wrong creation time is refused as a reused pid, exit 2' ($c -eq 2 -and ($o -join "`n") -cmatch ('"message":"attach failed: process ' + $script:app.Id + ' is not the one listed \(pid reused\)","code":0')) "exit $c; $(($o | Where-Object { $_ -match '@JSON' }) -join ' | ')"
    Check 'G: ...with no `detached` event after the error' (-not (($o -join "`n") -cmatch '"event":"detached"')) ''
    # Nothing was planted: the breakpoint site's bytes are the file's, and the app is not being debugged.
    $sp = $BpSite.Split(':')
    $site = & $Engine resolve $Target --line $sp[1] --module $sp[0] 2>&1 | Out-String
    $rva = if ($site -match 'RVA 0x([0-9A-Fa-f]+)') { [Convert]::ToUInt32($matches[1], 16) } else { $null }
    $same = $false
    if ($null -ne $rva) {
      $live = [AttachMem]::Read($script:app.Id, [int64]$script:pe.ImageBase + $rva, 16)
      $off = $script:pe.RvaToOffset([uint32]$rva)
      $same = $null -ne $live -and ((@($live) -join ',') -eq (@($script:pe.Bytes[$off..($off + 15)]) -join ','))
    }
    Check 'G: nothing was planted (the breakpoint site matches the file)' $same $(if ($null -eq $rva) { "could not resolve $BpSite" } else { ('RVA 0x{0:X}' -f $rva) })
    $p2 = & $Engine procs --json | ConvertFrom-Json
    Check 'G: the refused attach left no debugger on the app' (@($p2.procs | Where-Object { $_.pid -eq $script:app.Id }).Count -eq 1) ''
    "--expect-start $started"
  }
}
}

# A hit count that is never reached: every row of every browse traps, single-steps to re-arm, and resumes
# without a stop. The detach lands while browses are filling, so other threads are likely to have queued an
# INT3 or a single-step behind the event the detach holds.
$stressBp = "--bp `"$BpSite|hm=eq|hv=1000000`""
for ($r = 1; $r -le $StressRounds; $r++) {
  $id = "D$r"
  Invoke-CheckSection "${id}: detach inside a stream of silent breakpoint hits" {
    Invoke-Leg $id $stressBp {
      [void](Find-Logged $script:s '"event":"bp-set"')
      Start-Sleep -Seconds 1   # past the attach burst and its initial break
      # Four browses opened back to back, each filling on its own thread, and the detach 30 ms behind them.
      for ($k = 0; $k -lt 4; $k++) { [void](Poke-Menu) }
      Start-Sleep -Milliseconds 30
      Send 'bp list'   # evidence only: how many silent hits had happened when the detach went in
      Send 'detach'
      $bl = Wait-Line $script:s '"event":"bp-list"' 10
      Write-Host "        silent hits before the detach: $(if ($bl -cmatch '"hitCount":(\d+)') { $matches[1] } else { '?' })"
      Assert-Detached $id (Wait-Line $script:s '"event":"detached"' 15)
    }
  }
}

} finally { }

# Refusals 3; A, B, C and F 7 each (attached, one setup check, five after-detach); E and each stress round 6;
# G 11 (five on the refused attach, then attached and five after-detach).
$EXPECTED_CHECKS = $(if ($OnlyStress) { 0 } else { 3 + 7 + 7 + 7 + 6 + 7 + 11 }) + 6 * $StressRounds
Assert-CheckTotal $EXPECTED_CHECKS
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
