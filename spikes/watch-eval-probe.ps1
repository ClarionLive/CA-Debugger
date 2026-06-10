# Item-5b probe: watch command — non-threaded direct read + THREADed func-eval round trip.
# At the startup BP the JOBS buffer is empty, but this exercises the full hijack→trap→restore
# path and proves the engine survives it (re-pause, then continue/quit cleanly).
$exe = "H:\DevLaptop\Projects\ClarionDebugger\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe"
$target = "C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.Arguments = "break `"$target`" --bp clbrws002:299 --interactive --json"
$psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$deadline = (Get-Date).AddSeconds(40); $state = "wait-pause"
while ((Get-Date) -lt $deadline) {
    $line = $p.StandardOutput.ReadLine()
    if ($null -eq $line) { break }
    $line
    switch ($state) {
        "wait-pause" { if ($line -match '"event":"paused"') { $p.StandardInput.WriteLine("watch _CLARIONMONTHLISTLONG"); $state = "wait-w1" } }
        "wait-w1"    { if ($line -match '"event":"watch".*MONTHLIST') { $p.StandardInput.WriteLine("watch JOB:JOB_DESC"); $state = "wait-w2" } }
        "wait-w2"    { if ($line -match '"event":"watch".*JOB_DESC') { $state = "wait-repause" } }
        "wait-repause" { if ($line -match '"event":"paused".*"reason":"watch"') { $p.StandardInput.WriteLine("quit"); $state = "done" } }
    }
    if ($line -match '"event":"exited"') { break }
}
if ($state -ne "done") { "PROBE INCOMPLETE (state=$state)"; try { $p.Kill() } catch {} } else { "WATCH PROBE OK" }