# Shared event plumbing for the interactive engine harnesses (be6bb31c #2): read a session's @JSON events,
# wait for one, send a command, ask by reqId, and print a stop. Dot-source it AFTER engine-session.ps1, which
# provides Read-EngineLines.
#
# What is NOT here, on purpose: starting and closing a session. test-engine-session.ps1 requires every harness
# to call New-EngineSession and Stop-EngineTarget itself, so each harness keeps its own New-Session and
# Close-Session. This file launches nothing and names no binary.
#
# A session object carries .Events (an ArrayList of parsed events), .Seen (the Wait-Event cursor) and .Raw
# (every line read). Timeout and verbosity are PARAMETERS, never read from the caller's variables: a harness
# passes its own once, through $PSDefaultParameterValues (Get-EngineEventDefaults builds the table):
#   $PSDefaultParameterValues = Get-EngineEventDefaults -TimeoutSec $StopTimeoutSec -Verbose2 $Verbose2

# The default-parameter table that hands a harness's timeout and verbosity to every function below.
function Get-EngineEventDefaults([int] $TimeoutSec, [bool] $Verbose2) {
  $d = @{}
  foreach ($f in 'Read-Events', 'Wait-Event', 'Wait-Stop', 'Send', 'Ask') { $d["${f}:Verbose2"] = $Verbose2 }
  foreach ($f in 'Wait-Event', 'Wait-Stop', 'Ask') { $d["${f}:TimeoutSec"] = $TimeoutSec }
  return $d
}

# Drain the engine's output into $S.Raw, and parse every @JSON line into $S.Events.
function Read-Events($S, [bool] $Verbose2 = $false) {
  foreach ($l in (Read-EngineLines $S)) {
    if ($null -eq $l) { continue }
    [void]$S.Raw.Add($l)
    if ($Verbose2) { Write-Host "    | $l" }
    if ($l.StartsWith('@JSON ')) {
      $o = $null
      try { $o = $l.Substring(6) | ConvertFrom-Json } catch { }
      if ($null -ne $o) { [void]$S.Events.Add($o) }
    }
  }
}

# The next event (from the session's cursor) that $Pred accepts, or $null on timeout / engine exit. Events
# skipped on the way stay in $S.Events for the whole-session checks.
function Wait-Event($S, [scriptblock] $Pred, [int] $TimeoutSec = 30, [bool] $Verbose2 = $false) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
    Read-Events $S -Verbose2 $Verbose2
    while ($S.Seen -lt $S.Events.Count) {
      $e = $S.Events[$S.Seen]; $S.Seen++
      if (& $Pred $e) { return $e }
    }
    if ($S.Proc.HasExited) {
      Start-Sleep -Milliseconds 200; Read-Events $S -Verbose2 $Verbose2
      if ($S.Seen -ge $S.Events.Count) { return $null }
      continue
    }
    Start-Sleep -Milliseconds 100
  }
  return $null
}

# The next stop: a pause or the debuggee's exit.
function Wait-Stop($S, [int] $TimeoutSec = 30, [bool] $Verbose2 = $false) {
  return (Wait-Event $S { param($e) $e.event -ceq 'paused' -or $e.event -ceq 'exited' } -TimeoutSec $TimeoutSec -Verbose2 $Verbose2)
}

function Send($S, [string] $Cmd, [bool] $Verbose2 = $false) {
  if ($Verbose2) { Write-Host "    > $Cmd" }
  $S.Proc.StandardInput.WriteLine($Cmd)
}

# One request, and its reply: the next $Ev event whose reqId is $ReqId.
function Ask($S, [string] $Cmd, [string] $Ev, [string] $ReqId, [int] $TimeoutSec = 30, [bool] $Verbose2 = $false) {
  Send $S $Cmd -Verbose2 $Verbose2
  return (Wait-Event $S { param($e) $e.event -ceq $Ev -and "$($e.reqId)" -eq $ReqId } -TimeoutSec $TimeoutSec -Verbose2 $Verbose2)
}

function Show-Stop($e) {
  if ($null -eq $e) { return '(no stop)' }
  if ($e.event -ceq 'exited') { return "exited code $($e.code)" }
  return "paused $($e.reason) $($e.module):$($e.line) va $($e.va)"
}
