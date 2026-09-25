# The host's ONE selected thread (49538b78 item 8b, Owner decision 3, 2026-09-24).
#
#   pwsh -NoProfile -File tools\test-addin-selection.ps1 [-ServicePath <ClarionDebuggerService.cs>] [-HostGrantsPath <HostGrants.cs>]
#   pwsh -NoProfile -File tools\test-addin-selection.ps1 -SelfTest
# Exit code 0 = all checks passed.
#
# Three host places each kept their own idea of which thread is selected: the Disassembly view (_selTid,
# _stoppedTid), the grant table (_selectedTid) and the pad's calls into it. Each was fed by its own subset of the
# events, so an inventory that moved the engine's selection moved one copy and not another. Now the SERVICE is
# the one writer (MoveSelection), fed by Paused, the threads reply and an accepted ThreadSelected, and it hands
# every consumer an immutable snapshot through SelectionChanged.
#
# RUN, NOT READ. The real ClarionDebuggerService.cs is compiled whole, and its real private OnLine is driven with
# the engine's @JSON lines through reflection, exactly as Launch wires a live engine's stdout. The real EditGrants
# reads the real service's Selection. The Disassembly view's half (TakeSelection, ApplySelection) is run in
# tools/test-disasm-seat.ps1 section 6.
#
# NOT COVERED: Launch itself (it starts an engine process). Its selection reset is pinned by the single-writer
# scan below, which a reset written anywhere in the service fails. Anything live.
#
# ASCII only, for Windows PowerShell 5.1.

param(
  # Defaulted in the body: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $ServicePath = '',
  [string] $HostGrantsPath = '',
  [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$root = Join-Path $PSScriptRoot '..'
if (-not $ServicePath) { $ServicePath = Join-Path $root 'src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs' }
if (-not $HostGrantsPath) { $HostGrantsPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\HostGrants.cs' }
$others = @('Services\RedFileService.cs', 'Services\ClarionVersionService.cs', 'Wire\JsonMessageReader.cs', 'Wire\WireRules.cs',
  'Wire\AttachableProcess.cs', 'Terminal\PageMessages.cs') | ForEach-Object { Join-Path $root ('src\ClarionDebugger.Addin\' + $_) }

# ================================================================================================ -SelfTest
# Each mutation breaks ONE guard in a copy of the source and runs this suite on the copy in a fresh process
# (Add-Type cannot redefine a loaded type). CAUGHT only when that run exits non-zero AND never prints its success
# line; a find that does not match exactly once is a failure, so a mutation that changed nothing is never caught.
if ($SelfTest) {
  $M = @(
    @{ Id = 'S1'; File = 'svc'; Why = 'SelectionChanged raised AFTER Paused';
       Find = "MoveSelection(pause.Tid, pause.Tid, ThreadSelectionCause.Stop, false);`n                        Paused?.Invoke(pause);";
       Repl = "Paused?.Invoke(pause);`n                        MoveSelection(pause.Tid, pause.Tid, ThreadSelectionCause.Stop, false);" }
    @{ Id = 'S2'; File = 'svc'; Why = 'the epoch resets when a new session launches';
       Find = "MoveSelection(null, null, ThreadSelectionCause.Reset, true);`n            SetState(DebugSessionState.Launching);";
       Repl = "lock (_selectionLock) _selection = ThreadSelection.None;`n            SetState(DebugSessionState.Launching);" }
    @{ Id = 'S3'; File = 'svc'; Why = 'the epoch resets when a session ends';
       Find = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, this);';
       Repl = 'cause == ThreadSelectionCause.Ended ? 0 : System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, this);' }
    @{ Id = 'S4'; File = 'svc'; Why = 'a refused switch moves the selection';
       Find = 'if (selOk && WireRules.TidIsKnown(selTid))'; Repl = 'if (WireRules.TidIsKnown(selTid))' }
    @{ Id = 'S5'; File = 'svc'; Why = 'the inventory is ignored';
       Find = 'MoveSelection(InventorySelection(tl), tl.StoppedTid, ThreadSelectionCause.Inventory, true);'; Repl = '' }
    @{ Id = 'S6'; File = 'svc'; Why = 'an agreeing inventory still raises a change';
       Find = 'MoveSelection(InventorySelection(tl), tl.StoppedTid, ThreadSelectionCause.Inventory, true);';
       Repl = 'MoveSelection(InventorySelection(tl), tl.StoppedTid, ThreadSelectionCause.Inventory, false);' }
    @{ Id = 'S7'; File = 'grants'; Why = 'HostGrants offers on a stale selection epoch';
       Find = 'if (sentEpoch != sel.Epoch) return false;'; Repl = 'if (sentEpoch != sel.Epoch && sentEpoch < 0) return false;' }
    @{ Id = 'S8'; File = 'grants'; Why = 'HostGrants offers for a thread that is not the service''s selection';
       Find = 'if (!WireRules.TidIsKnown(tid) || tid != sel.Tid) return false;'; Repl = 'if (!WireRules.TidIsKnown(tid)) return false;' }
    @{ Id = 'S10'; File = 'svc'; Why = 'each service counts its own epochs (the counter is per instance)';
       Find = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, this);'; Repl = 'cur.Epoch + 1, cause, this);' }
    @{ Id = 'S11'; File = 'svc'; Why = 'a switch does not keep the stopped thread the selection holds';
       Find = 'if (cause == ThreadSelectionCause.Switch) stoppedTid = cur.StoppedTid;'; Repl = '' }
    @{ Id = 'S12'; File = 'svc'; Why = 'a snapshot does not name the service that made it';
       Find = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, this);'; Repl = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, null);' }
    @{ Id = 'S9'; File = 'svc'; Why = 'the session end leaves the selection standing';
       Find = "SetState(DebugSessionState.Idle);`n                MoveSelection(null, null, ThreadSelectionCause.Ended, true);";
       Repl = 'SetState(DebugSessionState.Idle);' }
  )
  $base = Join-Path ([IO.Path]::GetTempPath()) ('selection-selftest-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $base | Out-Null
  try {
    $src = @{ svc = $ServicePath; grants = $HostGrantsPath }
    $runs = @()
    foreach ($m in $M) {
      $dir = Join-Path $base $m.Id; New-Item -ItemType Directory -Path $dir | Out-Null
      foreach ($k in $src.Keys) { Copy-Item -LiteralPath $src[$k] -Destination (Join-Path $dir ([IO.Path]::GetFileName($src[$k]))) }
      $target = Join-Path $dir ([IO.Path]::GetFileName($src[$m.File]))
      $text = [IO.File]::ReadAllText($target)
      # The sources are LF in git and CRLF in a working tree (autocrlf): the find matches either.
      $pattern = [regex]::Escape($m.Find) -replace '\\n', '\r?\n'
      $n = [regex]::Matches($text, $pattern).Count
      Check "$($m.Id) find matches once ($($m.Why))" ($n -eq 1) "$n match(es)"
      if ($n -eq 1) { [IO.File]::WriteAllText($target, [regex]::Replace($text, $pattern, $m.Repl.Replace('$', '$$'))); $runs += $m }
    }
    $dir = Join-Path $base 'CONTROL'; New-Item -ItemType Directory -Path $dir | Out-Null
    foreach ($k in $src.Keys) { Copy-Item -LiteralPath $src[$k] -Destination (Join-Path $dir ([IO.Path]::GetFileName($src[$k]))) }
    $runs += @{ Id = 'CONTROL'; Why = 'unmutated copies' }
    foreach ($r in $runs) {
      $d = Join-Path $base $r.Id
      $out = & pwsh -NoProfile -File $PSCommandPath -ServicePath (Join-Path $d 'ClarionDebuggerService.cs') -HostGrantsPath (Join-Path $d 'HostGrants.cs') 2>&1
      $code = $LASTEXITCODE
      $passed = [bool](@($out) -match '^ALL \d+ CHECKS PASSED')
      $compiled = [bool](@($out) -match '^compiled the service and the grant table$')
      $fails = (@($out) -match '^\s*FAIL' | Select-Object -First 2) -join ' / '
      if ($r.Id -eq 'CONTROL') { Check 'CONTROL: the unmutated copies pass' ($passed -and $code -eq 0) "exit=$code" }
      else { Check "$($r.Id) CAUGHT: $($r.Why)" ($compiled -and (-not $passed) -and $code -ne 0) "exit=$code compiled=$compiled $fails" }
    }
  } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
  # 12 finds + 12 mutations + 1 control
  Assert-CheckTotal 25
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ================================================================================================ compile
$probe = @"
using System;
using System.Collections.Generic;
using ClarionDebugger.Services;

namespace ClarionDebugger.Terminal
{
  // Drives the service's real private OnLine, and records the order its events are raised in.
  public sealed class SelectionDriver {
    public readonly ClarionDebuggerService Svc = new ClarionDebuggerService();
    public readonly List<string> Events = new List<string>();
    public readonly List<ThreadSelection> Snaps = new List<ThreadSelection>();
    private readonly System.Reflection.MethodInfo _onLine = typeof(ClarionDebuggerService).GetMethod("OnLine",
      System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
    private readonly EditGrants _grants;
    public SelectionDriver() {
      Svc.SelectionChanged += s => { Snaps.Add(s); Events.Add("selection:" + s.Cause + ":" + T(s.Tid) + "/" + T(s.StoppedTid) + "#" + s.Epoch); };
      Svc.Paused += p => Events.Add("paused");
      Svc.ThreadsReceived += l => Events.Add("threads");
      Svc.ThreadSelected += (t, ok, e) => Events.Add("threadselected");
      _grants = new EditGrants(() => Svc.Selection);
    }
    static string T(uint? t) { return t.HasValue ? t.Value.ToString() : "-"; }
    public void Line(string json) { _onLine.Invoke(Svc, new object[] { null, "@JSON " + json }); }
    public string Current { get { var s = Svc.Selection; return s.Cause + ":" + T(s.Tid) + "/" + T(s.StoppedTid) + "#" + s.Epoch; } }
    // The grant table, reading this service's selection.
    public string AskStack() { string id = _grants.NewStackRequestId(); _grants.StackRequested(id); return id; }
    public bool Offer(uint tid, string id) {
      return _grants.OfferFrames(tid, id, new[] { new KeyValuePair<string, string>("0x402000", "0x19FF40") });
    }
  }
}
"@
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('selection-probe-' + [guid]::NewGuid().ToString('N') + '.cs')
[IO.File]::WriteAllText($tmp, $probe)
try {
  $paths = @($ServicePath, $HostGrantsPath) + $others | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
  Add-Type -Path ($paths + $tmp) -IgnoreWarnings -WarningAction SilentlyContinue -ReferencedAssemblies @(
    'System.Xml', 'System.Xml.ReaderWriter', 'System.Diagnostics.Process', 'System.Diagnostics.FileVersionInfo',
    'System.ComponentModel.Primitives', 'System.Text.RegularExpressions', 'System.Collections', 'System.Linq',
    'System.Threading', 'System.Threading.Thread', 'System.Runtime.InteropServices') | Out-Null
} finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
# Printed so the self-test can tell "a check caught the mutant" from "the mutant never compiled".
Write-Host 'compiled the service and the grant table'

function Paused { param([uint32] $tid) '{"tid":' + $tid + ',"event":"paused","reason":"breakpoint","va":"0x401000","regs":{"eip":"0x401000"}}' }
function Threads { param($stopped, $selected)
  '{"event":"threads","stopped":' + $stopped + ',"selected":' + $selected + ',"threads":[{"tid":' + $stopped + ',"stopped":true},{"tid":9001},{"tid":7000}]}'
}
function Picked { param($tid, [bool] $ok) '{"event":"threadselected","tid":' + $tid + ',"ok":' + $(if ($ok) { 'true' } else { 'false' }) + ',"error":null}' }
function Events { param($d) $d.Events -join ' , ' }
function Since { param($d, [int] $from) @($d.Events | Select-Object -Skip $from) -join ' , ' }

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '1. what moves the selection, and the order it is announced in'
$d = New-Object ClarionDebugger.Terminal.SelectionDriver
Check 'CONTROL: a new service has no thread selected, at epoch 0' ($d.Current -ceq 'None:-/-#0') $d.Current
$d.Line((Paused 4812))
# THE ORDER. A view handles each event on the UI thread after a BeginInvoke, so what it reads from the service
# there can be ahead of the event. It holds the snapshot SelectionChanged gave it instead, and that only works if
# the snapshot is in front of the event it belongs to.
Check 'a stop selects the stopped thread, announced BEFORE Paused' ((Events $d) -ceq 'selection:Stop:4812/4812#1 , paused') (Events $d)
$n = $d.Events.Count
$d.Line((Threads 4812 4812))
Check 'an inventory that agrees moves nothing and announces nothing' (((Since $d $n) -ceq 'threads') -and ($d.Current -ceq 'Stop:4812/4812#1')) ((Since $d $n) + ' | ' + $d.Current)
$n = $d.Events.Count
$d.Line((Threads 4812 9001))
Check 'an inventory that names another selection moves it, announced BEFORE the threads event' `
  ((Since $d $n) -ceq 'selection:Inventory:9001/4812#2 , threads') (Since $d $n)
$n = $d.Events.Count
$d.Line((Threads 4812 0))
Check 'an inventory whose selected is the 0 sentinel means the stopped thread' `
  ((Since $d $n) -ceq 'selection:Inventory:4812/4812#3 , threads') (Since $d $n)
$n = $d.Events.Count
$d.Line((Picked 7000 $true))
Check 'an accepted switch moves it, keeps the stopped thread, and is announced BEFORE ThreadSelected' `
  ((Since $d $n) -ceq 'selection:Switch:7000/4812#4 , threadselected') (Since $d $n)
$n = $d.Events.Count
$d.Line((Picked 9001 $false))
Check 'a REFUSED switch moves nothing: the engine''s selection is unchanged' `
  (((Since $d $n) -ceq 'threadselected') -and ($d.Current -ceq 'Switch:7000/4812#4')) ((Since $d $n) + ' | ' + $d.Current)
$n = $d.Events.Count
$d.Line('{"event":"threadselected","ok":true,"error":null}')
$d.Line((Picked 0 $true))
Check 'an accepted switch that names no thread, or thread 0, moves nothing' `
  (((Since $d $n) -ceq 'threadselected , threadselected') -and ($d.Current -ceq 'Switch:7000/4812#4')) ((Since $d $n) + ' | ' + $d.Current)
$n = $d.Events.Count
$d.Line('{"event":"paused","reason":"breakpoint","va":"0x401000"}')
Check 'a stop that names no thread still moves it: to nothing known, not to thread 0' `
  ((Since $d $n) -ceq 'selection:Stop:-/-#5 , paused') (Since $d $n)
$n = $d.Events.Count
$d.Line('{"event":"resumed","mode":"continue"}')
Check 'a resume moves nothing: the next stop does' (($d.Events.Count -eq $n) -and ($d.Current -ceq 'Stop:-/-#5')) ((Since $d $n) + ' | ' + $d.Current)

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '2. the epoch only ever rises, across sessions too'
$e = New-Object ClarionDebugger.Terminal.SelectionDriver
$e.Line((Paused 4812)); $e.Line((Picked 9001 $true))
$endOf1 = $e.Svc.Selection.Epoch
$n = $e.Events.Count
# The engine reports its debuggee gone. The service's session ends here (its engine is reaped on its own).
$e.Line('{"event":"exited","code":0}')
Check 'a session''s end clears the selection, as a change with the next epoch' `
  ((Since $e $n) -ceq ('selection:Ended:-/-#' + ($endOf1 + 1))) (Since $e $n)
$e.Line((Paused 7000))
$first2 = $e.Snaps[$e.Snaps.Count - 1]
Check 'the NEXT session''s first stop carries on from the last epoch: it is newer than anything before it' `
  (($first2.Epoch -eq $endOf1 + 2) -and ($first2.Tid -eq 7000)) "session 1 ended at #$($endOf1 + 1); session 2 first #$($first2.Epoch)"
$epochs = @($e.Snaps | ForEach-Object { $_.Epoch })
$rising = $true; for ($i = 1; $i -lt $epochs.Count; $i++) { if ($epochs[$i] -le $epochs[$i - 1]) { $rising = $false } }
Check 'every snapshot the service raised has a higher epoch than the one before it' $rising ($epochs -join ',')
$e.Line('{"event":"exited","code":0}')
$n = $e.Events.Count
$e.Line('{"event":"exited","code":0}')
Check 'a second end moves nothing (there is nothing selected to clear)' ($e.Events.Count -eq $n) (Since $e $n)

# THE ONE WRITER, by statement: MoveSelection is the only code that assigns _selection, so no reset can be
# written anywhere else - in Launch, say - without failing here; and its epoch is always the previous one + 1.
$svcCode = Get-CSharpCodeOnly (Get-Content -Raw -LiteralPath $ServicePath)
$assignRx = '(?<![\w.])_selection\s*=(?!=)'
$assigns = [regex]::Matches($svcCode, $assignRx)
$mover = Get-CSharpCodeOnly (Get-Method 'private void MoveSelection(uint? tid, uint? stoppedTid, ThreadSelectionCause cause, bool onlyIfChanged)' (Get-Content -Raw -LiteralPath $ServicePath))
Check 'the service assigns _selection in exactly two places: its declaration and MoveSelection' `
  (($assigns.Count -eq 2) -and ($svcCode -match 'private ThreadSelection _selection = ThreadSelection\.None;') -and ($mover -match '_selection = next = new ThreadSelection\(')) `
  "$($assigns.Count) assignment(s)"
Check 'CONTROL: that scan sees a reset written elsewhere' ([regex]::Matches((Get-CSharpCodeOnly 'lock (_selectionLock) _selection = ThreadSelection.None;'), $assignRx).Count -eq 1) ''
Check 'and MoveSelection draws every epoch from the one process-wide counter, naming itself as the source' `
  ($mover -match 'new ThreadSelection\(tid, stoppedTid,\s*System\.Threading\.Interlocked\.Increment\(ref s_selectionEpoch\), cause, this\)') ''
# A NEW SESSION is a Reset, not an End: Launch is not driven here (it starts an engine), so its one call is pinned.
Check 'Launch clears the selection as a Reset, before it reports Launching' `
  ((Get-CSharpCodeOnly (Get-Content -Raw -LiteralPath $ServicePath)) -match 'MoveSelection\(null, null, ThreadSelectionCause\.Reset, true\);\s*SetState\(DebugSessionState\.Launching\);') ''

# ONE COUNTER FOR THE PROCESS (pipeline run 1, debugger L1). The Disassembly view outlives a service: when a
# different one becomes active it is rebound, and a counter per service would start the new one's epochs at 1,
# below a snapshot the view took from the old one. So a second service's first change is newer than every
# change the first one made, however many that was.
$a = New-Object ClarionDebugger.Terminal.SelectionDriver
foreach ($i in 1..5) { $a.Line((Paused 4812)); $a.Line((Picked 9001 $true)) }
$aLast = $a.Snaps[$a.Snaps.Count - 1].Epoch
$b2 = New-Object ClarionDebugger.Terminal.SelectionDriver
$b2.Line((Paused 7000))
$bFirst = $b2.Snaps[0]
Check 'a second service''s first change has a higher epoch than the first service''s last' ($bFirst.Epoch -gt $aLast) "first service last #$aLast, second service first #$($bFirst.Epoch)"
Check 'and each snapshot names the service that made it' `
  ([object]::ReferenceEquals($bFirst.Source, $b2.Svc) -and [object]::ReferenceEquals($a.Snaps[0].Source, $a.Svc)) ''
# A SWITCH KEEPS THE STOPPED THREAD it finds under the lock (code-reviewer NIT): the caller no longer passes one
# in, read outside the lock, where a concurrent end could have cleared it a moment before.
Check 'the threadselected arm passes no stopped thread; MoveSelection keeps it, first thing under the lock' `
  (((Get-CSharpCodeOnly (Get-Content -Raw -LiteralPath $ServicePath)) -match 'MoveSelection\(selTid, null, ThreadSelectionCause\.Switch, false\);') -and `
   ($mover -match 'lock \(_selectionLock\)\s*\{\s*var cur = _selection;\s*if \(cause == ThreadSelectionCause\.Switch\) stoppedTid = cur\.StoppedTid;')) ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '3. the grant table reads the service''s selection, and binds a stack request to its epoch'
$g = New-Object ClarionDebugger.Terminal.SelectionDriver
$g.Line((Paused 4812))
$id = $g.AskStack()
Check 'CONTROL: a stack reply for the selected thread, to a request of this epoch, offers' ($g.Offer(4812, $id)) ''
$idA = $g.AskStack()
$g.Line((Picked 9001 $true))
Check 'a reply for the OLD thread, after a switch, offers nothing' (-not $g.Offer(4812, $idA)) ''
$idB = $g.AskStack()
Check 'a reply stamped for another thread than the service''s selection offers nothing' (-not $g.Offer(4812, $idB)) ''
$idB2 = $g.AskStack()
$g.Line((Threads 4812 7000))
Check 'an inventory that moved the selection retires a request sent before it, with no clear between' (-not $g.Offer(7000, $idB2)) ''
$idC = $g.AskStack()
$g.Line((Picked 9001 $true)); $g.Line((Picked 7000 $true))
Check 'a selection that moved away and BACK retires the request: same thread, same live id, older epoch' (-not $g.Offer(7000, $idC)) ''
$idD = $g.AskStack()
Check 'CONTROL: a request sent under the current selection offers' ($g.Offer(7000, $idD)) ''

Assert-CheckTotal 27
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
