# The host's ONE selected thread (49538b78 item 8b, Owner decision 3, 2026-09-24).
#
#   pwsh -NoProfile -File tools\test-addin-selection.ps1 [-ServicePath <ClarionDebuggerService.cs>] [-HostGrantsPath <HostGrants.cs>]
#        [-WebViewPath <ClarionDebuggerWebView.cs>]
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
# Section 4 (3517fd15, contract C1) is the grant table's other half: a watch or moduledata reply GRANTS an edit
# only when it echoes a request id the pad sent in the current selection epoch. The pad's real request writers and
# reply handlers are lifted out of ClarionDebuggerWebView.cs and run over the real service's OnLine, fed the
# engine's reply in the contract's literal shape.
#
# NOT COVERED: Launch itself (it starts an engine process). Its selection reset is pinned by the single-writer
# scan below, which a reset written anywhere in the service fails. Anything live.
#
# ASCII only, for Windows PowerShell 5.1.

param(
  # Defaulted in the body: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $ServicePath = '',
  [string] $HostGrantsPath = '',
  [string] $WebViewPath = '',
  [string] $ReaderPath = '',
  [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$root = Join-Path $PSScriptRoot '..'
if (-not $ServicePath) { $ServicePath = Join-Path $root 'src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs' }
if (-not $HostGrantsPath) { $HostGrantsPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\HostGrants.cs' }
if (-not $WebViewPath) { $WebViewPath = Join-Path $root 'src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs' }
if (-not $ReaderPath) { $ReaderPath = Join-Path $root 'src\ClarionDebugger.Addin\Wire\JsonMessageReader.cs' }
$others = @('Services\RedFileService.cs', 'Services\ClarionVersionService.cs', 'Wire\WireRules.cs',
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
    @{ Id = 'S7'; File = 'grants'; Why = 'the grant table does not retire itself when the selection moves (Sync)';
       Find = 'if (now == _epoch) return;'; Repl = 'if (now == _epoch || now > 0) return;' }
    @{ Id = 'S8'; File = 'grants'; Why = 'HostGrants offers for a thread that is not the service''s selection';
       Find = 'if (!WireRules.TidIsKnown(tid) || tid != sel.Tid) return false;'; Repl = 'if (!WireRules.TidIsKnown(tid)) return false;' }
    @{ Id = 'S10'; File = 'svc'; Why = 'each service counts its own epochs (the counter is per instance)';
       Find = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, this);'; Repl = 'cur.Epoch + 1, cause, this);' }
    @{ Id = 'S11'; File = 'svc'; Why = 'a switch does not keep the stopped thread the selection holds';
       Find = 'if (cause == ThreadSelectionCause.Switch) stoppedTid = cur.StoppedTid;'; Repl = '' }
    @{ Id = 'S12'; File = 'svc'; Why = 'a snapshot does not name the service that made it';
       Find = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, this);'; Repl = 'System.Threading.Interlocked.Increment(ref s_selectionEpoch), cause, null);' }
    @{ Id = 'G1'; File = 'grants'; Why = 'a watch/moduledata reply grants for an id the pad never sent, or already spent';
       Find = 'return reqId != null && _readIds.Remove(reqId);'; Repl = 'return reqId != null;' }
    @{ Id = 'G2'; File = 'grants'; Why = 'a reply with no reqId (an older engine) grants';
       Find = 'return reqId != null && _readIds.Remove(reqId);'; Repl = 'return reqId == null || _readIds.Remove(reqId);' }
    @{ Id = 'G3'; File = 'grants'; Why = 'a resume spares what its own epoch issued';
       Find = 'if (epoch < _epoch) return;'; Repl = 'if (epoch <= _epoch) return;' }
    @{ Id = 'G4'; File = 'grants'; Why = 'a resume retires what a NEWER epoch has already issued';
       Find = 'if (epoch < _epoch) return;'; Repl = 'if (epoch < _epoch && epoch < 0) return;' }
    @{ Id = 'W1'; File = 'web'; Why = 'OnWatch grants a found reply whatever request it answers';
       Find = 'if (w.Found && mayGrant)'; Repl = 'if (w.Found)' }
    @{ Id = 'W2'; File = 'web'; Why = 'OnSvcModuleData grants whatever request it answers';
       Find = 'if (mayGrant) _editGrants.GrantRows(itemsJson, tid);'; Repl = '_editGrants.GrantRows(itemsJson, tid);' }
    @{ Id = 'W3'; File = 'web'; Why = 'WatchOrExplain does not record the id it sent';
       Find = 'if (_svc.Watch(name, id)) _editGrants.ReadRequested(id);'; Repl = 'if (_svc.Watch(name, id)) { }' }
    @{ Id = 'W4'; File = 'web'; Why = 'RequestModuleData does not record the id it sent';
       Find = 'if (_svc.RequestModuleData(id)) _editGrants.ReadRequested(id);'; Repl = 'if (_svc.RequestModuleData(id)) { }' }
    @{ Id = 'W5'; File = 'web'; Why = 'the resume reads its epoch inside the marshal, where a newer stop''s can already be';
       Find = 'int epoch = _svc.Selection.Epoch; UI(() => { _editGrants.Resumed(epoch);'; Repl = 'UI(() => { int epoch = _svc.Selection.Epoch; _editGrants.Resumed(epoch);' }
    @{ Id = 'V1'; File = 'svc'; Why = 'the service drops the moduledata reply''s reqId';
       Find = "GetUIntOrNull(json, `"tid`"),`n                                               GetStr(json, `"reqId`"));"; Repl = 'GetUIntOrNull(json, "tid"), null);' }
    @{ Id = 'V2'; File = 'svc'; Why = 'ParseWatch drops the watch reply''s reqId';
       Find = 'w.ReqId = GetStr(json, "reqId");'; Repl = '' }
    @{ Id = 'S13'; File = 'grants'; Why = 'the edit authorization check does not sync to the service epoch';
       Find = "// switch or disagreeing inventory is refused here with no other call on the table in between.`n            Sync();";
       Repl = '// switch or disagreeing inventory is refused here with no other call on the table in between.' }
    @{ Id = 'S14'; File = 'grants'; Why = 'the frame offer path does not sync to the service epoch';
       Find = "// retires it here, with everything else from that epoch.`n            Sync();";
       Repl = '// retires it here, with everything else from that epoch.' }
    @{ Id = 'Y1'; File = 'grants'; Why = 'ExpandVerified does not sync';
       Find = 'public bool ExpandVerified(string reqId) { Sync(); return'; Repl = 'public bool ExpandVerified(string reqId) { return' }
    @{ Id = 'Y2'; File = 'grants'; Why = 'IsFrameOffered does not sync';
       Find = "public bool IsFrameOffered(string va, string ebp)`n        {`n            Sync();"; Repl = "public bool IsFrameOffered(string va, string ebp)`n        {" }
    @{ Id = 'Y3'; File = 'grants'; Why = 'IsWritePending does not sync';
       Find = "public bool IsWritePending(string va)`n        {`n            Sync();"; Repl = "public bool IsWritePending(string va)`n        {" }
    @{ Id = 'Y4'; File = 'grants'; Why = 'IsGranted does not sync';
       Find = "public bool IsGranted(string va, string typeCode, int size, int places, uint? tid)`n        {`n            Sync();"; Repl = "public bool IsGranted(string va, string typeCode, int size, int places, uint? tid)`n        {" }
    @{ Id = 'Y5'; File = 'grants'; Why = 'Count does not sync';
       Find = 'public int Count { get { Sync(); return'; Repl = 'public int Count { get { return' }
    @{ Id = 'Y6'; File = 'grants'; Why = 'ExpandableCount does not sync';
       Find = 'public int ExpandableCount { get { Sync(); return'; Repl = 'public int ExpandableCount { get { return' }
    @{ Id = 'Y7'; File = 'grants'; Why = 'Grant does not sync, so a grant made first after a move is lost';
       Find = "public void Grant(string va, string typeCode, int size, int places, uint? tid)`n        {`n            Sync();"; Repl = "public void Grant(string va, string typeCode, int size, int places, uint? tid)`n        {" }
    @{ Id = 'Y8'; File = 'grants'; Why = 'GrantExpandable does not sync';
       Find = "public void GrantExpandable(string module, uint typeRef, string addr)`n        {`n            Sync();"; Repl = "public void GrantExpandable(string module, uint typeRef, string addr)`n        {" }
    @{ Id = 'Y9'; File = 'grants'; Why = 'ExpandForwarded does not sync';
       Find = 'public void ExpandForwarded(int reqId) { Sync(); _expands'; Repl = 'public void ExpandForwarded(int reqId) { _expands' }
    @{ Id = 'R1'; File = 'web'; Why = 'OnWatch posts the edit tuple for a reply that granted nothing';
       Find = "if (mayGrant)`n                    sb.Append(`",\`"va\`":`")"; Repl = "if (w.Found)`n                    sb.Append(`",\`"va\`":`")" }
    @{ Id = 'R2'; File = 'web'; Why = 'an ungranted moduledata reply is posted verbatim';
       Find = 'if (granted || string.IsNullOrEmpty(itemsJson)) return itemsJson ?? "";'; Repl = 'if (itemsJson != null || granted) return itemsJson ?? "";' }
    @{ Id = 'P1'; File = 'reader'; Why = 'the stripper takes any unquoted word as a literal';
       Find = 'return tok == "true" || tok == "false" || tok == "null" || s_jsonNumber.IsMatch(tok);'; Repl = 'return tok.Length > 0 && (tok[0] != ''-'' && !char.IsDigit(tok[0]) || s_jsonNumber.IsMatch(tok));' }
    @{ Id = 'P2'; File = 'reader'; Why = 'the stripper takes any run of digit-ish characters as a number';
       Find = 'return tok == "true" || tok == "false" || tok == "null" || s_jsonNumber.IsMatch(tok);'; Repl = 'return tok == "true" || tok == "false" || tok == "null" || (tok.Length > 0 && (tok[0] == ''-'' || tok[0] == ''+'' || tok[0] == ''.'' || char.IsDigit(tok[0])));' }
    @{ Id = 'S9'; File = 'svc'; Why = 'the session end leaves the selection standing';
       Find = "SetState(DebugSessionState.Idle);`n                MoveSelection(null, null, ThreadSelectionCause.Ended, true);";
       Repl = 'SetState(DebugSessionState.Idle);' }
  )
  $base = Join-Path ([IO.Path]::GetTempPath()) ('selection-selftest-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $base | Out-Null
  try {
    $src = @{ svc = $ServicePath; grants = $HostGrantsPath; web = $WebViewPath; reader = $ReaderPath }
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
      $out = & pwsh -NoProfile -File $PSCommandPath -ServicePath (Join-Path $d 'ClarionDebuggerService.cs') -HostGrantsPath (Join-Path $d 'HostGrants.cs') `
        -WebViewPath (Join-Path $d 'ClarionDebuggerWebView.cs') -ReaderPath (Join-Path $d 'JsonMessageReader.cs') 2>&1
      $code = $LASTEXITCODE
      $passed = [bool](@($out) -match '^ALL \d+ CHECKS PASSED')
      $compiled = [bool](@($out) -match '^compiled the service and the grant table$')
      $fails = (@($out) -match '^\s*FAIL' | Select-Object -First 2) -join ' / '
      if ($r.Id -eq 'CONTROL') { Check 'CONTROL: the unmutated copies pass' ($passed -and $code -eq 0) "exit=$code" }
      else { Check "$($r.Id) CAUGHT: $($r.Why)" ($compiled -and (-not $passed) -and $code -ne 0) "exit=$code compiled=$compiled $fails" }
    }
  } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
  # 38 finds + 38 mutations + 1 control
  Assert-CheckTotal 77
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ================================================================================================ compile
# The pad's grant half, lifted out of the WebView as it ships (section 4). An arrow handler brace-matches to its
# lambda's closing brace; the `);` that closes UI( is put back.
$web = Get-Content -Raw -LiteralPath $WebViewPath
$liftTidNames = @('private const string TidMemberTid', 'private const string TidMemberStopped', 'private const string TidMemberSelected',
  'private static readonly string[] TidValuedMemberNames') | ForEach-Object { Get-Statement $_ $web }
$lifted = @(
  (Get-Method 'private static string Str(string s)' $web),
  (Get-Method 'private static string TidJson(uint? tid)' $web),
  (Get-Method 'private static string TidMember(string name, uint? tid)' $web),
  (($liftTidNames) -join "`n"),
  ((Get-Method 'private void WatchOrExplain(string name)' $web) -replace '^private void', 'public void'),
  ((Get-Method 'private void RequestModuleData()' $web) -replace '^private void', 'public void'),
  ((Get-Method 'private void RequestStack()' $web) -replace '^private void', 'public void'),
  (Get-Method 'private void OnWatch(DebugWatch w)' $web),
  ((Get-Method 'private void OnSvcModuleData(' $web) + ');'),
  (Get-Statement 'private static readonly string[] EditTupleMembers' $web),
  (Get-Method 'private static string RowsAsGranted(string itemsJson, bool granted)' $web),
  (Get-Method 'private void OnSvcResumed(string mode)' $web)
) -join "`n"
$probe = @"
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using ClarionDebugger.Services;
using ClarionDebugger.Wire;

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
    public string AskStack() { string id = _grants.NewRequestId(); _grants.StackRequested(id); return id; }
    public bool Offer(uint tid, string id) {
      return _grants.OfferFrames(tid, id, new[] { new KeyValuePair<string, string>("0x402000", "0x19FF40") });
    }
  }

  // What the lifted request writers call as _svc: the service's SENDING side, recorded (SendCommand needs an engine
  // process), and its selection, read from the real service. Every reply comes through the real service's OnLine.
  public sealed class PadSvc {
    private readonly ClarionDebuggerService _real;
    public PadSvc(ClarionDebuggerService real) { _real = real; }
    public ThreadSelection Selection { get { return _real.Selection; } }
    public string LastWatchId, LastModuleDataId, LastStackId;
    public bool Watch(string name, string reqId) { LastWatchId = reqId; return true; }
    public bool RequestModuleData(string reqId) { LastModuleDataId = reqId; return true; }
    public bool RequestStack(string reqId) { LastStackId = reqId; return true; }
  }

  // The pad's grant half over the real service and the real EditGrants. UI() runs at once, or - with Hold - waits
  // in Queue, as a BeginInvoke waits behind whatever the UI thread is doing.
  public sealed class GrantPad {
    public readonly SelectionDriver D = new SelectionDriver();
    public readonly PadSvc _svc;
    private readonly EditGrants _editGrants;
    public readonly List<string> Posts = new List<string>();
    public bool Hold;
    public readonly List<Action> Queue = new List<Action>();
    private DebugPause _stopSource;
    public GrantPad() {
      _svc = new PadSvc(D.Svc);
      _editGrants = new EditGrants(() => D.Svc.Selection);
      D.Svc.WatchReceived += w => UI(() => OnWatch(w));   // OnSvcWatch, whose one line is pinned below
      D.Svc.ModuleDataReceived += OnSvcModuleData;
      D.Svc.Resumed += OnSvcResumed;
    }
    public void Drain() { var q = new List<Action>(Queue); Queue.Clear(); foreach (var a in q) a(); }
    private void UI(Action a) { if (Hold) Queue.Add(a); else a(); }
    private void Post(string s) { Posts.Add(s); }
    private void Console(string level, string text) { }
    private void ClearExecutionLineIfHooked() { }
    public bool Granted(string va, uint tid) { return _editGrants.IsGranted(va, "0x03", 4, 0, tid); }
    public static string Strip(string json) { return JsonMessageReader.WithoutMembers(json, EditTupleMembers); }   // the pad's own list, lifted
    public static string ReadOnlyRows(string items) { return RowsAsGranted(items, false); }
    // The edit authorization check itself (EditVar's TryConsume), called with nothing in front of it.
    public bool Consume(string va, uint tid) { return _editGrants.TryConsume(va, "0x03", 4, 0, tid); }
    // Each table member on its own, for section 5: a move, then ONLY that call.
    public void GrantNow(string va, uint tid) { _editGrants.Grant(va, "0x03", 4, 0, tid); }
    public void ExpandableNow(string addr) { _editGrants.GrantExpandable("clbrws011.clw", 77, addr); }
    public bool ExpandIssued(string addr) { return _editGrants.IsExpandIssued("clbrws011.clw", 77, addr); }
    public void ExpandForwarded(int reqId) { _editGrants.ExpandForwarded(reqId); }
    public bool ExpandVerified(string reqId) { return _editGrants.ExpandVerified(reqId); }
    public bool FrameOffered() { return _editGrants.IsFrameOffered("0x402000", "0x19FF40"); }
    public bool WritePending(string va) { return _editGrants.IsWritePending(va); }
    public int Count { get { return _editGrants.Count; } }
    public int ExpandableCount { get { return _editGrants.ExpandableCount; } }
    public bool Offer(uint tid, string id) {
      return _editGrants.OfferFrames(tid, id, new[] { new KeyValuePair<string, string>("0x402000", "0x19FF40") });
    }
    $lifted
  }
}
"@
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('selection-probe-' + [guid]::NewGuid().ToString('N') + '.cs')
[IO.File]::WriteAllText($tmp, $probe)
try {
  $paths = @($ServicePath, $HostGrantsPath, $ReaderPath) + $others | ForEach-Object { (Resolve-Path -LiteralPath $_).Path }
  Add-Type -Path ($paths + $tmp) -IgnoreWarnings -WarningAction SilentlyContinue -ReferencedAssemblies @(
    'System.Xml', 'System.Xml.ReaderWriter', 'System.Diagnostics.Process', 'System.Diagnostics.FileVersionInfo',
    'System.ComponentModel.Primitives', 'System.Text.RegularExpressions', 'System.Collections', 'System.Linq',
    'System.Threading', 'System.Threading.Thread', 'System.Runtime.InteropServices', 'System.Diagnostics.Debug') | Out-Null
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
# The engine's watch and moduledata replies, in the contract's literal shape (C1): "reqId" is a STRING member,
# present only when the request carried reqid=N.
function IdMember { param($reqId) if ($null -ne $reqId) { ',"reqId":"' + $reqId + '"' } else { '' } }
function WatchHit { param($tid, $reqId, [string] $va = '0x4A10F0')
  '{"event":"watch","name":"GLO:X","found":true,"threaded":false,"typeName":"LONG","value":"5","va":"' + $va + '","type":"0x03","size":4,"places":0,"tid":' + $tid + (IdMember $reqId) + '}'
}
function WatchMiss { param($tid, $reqId) '{"event":"watch","name":"GLO:X","found":false,"outOfScope":false,"error":null,"tid":' + $tid + (IdMember $reqId) + '}' }
function ModData { param($tid, $reqId, [string] $va = '0x4A2200')
  '{"event":"moduledata","module":"clbrws011.clw","items":[{"name":"G:X","type":"LONG","value":"1","va":"' + $va + '","typeCode":"0x03","size":4,"places":0}],"tid":' + $tid + (IdMember $reqId) + '}'
}
function Resumed { '{"event":"resumed","mode":"continue"}' }

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

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '4. a watch or moduledata reply grants only for a request the pad sent in this epoch (3517fd15, contract C1)'
$p = New-Object ClarionDebugger.Terminal.GrantPad
$p.D.Line((Paused 4812))
$p.WatchOrExplain('GLO:X'); $w1 = $p._svc.LastWatchId
$p.D.Line((WatchHit 4812 $w1))
Check 'CONTROL: the reply to the watch the pad sent in this epoch grants its row' ($p.Granted('0x4A10F0', 4812)) "id=$w1"
$p.D.Line((WatchHit 4812 $w1 '0x4A10F4'))
Check 'the same id answered twice grants once: an answered id is spent' (-not $p.Granted('0x4A10F4', 4812)) ''
$p.D.Line((WatchHit 4812 '999999' '0x4A10F8'))
Check 'an id the pad never sent grants nothing' (-not $p.Granted('0x4A10F8', 4812)) ''
$n = $p.Posts.Count
$p.D.Line((WatchHit 4812 $null '0x4A10FC'))
Check 'a reply with NO reqId (an engine older than the echo) grants nothing' (-not $p.Granted('0x4A10FC', 4812)) ''
Check '...and is still shown: the value is posted, read-only' (($p.Posts.Count -eq $n + 1) -and ($p.Posts[$n] -cmatch '"found":true,"value":"5"')) (($p.Posts | Select-Object -Skip $n) -join ' / ')
$p.WatchOrExplain('GLO:X'); $wMiss = $p._svc.LastWatchId
$p.D.Line((WatchMiss 4812 $wMiss))
$p.D.Line((WatchHit 4812 $wMiss '0x4A1100'))
Check 'a MISS answers its request too: a hit echoing that id afterwards grants nothing' (-not $p.Granted('0x4A1100', 4812)) ''

# THE CODEX SCENARIO: a watch reply delayed past a resume and the next stop, on the same thread.
$r = New-Object ClarionDebugger.Terminal.GrantPad
$r.D.Line((Paused 4812))
$r.WatchOrExplain('GLO:X'); $old = $r._svc.LastWatchId
$r.D.Line((Resumed))
$r.D.Line((Paused 4812))
$r.WatchOrExplain('GLO:X'); $new = $r._svc.LastWatchId
$r.D.Line((WatchHit 4812 $old))
Check 'an OLD watch reply, after a resume and a new stop on the same thread, grants nothing' (-not $r.Granted('0x4A10F0', 4812)) "old=$old new=$new"
$r.D.Line((WatchHit 4812 $new))
Check 'CONTROL: the new stop''s own reply grants' ($r.Granted('0x4A10F0', 4812)) "new=$new"

# An id from an OLDER epoch of the same stop: the selection moved under it, with no resume.
$e = New-Object ClarionDebugger.Terminal.GrantPad
$e.D.Line((Paused 4812))
$e.WatchOrExplain('GLO:X'); $pre = $e._svc.LastWatchId
$e.D.Line((Threads 4812 9001))
$e.D.Line((WatchHit 9001 $pre))
Check 'an id from before an inventory moved the selection grants nothing, whatever thread its reply names' (-not $e.Granted('0x4A10F0', 9001)) "id=$pre"
$e.WatchOrExplain('GLO:X'); $pre2 = $e._svc.LastWatchId
$e.D.Line((Picked 7000 $true))
$e.D.Line((WatchHit 7000 $pre2))
Check 'and so does one from before an accepted switch' (-not $e.Granted('0x4A10F0', 7000)) "id=$pre2"

# moduledata: the same rule, through the real request writer and the real reply handler.
$m = New-Object ClarionDebugger.Terminal.GrantPad
$m.D.Line((Paused 4812))
$m.RequestModuleData(); $m1 = $m._svc.LastModuleDataId
$m.D.Line((ModData 4812 $m1))
Check 'CONTROL: the moduledata reply to this epoch''s request grants its rows' ($m.Granted('0x4A2200', 4812)) "id=$m1"
$m.RequestModuleData(); $mOld = $m._svc.LastModuleDataId
$m.D.Line((Resumed)); $m.D.Line((Paused 4812))
$m.D.Line((ModData 4812 $mOld '0x4A2204'))
Check 'an OLD moduledata reply, after a resume and a new stop, grants nothing' (-not $m.Granted('0x4A2204', 4812)) "id=$mOld"
$n = $m.Posts.Count
$m.D.Line((ModData 4812 $null '0x4A2208'))
Check 'a moduledata reply with no reqId grants nothing, and is still posted' `
  ((-not $m.Granted('0x4A2208', 4812)) -and ($m.Posts.Count -eq $n + 1) -and ($m.Posts[$n] -cmatch '"type":"moduledata"')) (($m.Posts | Select-Object -Skip $n) -join ' / ')

# A RESUME moves no selection, so the table cannot see it; the pad's resume handler retires it - including what
# was issued in the epoch it resumed from.
$s = New-Object ClarionDebugger.Terminal.GrantPad
$s.D.Line((Paused 4812))
$s.WatchOrExplain('GLO:X'); $sw = $s._svc.LastWatchId
$s.D.Line((WatchHit 4812 $sw))
$s.WatchOrExplain('GLO:X'); $late = $s._svc.LastWatchId
$s.D.Line((Resumed))
Check 'a resume retires the grants its own stop issued' (-not $s.Granted('0x4A10F0', 4812)) ''
$s.D.Line((WatchHit 4812 $late '0x4A1200'))
Check 'and a reply arriving after the resume, before any stop, grants nothing' (-not $s.Granted('0x4A1200', 4812)) "id=$late"

# ORDER (debugger L2, wave 6): a marshalled clear must not wipe what the UI thread recorded before it ran. The
# resume's clear is the one marshalled clear left, so it names the epoch it was raised in: a stop that followed
# it, and a request bound under that stop before the clear ran, survive it.
$o = New-Object ClarionDebugger.Terminal.GrantPad
$o.D.Line((Paused 4812))
$o.Hold = $true
$o.D.Line((Resumed))                    # the resume's clear waits behind the UI thread...
$o.D.Line((Paused 4812))                # ...the next stop arrives...
$o.Hold = $false
$o.RequestModuleData(); $oid = $o._svc.LastModuleDataId   # ...and the page's request runs first
$o.WatchOrExplain('GLO:X'); $owid = $o._svc.LastWatchId
$o.RequestStack(); $osid = $o._svc.LastStackId
$o.Drain()
$o.D.Line((ModData 4812 $oid)); $o.D.Line((WatchHit 4812 $owid))
Check 'a resume''s queued clear does not retire requests the NEXT stop bound before it ran' `
  ($o.Granted('0x4A2200', 4812) -and $o.Granted('0x4A10F0', 4812)) "moduledata=$oid watch=$owid"
Check '...stack included: its reply still offers frames' ($o.Offer(4812, $osid)) "id=$osid"
# The selection moves (a stop, a switch, an inventory) have no marshalled clear at all: the table sees the move.
$l = New-Object ClarionDebugger.Terminal.GrantPad
$l.D.Line((Paused 4812))
$l.Hold = $true
$l.D.Line((Threads 4812 9001))          # an inventory moves the selection while the UI thread is busy
$l.Hold = $false
$l.RequestStack(); $lid = $l._svc.LastStackId
$l.RequestModuleData(); $lmid = $l._svc.LastModuleDataId
$l.Drain()
$l.D.Line((ModData 9001 $lmid))
Check 'a request bound after an inventory moved the selection is answered, with nothing queued to wipe it' `
  ($l.Offer(9001, $lid) -and $l.Granted('0x4A2200', 9001)) "stack=$lid moduledata=$lmid"
# THE LAZY CLEAR IS ONLY AS GOOD AS ITS READERS (PM's condition, 3517fd15): a move must be noticed by the very call
# that would honour a stale grant or offer, with NO other call on the table in between.
$z = New-Object ClarionDebugger.Terminal.GrantPad
$z.D.Line((Paused 4812))
$z.WatchOrExplain('GLO:X'); $z.D.Line((WatchHit 4812 $z._svc.LastWatchId))
$z.D.Line((Picked 9001 $true))
Check 'a grant minted before a switch is refused by the edit check alone, nothing called in between' (-not $z.Consume('0x4A10F0', 4812)) ''
$z2 = New-Object ClarionDebugger.Terminal.GrantPad
$z2.D.Line((Paused 4812))
$z2.WatchOrExplain('GLO:X'); $z2.D.Line((WatchHit 4812 $z2._svc.LastWatchId))
Check 'CONTROL: before any move, the edit check honours that grant' ($z2.Consume('0x4A10F0', 4812)) ''
$y = New-Object ClarionDebugger.Terminal.GrantPad
$y.D.Line((Paused 4812))
$y.RequestStack(); $yid = $y._svc.LastStackId
$y.D.Line((Threads 4812 9001))
Check 'a stack reply to a request sent before an inventory moved the selection offers nothing, the offer call alone deciding' `
  (-not $y.Offer(9001, $yid)) "id=$yid"
# DISPLAY ONLY MEANS NO EDIT TUPLE ON THE PAGE (codex security, pipeline run 1). A reply that grants nothing was
# still posted with va/typeCode/size/places, so the page drew an edit pencil the host then refused.
function Last { param($t) $t.Posts[$t.Posts.Count - 1] }
$tupleRx = '"(va|typeCode|size|places)":'
$d = New-Object ClarionDebugger.Terminal.GrantPad
$d.D.Line((Paused 4812))
$d.WatchOrExplain('GLO:X'); $d.D.Line((WatchHit 4812 $d._svc.LastWatchId))
Check 'CONTROL: the current reply posts its edit tuple, and its View-memory addr' `
  (((Last $d) -cmatch '"va":"0x4A10F0","typeCode":"0x03","size":4,"places":0') -and ((Last $d) -cmatch '"addr":null')) (Last $d)
$d.D.Line((WatchHit 4812 $null '0x4A1300'))
Check 'a watch reply with no reqId is posted with NO edit tuple, the rest intact' `
  (((Last $d) -notmatch $tupleRx) -and ((Last $d) -cmatch '"found":true,"value":"5","typeName":"LONG","threaded":false,"note":null,"addr":null')) (Last $d)
$d.WatchOrExplain('GLO:X'); $stale = $d._svc.LastWatchId
$d.D.Line((Picked 9001 $true))
$d.D.Line((WatchHit 9001 $stale '0x4A1304'))
Check 'a watch reply with a STALE reqId is posted with no edit tuple' ((Last $d) -notmatch $tupleRx) (Last $d)
$d.RequestModuleData(); $mid = $d._svc.LastModuleDataId
$d.D.Line((ModData 9001 $mid))
Check 'CONTROL: the current moduledata reply keeps its rows'' edit tuples' ((Last $d) -cmatch '"va":"0x4A2200","typeCode":"0x03","size":4,"places":0') (Last $d)
$d.D.Line((ModData 9001 $null '0x4A2300'))
Check 'a moduledata reply with no reqId is posted with no edit tuple, the rest of the row kept' `
  (((Last $d) -notmatch $tupleRx) -and ((Last $d) -cmatch '\{"name":"G:X","type":"LONG","value":"1"\}')) (Last $d)
$d.D.Line((ModData 9001 $mid '0x4A2304'))
Check 'a moduledata reply with a spent reqId is posted with no edit tuple' ((Last $d) -notmatch $tupleRx) (Last $d)
# The stripper walks JSON, not text: a key-like run inside a string survives, nested children lose theirs, and
# text that is not JSON strips to nothing rather than to a guess.
$GP = [ClarionDebugger.Terminal.GrantPad]
$nested = '[{"name":"G","value":"has \"va\":\"0x1\" in it","va":"0x10","typeCode":"0x03","size":4,"places":0,"addr":"0x10","children":[{"name":"C","va":"0x14","typeCode":"0x03","size":4,"places":0,"addr":"0x14"}]},{"name":"R","ref":true,"addr":"0x4B0000","module":"m.clw","typeRef":7}]'
$want = '[{"name":"G","value":"has \"va\":\"0x1\" in it","addr":"0x10","children":[{"name":"C","addr":"0x14"}]},{"name":"R","ref":true,"addr":"0x4B0000","module":"m.clw","typeRef":7}]'
Check 'the stripper removes the tuple at every depth, keeps a string that merely contains one, and keeps what expand needs' `
  ($GP::Strip($nested) -ceq $want) ($GP::Strip($nested))
Check 'text that is not well-formed strips to nothing' (($null -eq $GP::Strip('[{"va":"0x1"')) -and ($null -eq $GP::Strip('[{"a":1}] x'))) ''
# PRIMITIVES ARE VALIDATED (codex security, pipeline run 2): any run of characters used to pass as a value, so
# `"name":bad` survived the strip and the page was posted broken JSON instead of no rows.
$tuple = ',"va":"0x1","typeCode":"0x03","size":4,"places":0'
$badPrims = @('bad', 'True', 'nul', '01', '1.', '.5', '+1', '0x10', '1e', '--1', '1.5.2')
$badLet = @($badPrims | Where-Object { $null -ne $GP::Strip('[{"name":' + $_ + $tuple + '}]') })
Check 'a bad literal or number anywhere makes the strip fail: bad, True, nul, 01, 1., .5, +1, 0x10, 1e, --1, 1.5.2' ($badLet.Count -eq 0) ($badLet -join ', ')
$cut = @('[{"name":"G"', '[{"name":"G', '[{"name":"G","children":[', '[{"name":"G"}', '[{"name":"G"}]]', '[{"name":"G"}] ,', '[{"name":"G"}]{}')
$cutLet = @($cut | Where-Object { $null -ne $GP::Strip($_) })
Check 'a truncated string, object or array, or anything after the top-level value, strips to nothing' ($cutLet.Count -eq 0) ($cutLet -join ' | ')
Check 'and such a reply is posted as NO rows, never as broken ones' ($GP::ReadOnlyRows('{"name":bad' + $tuple + '}') -ceq '') ($GP::ReadOnlyRows('{"name":bad' + $tuple + '}'))
$goodPrims = '[{"a":0,"b":-1,"c":12.5,"d":-0.25,"e":1e3,"f":2E-4,"g":6.02e+23,"h":true,"i":false,"j":null' + $tuple + '}]'
Check 'CONTROL: every valid primitive survives the strip unchanged' `
  ($GP::Strip($goodPrims) -ceq '[{"a":0,"b":-1,"c":12.5,"d":-0.25,"e":1e3,"f":2E-4,"g":6.02e+23,"h":true,"i":false,"j":null}]') ($GP::Strip($goodPrims))
Check 'the pad wires the watch reply exactly as OnSvcWatch does: marshal, then OnWatch' `
  ((Get-CSharpCodeOnly $web) -match 'private void OnSvcWatch\(DebugWatch w\) => UI\(\(\) => OnWatch\(w\)\);') ''

# ------------------------------------------------------------------------------------------------------------
Write-Host ''
Write-Host '5. every member of the grant table notices a selection move by itself (3517fd15)'
# Each check: state made in one epoch, the selection moves (an accepted switch), and then ONE member is called with
# nothing in front of it. A reader must answer for the new epoch; a writer must record into it, not into the old
# table the next read will retire. (Regrant and FrameLocalsForwarded do not sync, and say why in HostGrants.cs.)
function Fresh { $t = New-Object ClarionDebugger.Terminal.GrantPad; $t.D.Line((Paused 4812)); $t }
function MoveSel { param($t) $t.D.Line((Picked 9001 $true)) }
$t = Fresh; $t.ExpandableNow('0x4B0000'); $t.ExpandForwarded(7)
Check 'CONTROL: a forwarded expand is verified in its own epoch' ($t.ExpandVerified('7')) ''
$t = Fresh; $t.ExpandableNow('0x4B0000'); $t.ExpandForwarded(7); MoveSel $t
Check 'ExpandVerified: an expand forwarded before the move grants nothing after it' (-not $t.ExpandVerified('7')) ''
$t = Fresh; $t.RequestStack(); [void]$t.Offer(4812, $t._svc.LastStackId)
Check 'CONTROL: an offered frame is offered in its own epoch' ($t.FrameOffered()) ''
$t = Fresh; $t.RequestStack(); [void]$t.Offer(4812, $t._svc.LastStackId); MoveSel $t
Check 'IsFrameOffered: a frame offered before the move is not offered after it' (-not $t.FrameOffered()) ''
$t = Fresh; $t.GrantNow('0x4A10F0', 4812); [void]$t.Consume('0x4A10F0', 4812)
Check 'CONTROL: a spent grant leaves its write pending' ($t.WritePending('0x4A10F0')) ''
$t = Fresh; $t.GrantNow('0x4A10F0', 4812); [void]$t.Consume('0x4A10F0', 4812); MoveSel $t
Check 'IsWritePending: a write sent before the move is not pending after it (the refusal says stale, not pending)' (-not $t.WritePending('0x4A10F0')) ''
$t = Fresh; $t.GrantNow('0x4A10F0', 4812); MoveSel $t
Check 'IsGranted: a grant made before the move is not granted after it' (-not $t.Granted('0x4A10F0', 4812)) ''
$t = Fresh; $t.GrantNow('0x4A10F0', 4812); MoveSel $t
Check 'Count: it counts none of them after it' ($t.Count -eq 0) "$($t.Count)"
$t = Fresh; $t.ExpandableNow('0x4B0000'); MoveSel $t
Check 'ExpandableCount: nor any expandable row' ($t.ExpandableCount -eq 0) "$($t.ExpandableCount)"
$t = Fresh; MoveSel $t; $t.GrantNow('0x4A10F4', 9001)
Check 'Grant: a grant made as the FIRST call after a move stands' ($t.Granted('0x4A10F4', 9001)) ''
$t = Fresh; MoveSel $t; $t.ExpandableNow('0x4C0000')
Check 'GrantExpandable: an expandable row recorded first after a move is issued' ($t.ExpandIssued('0x4C0000')) ''
$t = Fresh; MoveSel $t; $t.ExpandForwarded(9)
Check 'ExpandForwarded: an expand forwarded after a move is verified' ($t.ExpandVerified('9')) ''

Assert-CheckTotal 73
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
