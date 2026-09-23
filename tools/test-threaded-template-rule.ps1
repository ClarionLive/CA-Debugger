# Source-level check: the THREADed-template question has ONE rule, over a symbol's SPAN (tickets ef0a941d,
# 3c031cdc).
#
# A start-only test - `loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi` - classified a symbol straddling
# into the shared .cwtls template as ordinary data. Run 2 of 49538b78 removed it from the module-data panel;
# the same expression then survived in Watch, the thread scan and breakpoint conditions, where it could
# change whether the developer stops. All four now ask ClassifyTemplateSpan in DebugEngine.VarEdit.cs.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE, stated up front because a green run must not imply more than it is:
#   CAN  - that no engine source file outside DebugEngine.VarEdit.cs compares an address or RVA directly
#          against CwtlsLo/CwtlsHi; that each of the four callers takes its answer from ONE
#          ClassifyTemplateSpan call and never reassigns it; and that each names the Straddling case, so
#          it made its own decision about it.
#          Also: the live THREADed resolver takes its verdict from ClassifyEmulatedInstance, the method
#          protocolcheck's CheckEmulationFaultBranches drives on injected emulations (38b75897).
#   CANNOT - that a caller does the RIGHT thing with a straddling symbol, or that the rule itself is right.
#          The rule is asserted by `ClarionDbg protocolcheck` (CheckTemplateSpanDiscriminator); what each
#          caller renders needs a live debuggee with a symbol crossing CwtlsLo, which nothing here has.
#          A comparison against a LOCAL COPY of CwtlsLo (`uint lo = m.CwtlsLo; ... va >= lo`) is not seen.
#
#   pwsh tools/test-threaded-template-rule.ps1
# Exit code 0 = all checks passed.

param(
  [string] $EngineDir = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli'),
  [string] $CoreDir   = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Core')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$script:checks = 0
$script:failures = 0

# A relational comparison with an identifier ending in Rva/Va on one side and a CwtlsLo/CwtlsHi term on the
# other, within one statement. Hi-vs-Lo size arithmetic (`CwtlsHi > CwtlsLo`) has no Rva/Va operand and is
# not matched.
$addrThenCwtls = '(?i)\b\w*(rva|va)\s*(<=|>=|<|>)\s*[^;?&|]*?\bCwtls(Lo|Hi)\b'
$cwtlsThenAddr = '(?i)\bCwtls(Lo|Hi)\b\s*(<=|>=|<|>)\s*[^;?&|]*?\b\w*(rva|va)\b'

function Find-DirectTemplateTests {
  param([string] $Code)
  $hits = @()
  foreach ($rx in @($addrThenCwtls, $cwtlsThenAddr)) {
    foreach ($m in [regex]::Matches($Code, $rx)) { $hits += $m.Value.Trim() }
  }
  return ,$hits
}

Write-Host 'the scan can fail: known-dirty inputs are flagged'
# Each is a shape that has actually shipped. Without these, a scan whose pattern matched nothing at all would
# report a clean tree.
$dirty = @(
  'bool threaded = owner.CwtlsHi != 0 && loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi;',   # ThreadScan, BpAdvanced
  'bool threaded = loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi && owner.CwtlsHi != 0;',   # Watch, reordered
  'if (va >= m.LoadBase + m.CwtlsLo) return true;',
  'if (m.CwtlsHi > ds.Rva) return true;'
)
foreach ($d in $dirty) {
  $h = Find-DirectTemplateTests $d
  Check "flagged: $d" ($h.Count -gt 0) ''
}
# ...and the comment stripper runs first, so the idiom QUOTED in a comment is not a hit.
$commented = "// the old test was ``loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi```nint x = 1;"
Check 'not flagged: the same idiom inside a comment' ((Find-DirectTemplateTests (Get-CSharpCodeOnly $commented)).Count -eq 0) ''
# Size arithmetic is not an address test.
Check 'not flagged: CwtlsHi > CwtlsLo size arithmetic' ((Find-DirectTemplateTests 'uint n = owner.CwtlsHi > owner.CwtlsLo ? owner.CwtlsHi - owner.CwtlsLo : 0;').Count -eq 0) ''

Write-Host ''
Write-Host 'no engine file outside DebugEngine.VarEdit.cs tests an address against the template directly'
$files = @(Get-ChildItem -LiteralPath $EngineDir -Filter '*.cs' -File) + @(Get-ChildItem -LiteralPath $CoreDir -Filter '*.cs' -File)
Check 'the scan found engine sources to read' ($files.Count -gt 10) "$($files.Count) files"
$varEditSeen = $false
$dirtyFiles = 0
foreach ($f in $files) {
  if ($f.Name -eq 'DebugEngine.VarEdit.cs') { $varEditSeen = $true; continue }
  $code = Get-CSharpCodeOnly (Get-Content -Raw -LiteralPath $f.FullName)
  $h = Find-DirectTemplateTests $code
  if ($h.Count -gt 0) { $dirtyFiles++; Check "$($f.Name) has no direct Rva-vs-Cwtls comparison" $false ($h -join ' | ') }
}
Check 'every other engine source file is clean' ($dirtyFiles -eq 0) "$dirtyFiles dirty"
# The exemption is by NAME, so prove the exempted file is where the rule lives - otherwise a rename would
# exempt nothing and this would still pass.
$varEdit = Get-Content -Raw -LiteralPath (Join-Path $EngineDir 'DebugEngine.VarEdit.cs')
Check 'the exempted file exists and holds TouchesThreadedTemplate' `
  ($varEditSeen -and ($varEdit -match 'private static bool TouchesThreadedTemplate\(')) ''

Write-Host ''
Write-Host 'the symbol classification asks the shared range test'
$classify = Get-CSharpBlock 'private static TemplateSpan ClassifyTemplateSpan(' $varEdit
Check 'ClassifyTemplateSpan exists' ($null -ne $classify) ''
if ($null -ne $classify) {
  Check 'and calls TouchesThreadedTemplate' ((Get-CSharpCodeOnly $classify) -match '\bTouchesThreadedTemplate\(') ''
}

Write-Host ''
Write-Host 'each caller takes ONE answer from ClassifyTemplateSpan and decides the straddling case itself'
$callers = @(
  @{ File = 'DebugEngine.BpAdvanced.cs'; Sig = 'private int ReadVarValue(' },
  @{ File = 'DebugEngine.ThreadScan.cs'; Sig = 'private void ProbeNameOnEachThread(' },
  @{ File = 'DebugEngine.Watch.cs';      Sig = 'private void HandleWatchCommand(' },
  @{ File = 'DebugEngine.Locals.cs';     Sig = 'private void HandleModuleDataCommand(' }
)
foreach ($c in $callers) {
  $src = Get-Content -Raw -LiteralPath (Join-Path $EngineDir $c.File)
  $block = Get-CSharpBlock $c.Sig $src
  if ($null -eq $block) { Check "$($c.File): $($c.Sig) exists" $false 'absent from this version of the engine'; continue }
  $code = Get-CSharpCodeOnly $block
  $calls = [regex]::Matches($code, '\bvar span = ClassifyTemplateSpan\(').Count
  # Any assignment to `span`, the declaration included. Exactly one means nothing overrides the answer
  # afterwards - `span = TemplateSpan.Outside;` below the call would disable it and keep the call text.
  $assigns = [regex]::Matches($code, '\bspan\s*=(?!=)').Count
  Check "$($c.File): one ClassifyTemplateSpan call, assigned once" (($calls -eq 1) -and ($assigns -eq 1)) "calls=$calls assignments=$assigns"
  Check "$($c.File): names TemplateSpan.Straddling" ($code -match '\bTemplateSpan\.Straddling\b') ''
}

Write-Host ''
Write-Host 'the live THREADed resolver uses the emulation verdict protocolcheck drives (38b75897)'
# protocolcheck's CheckEmulationFaultBranches runs ClassifyEmulatedInstance on injected emulations. That proves
# nothing about the live path unless TryResolveThreadedInstance reaches its verdict through the same method,
# rather than through a re-inlined copy that the harness never sees.
$watch = Get-Content -Raw -LiteralPath (Join-Path $EngineDir 'DebugEngine.Watch.cs')
$live = Get-CSharpBlock 'private ThreadedResolve TryResolveThreadedInstance(' $watch
Check 'TryResolveThreadedInstance exists' ($null -ne $live) ''
if ($null -ne $live) {
  $liveCode = Get-CSharpCodeOnly $live
  $verdicts = [regex]::Matches($liveCode, '\bvar verdict = ClassifyEmulatedInstance\(').Count
  $calls = [regex]::Matches($liveCode, '\bemu\.Call\(').Count
  Check 'it takes ONE verdict from ClassifyEmulatedInstance and runs no emulation of its own' `
    (($verdicts -eq 1) -and ($calls -eq 0)) "verdicts=$verdicts emu.Call=$calls"
  Check 'and returns every verdict but Ok straight away' `
    ($liveCode -match 'if \(verdict != ThreadedResolve\.Ok\) return verdict;') ''
}

Write-Host ''
Write-Host 'NOT PROVED HERE, and deliberately not implied by a green run:'
Write-Host '  what each caller shows or decides for a straddling symbol, and that the rule itself is right.'
Write-Host '  protocolcheck asserts the rule; the callers need a live debuggee with a symbol crossing CwtlsLo.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
