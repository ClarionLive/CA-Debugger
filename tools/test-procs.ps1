# The attach picker's process enumerator (ticket 3f2d747f part B): PeProbe, the headers-only PE probe in
# ClarionDbg.Core, and the `ClarionDbg procs --json` verb built on it.
#
#   pwsh -NoProfile -File tools\test-procs.ps1              # the suite
#   pwsh -NoProfile -File tools\test-procs.ps1 -SelfTest    # the suite must go red with the TSWD test broken
#   pwsh -NoProfile -File tools\test-procs.ps1 -WithClarion # plus: a running TSWD app is listed (opens a window)
# Exit code 0 = all checks passed.
#
# PeProbe is compiled from source with Add-Type into THIS (64-bit) process. That matters: the engine is x86,
# and an x86 process that opens C:\Windows\System32\notepad.exe is silently redirected to the x86 copy in
# SysWOW64, so an "x64 is rejected" check run through the engine would be probing the wrong file.
param(
  [string] $Engine = "$PSScriptRoot\..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe",
  # A Clarion example built with full debug info. Absent -> the TSWD checks are SKIPPED, loudly.
  [string] $TswdImage = 'C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses\clbrws.exe',
  [switch] $SelfTest,
  [switch] $WithClarion,
  # Internal, used by -SelfTest: compile PeProbe with a planted fault. Needs a fresh process (Add-Type
  # cannot redefine a loaded type), which is why -SelfTest spawns one per mutant.
  [ValidateSet('', 'tswd-inverted')] [string] $Mutate = ''
)

. "$PSScriptRoot\lib-check.ps1"

$X86Plain = "$env:WINDIR\SysWOW64\PING.EXE"      # x86, no TSWD; also the live stand-in below (console, no window)
$X64Image = "$env:WINDIR\System32\notepad.exe"
$haveTswd = Test-Path -LiteralPath $TswdImage

# ---------------------------------------------------------------------------------------------------------
if ($SelfTest) {
  Write-Host 'test-procs -SelfTest: the suite must go red when PeProbe''s TSWD test is broken'
  Write-Host ''
  Invoke-CheckSection 'tswd-inverted: PeProbe reports TSWD for exactly the images without it' {
    $out = @(& pwsh -NoProfile -File $PSCommandPath -Mutate tswd-inverted -Engine $Engine -TswdImage $TswdImage 2>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    # Fail closed: the mutant counts as CAUGHT only if it provably compiled and ran with the plant in it,
    # and then failed the check aimed at it. A mutant that never compiled also exits non-zero.
    Check 'the mutant compiled with the plant applied' ($out -contains 'MUTATION APPLIED: tswd-inverted') ($out | Select-Object -Last 3 | Out-String).Trim()
    Check 'the mutant run exited non-zero' ($code -ne 0) "exit $code"
    $hit = @($out | Where-Object { $_ -match '^\s+FAIL\s+.*x86 image without TSWD.*reports no TSWD' })
    Check 'and the check aimed at it is the one that failed' ($hit.Count -ge 1) $(if ($hit.Count) { $hit[0].Trim() } else { 'no FAIL line for the non-TSWD x86 image' })
  }
  Assert-CheckTotal 3
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

# ---------------------------------------------------------------------------------------------------------
Write-Host 'test-procs: PeProbe and the procs verb'
Write-Host ''

$work = Join-Path ([IO.Path]::GetTempPath()) ("test-procs-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

try {

Invoke-CheckSection 'compile ClarionDbg.Core from source' {
  $coreDir = Join-Path $PSScriptRoot '..\src\ClarionDbg.Core'
  $src = Join-Path $work 'core'
  New-Item -ItemType Directory -Path $src | Out-Null
  foreach ($f in Get-ChildItem -LiteralPath $coreDir -Filter *.cs) {
    $text = [IO.File]::ReadAllText($f.FullName)
    if ($Mutate -eq 'tswd-inverted' -and $f.Name -eq 'PeProbe.cs') {
      $anchor = 'hasTswd = BitConverter.ToUInt32(entry, 12) == TswdDebugInfo.TswdMagic;'
      $n = ([regex]::Matches($text, [regex]::Escape($anchor))).Count
      if ($n -ne 1) { throw "mutation anchor found $n time(s), expected 1" }
      $text = $text.Replace($anchor, $anchor.Replace('==', '!='))
    }
    [IO.File]::WriteAllText((Join-Path $src $f.Name), $text)
  }
  Add-Type -Path (Get-ChildItem -LiteralPath $src -Filter *.cs).FullName
  if ($Mutate) { Write-Host "MUTATION APPLIED: $Mutate" }
  Check 'PeProbe compiled' ($null -ne ('ClarionDbg.Core.PeProbe' -as [type])) ''
}

function Probe([string] $path) {
  $m = [uint16]0; $t = $false
  $ok = [ClarionDbg.Core.PeProbe]::TryProbe($path, [ref]$m, [ref]$t)
  [pscustomobject]@{ Ok = $ok; Machine = $m; Tswd = $t }
}
# The full reader's verdict, for the "same answer" checks: PeProbe must agree with TswdDebugInfo.TryFromPe.
function FullReaderTswd([string] $path) {
  $pe = [ClarionDbg.Core.PeImage]::Load($path)
  $null -ne [ClarionDbg.Core.TswdDebugInfo]::TryFromPe($pe)
}

Invoke-CheckSection 'PeProbe: real images' {
  if ($haveTswd) {
    $r = Probe $TswdImage
    Check 'TSWD image: parses' $r.Ok ''
    Check 'TSWD image: machine is i386' ($r.Machine -eq 0x14C) ('0x{0:X}' -f $r.Machine)
    Check 'TSWD image: reports TSWD' $r.Tswd ''
    Check 'TSWD image: agrees with TswdDebugInfo.TryFromPe' ($r.Tswd -eq (FullReaderTswd $TswdImage)) ''
  } else {
    Write-Host "  SKIP  TSWD image checks (4): $TswdImage is not on this machine. THE POSITIVE TSWD CASE IS UNTESTED."
  }
  $r = Probe $X86Plain
  Check 'x86 image without TSWD: parses' $r.Ok $X86Plain
  Check 'x86 image without TSWD: machine is i386' ($r.Machine -eq 0x14C) ('0x{0:X}' -f $r.Machine)
  Check 'x86 image without TSWD: reports no TSWD' (-not $r.Tswd) ''
  Check 'x86 image without TSWD: agrees with TswdDebugInfo.TryFromPe' ($r.Tswd -eq (FullReaderTswd $X86Plain)) ''
  $r = Probe $X64Image
  Check 'x64 image: parses' $r.Ok $X64Image
  Check 'x64 image: machine is AMD64, so procs rejects it as not x86' ($r.Machine -eq 0x8664) ('0x{0:X}' -f $r.Machine)
  Check 'x64 image: reports no TSWD (PE32+ is never TSWD)' (-not $r.Tswd) ''
}

Invoke-CheckSection 'PeProbe: bad input never throws and reports false' {
  $src = [IO.File]::ReadAllBytes($X86Plain)
  $cases = [ordered]@{
    'missing file'            = $null
    'empty file'              = [byte[]]@()
    'MZ only'                 = [byte[]](0x4D, 0x5A)
    'garbage'                 = [byte[]](1..4096 | ForEach-Object { ($_ * 37 + 11) % 256 })
    'truncated in section table' = $src[0..299]
  }
  # e_lfanew pointing far past the end, and negative.
  $far = [byte[]]$src[0..1023].Clone(); [BitConverter]::GetBytes([int]0x7FFFFFF0).CopyTo($far, 0x3C); $cases['e_lfanew huge'] = $far
  $neg = [byte[]]$src[0..1023].Clone(); [BitConverter]::GetBytes([int]-8).CopyTo($neg, 0x3C); $cases['e_lfanew negative'] = $neg
  $sig = [byte[]]$src[0..4095].Clone(); $o = [BitConverter]::ToInt32($sig, 0x3C); $sig[$o] = 0x4E; $cases['PE signature wrong'] = $sig
  foreach ($k in $cases.Keys) {
    $p = Join-Path $work ("bad-" + ($k -replace '\W', '_') + '.bin')
    if ($null -ne $cases[$k]) { [IO.File]::WriteAllBytes($p, [byte[]]$cases[$k]) }
    $r = $null; $err = $null
    try { $r = Probe $p } catch { $err = $_.Exception.Message }
    Check "$k -> false, no throw" ($null -eq $err -and $r -and -not $r.Ok -and -not $r.Tswd) $(if ($err) { "threw: $err" } else { "ok=$($r.Ok) tswd=$($r.Tswd)" })
  }
  # Cut just short of the end of the first debug entry: the headers parse, the entry does not.
  $pe = [ClarionDbg.Core.PeImage]::new($src)
  $dbgOff = $pe.RvaToOffset($pe.DebugDirRva)
  $cut = Join-Path $work 'cut-debug-entry.bin'
  [IO.File]::WriteAllBytes($cut, [byte[]]$src[0..($dbgOff + 13)])
  $r = Probe $cut
  Check 'debug entry cut short -> headers parse, no TSWD' ($r.Ok -and $r.Machine -eq 0x14C -and -not $r.Tswd) "ok=$($r.Ok) machine=0x$('{0:X}' -f $r.Machine) tswd=$($r.Tswd) (entry at 0x$('{0:X}' -f $dbgOff))"
}

function Invoke-Procs([string[]] $a) {
  $o = @(& $Engine procs @a 2>&1 | ForEach-Object { "$_" })
  [pscustomobject]@{ Code = $LASTEXITCODE; Lines = $o; Json = $(if ($o.Count -eq 1) { try { $o[0] | ConvertFrom-Json } catch { $null } }) }
}

Invoke-CheckSection 'procs --json: the default list' {
  Check 'the engine is built' (Test-Path -LiteralPath $Engine) $Engine
  $r = Invoke-Procs @('--json')
  Check 'exit 0, exactly one line of output' ($r.Code -eq 0 -and $r.Lines.Count -eq 1) "exit $($r.Code), $($r.Lines.Count) line(s)"
  Check 'the line is JSON' ($null -ne $r.Json) ($r.Lines | Select-Object -First 1)
  Check 'member order is the contract: event, procs, skipped' ($r.Lines[0] -match '^\{"event":"procs","procs":\[.*\],"skipped":\d+\}$') ''
  Check 'no verbose skips list without --verbose' ($null -eq $r.Json.skips) ''
  $notTswd = @($r.Json.procs | Where-Object { -not $_.tswd })
  Check 'every listed process is TSWD by default' ($notTswd.Count -eq 0) (($notTswd | ForEach-Object { "$($_.pid) $($_.name)" }) -join ', ')
  Check 'skipped counts the rest (> 0 on any real machine)' ($r.Json.skipped -gt 0) "skipped=$($r.Json.skipped)"
}

Invoke-CheckSection 'procs --json: a live x86 process, and the filters' {
  $script:ping = Start-Process -FilePath $X86Plain -ArgumentList '-n', '120', '127.0.0.1' -WindowStyle Hidden -PassThru
  Start-Sleep -Milliseconds 500
  $pp = [uint32]$script:ping.Id

  $r = Invoke-Procs @('--json', '--verbose')
  $s = @($r.Json.skips | Where-Object { $_.pid -eq $pp })
  Check 'default: the x86 non-TSWD process is skipped as no-tswd' ($s.Count -eq 1 -and $s[0].reason -eq 'no-tswd') (($s | ConvertTo-Json -Compress))
  Check 'skipped equals the length of skips' ($r.Json.skipped -eq @($r.Json.skips).Count) "$($r.Json.skipped) vs $(@($r.Json.skips).Count)"
  $self = @($r.Json.skips | Where-Object { $_.reason -eq 'self' })
  Check 'the engine skips itself, as self' ($self.Count -eq 1 -and $self[0].name -eq 'ClarionDbg.exe') (($self | ConvertTo-Json -Compress))
  $me = @($r.Json.skips | Where-Object { $_.pid -eq $PID })
  Check 'this 64-bit pwsh is skipped as not-x86' ($me.Count -eq 1 -and $me[0].reason -eq 'not-x86') (($me | ConvertTo-Json -Compress))
  Check 'verbose: skips follows skipped, last' ($r.Lines[0] -match '"skipped":\d+,"skips":\[.*\]\}$') ''

  $r = Invoke-Procs @('--json', '--all')
  $e = @($r.Json.procs | Where-Object { $_.pid -eq $pp })
  Check '--all: it is listed, tswd false' ($e.Count -eq 1 -and $e[0].tswd -eq $false) (($e | ConvertTo-Json -Compress))
  $want = '{"pid":' + $pp + ',"name":"PING.EXE","path":' + (ConvertTo-Json $X86Plain) + ',"tswd":false}'
  Check '--all: the entry is exactly pid,name,path,tswd with the path escaped' ($r.Lines[0].IndexOf($want, [StringComparison]::OrdinalIgnoreCase) -ge 0) $want

  $r = Invoke-Procs @('--json', '--all', '--verbose', '--exclude', "$pp")
  $s = @($r.Json.skips | Where-Object { $_.pid -eq $pp })
  Check '--exclude: it is skipped as excluded, even with --all' ($s.Count -eq 1 -and $s[0].reason -eq 'excluded' -and -not @($r.Json.procs | Where-Object { $_.pid -eq $pp }).Count) (($s | ConvertTo-Json -Compress))

  $r = Invoke-Procs @('--json', '--exclude', 'abc')
  Check '--exclude with no pid is a usage error (exit 1)' ($r.Code -eq 1) "exit $($r.Code)"
}

if ($WithClarion) {
  Invoke-CheckSection 'procs --json: a running TSWD app is listed' {
    if (-not $haveTswd) { throw "-WithClarion needs $TswdImage" }
    $script:app = Start-Process -FilePath $TswdImage -WorkingDirectory (Split-Path $TswdImage) -PassThru
    Start-Sleep -Seconds 2
    $r = Invoke-Procs @('--json')
    $e = @($r.Json.procs | Where-Object { $_.pid -eq $script:app.Id })
    Check 'the TSWD app is listed by default, tswd true' ($e.Count -eq 1 -and $e[0].tswd) (($e | ConvertTo-Json -Compress))
  }
}

} finally {
  # Kill through the Process objects we started, never by a bare pid (a pid is not an identity).
  foreach ($p in @($script:ping, $script:app)) { if ($p -and -not $p.HasExited) { try { $p.Kill() } catch { } } }
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

$EXPECTED_CHECKS = 33 + $(if ($haveTswd) { 4 } else { 0 }) + $(if ($WithClarion) { 1 } else { 0 })
Assert-CheckTotal $EXPECTED_CHECKS
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
