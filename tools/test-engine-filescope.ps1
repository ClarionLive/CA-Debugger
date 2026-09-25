# Real compiler output for data-name resolution (tickets 04d7b4c8 and 52458d89): builds the hand-coded
# fixture tools\fixtures\filescope with Clarion 11 and asks the engine's offline `data` and `globals` commands
# about it.
#
# WHAT THIS SUITE CAN AND CANNOT PROVE:
#   CAN  - the names Clarion 11 really gives a global FILE's record, a procedure-local FILE's record and a
#          History:: copy (04d7b4c8 item 4); that two procedure-local FILEs sharing a prefix make a bare field
#          and a bare record name AMBIGUOUS, with each candidate printed in a form that resolves when pasted
#          back (item 1, one image); that the History:: copy never wins a FILE field; and that the PROGRAM
#          module's own global is attributed to it (52458d89).
#   CANNOT - two images (no multi-DLL fixture: protocolcheck CheckAmbiguousFileRecordsFailClosed covers the
#          cross-image rule on hand-built candidates), or anything live: `data` runs the same static
#          resolver a watch runs, not the watch command itself.
#
# Needs Clarion 11 (MSBuild + SoftVelocity.Build.Clarion.targets), which is why run-all lists it as live.
#
#   pwsh tools/test-engine-filescope.ps1
# Exit code 0 = all checks passed.

param(
  [string] $Engine     = (Join-Path $PSScriptRoot '..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe'),
  [string] $Fixture    = (Join-Path $PSScriptRoot 'fixtures\filescope'),
  [string] $MSBuild    = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe',
  [string] $ClarionBin = 'C:\Clarion11\bin'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-check.ps1')
$script:checks = 0
$script:failures = 0

# Run the engine's offline `data` command; returns @{ Exit; Line }.
function Invoke-Data {
  param([string] $Spec)
  $out = & $Engine data $script:exe $Spec 2>&1 | Out-String
  return @{ Exit = $LASTEXITCODE; Line = $out.Trim() }
}

# The RVA a `data` line reports ("... RVA 0x30B4 in ..."), or $null.
function Get-DataRva {
  param([string] $Line)
  if ($Line -match 'RVA (0x[0-9A-F]+) in ') { return $Matches[1] }
  return $null
}

# A known-good ambiguity line for ORD:ITEM, as the suite expects the engine to print it.
$AmbiguousOrdItem = 'ORD:ITEM: ambiguous: filescope_a.clw!ORD:ITEM, filescope_b.clw!ORD:ITEM - watch one of these'

$script:work = Join-Path ([IO.Path]::GetTempPath()) ('ClarionDbg-filescope-' + [Guid]::NewGuid().ToString('N'))
$script:exe = Join-Path $script:work 'filescope.exe'
$Engine = (Resolve-Path -LiteralPath $Engine).Path

try {
  Invoke-CheckSection 'the fixture builds with Clarion 11' {
    Check 'MSBuild is present' (Test-Path -LiteralPath $MSBuild) $MSBuild
    Check 'the Clarion build targets are present' (Test-Path -LiteralPath (Join-Path $ClarionBin 'SoftVelocity.Build.Clarion.targets')) $ClarionBin
    New-Item -ItemType Directory -Path $script:work | Out-Null
    foreach ($f in Get-ChildItem -LiteralPath $Fixture -File | Where-Object { $_.Extension -in '.clw', '.cwproj' }) {
      # CRLF whatever the checkout did: the Clarion compiler rejects LF.
      $text = [IO.File]::ReadAllText($f.FullName) -replace "`r?`n", "`r`n"
      [IO.File]::WriteAllText((Join-Path $script:work $f.Name), $text, [Text.Encoding]::ASCII)
    }
    Push-Location $script:work
    try { $build = & $MSBuild filescope.cwproj -nologo -v:m "/p:ClarionBinPath=$ClarionBin" 2>&1 | Out-String }
    finally { Pop-Location }
    Check 'filescope.exe was built' (Test-Path -LiteralPath $script:exe) $(if (Test-Path -LiteralPath $script:exe) { '' } else { $build.Trim() })
  }

  Invoke-CheckSection 'the names Clarion 11 emits (04d7b4c8 item 4)' {
    $globals = & $Engine globals $script:exe 2>&1 | Out-String
    $rows = @($globals -split "`r?`n" | Where-Object { $_ -match '^\s+0x[0-9A-F]+\s' })
    $names = @($rows | ForEach-Object { ($_.Trim() -split '\s+')[1] })
    Check 'a global FILE record is CUSTOMER$CUS:RECORD' ($names -contains 'CUSTOMER$CUS:RECORD') ($names -join ', ')
    Check 'each procedure-local FILE record is ORDERS$ORD:RECORD, twice' (@($names | Where-Object { $_ -eq 'ORDERS$ORD:RECORD' }).Count -eq 2) ($names -join ', ')
    Check 'no record name carries a procedure scope' (@($names | Where-Object { $_ -match '^PROC[AB]::' }).Count -eq 0) ($names -join ', ')
    Check 'the History:: copy is HISTORY::ORD:RECORD' ($names -contains 'HISTORY::ORD:RECORD') ($names -join ', ')
    $ordRows = @($rows | Where-Object { $_ -match 'ORDERS\$ORD:RECORD' })
    Check 'the two ORDERS records sit in filescope_a.clw and filescope_b.clw' `
      ((@($ordRows | Where-Object { $_ -match 'filescope_a\.clw$' }).Count -eq 1) -and (@($ordRows | Where-Object { $_ -match 'filescope_b\.clw$' }).Count -eq 1)) ($ordRows -join ' | ')
    # 52458d89: the PROGRAM module's _main has no line record at its entry, so its slot has only a boundary vote.
    Check 'the PROGRAM module''s global is attributed to filescope.clw' (@($rows | Where-Object { $_ -match 'CUSTOMER\$CUS:RECORD.*filescope\.clw$' }).Count -eq 1) ($rows -join ' | ')
    $script:rvaA = if (($ordRows | Where-Object { $_ -match 'filescope_a\.clw$' }) -match '^\s+(0x[0-9A-F]+)') { '0x' + ([Convert]::ToUInt32($Matches[1], 16)).ToString('X') } else { $null }
    $script:rvaB = if (($ordRows | Where-Object { $_ -match 'filescope_b\.clw$' }) -match '^\s+(0x[0-9A-F]+)') { '0x' + ([Convert]::ToUInt32($Matches[1], 16)).ToString('X') } else { $null }
    Check 'both record RVAs were read' (($null -ne $script:rvaA) -and ($null -ne $script:rvaB) -and ($script:rvaA -ne $script:rvaB)) "a=$($script:rvaA) b=$($script:rvaB)"
  }

  Invoke-CheckSection 'the ambiguity check can fail: an unambiguous name is not called ambiguous' {
    $one = Invoke-Data 'CUS:NAME'
    Check 'CUS:NAME resolves (exit 0)' ($one.Exit -eq 0) $one.Line
    Check 'and its line is not the ambiguity line' ($one.Line -ne $AmbiguousOrdItem) $one.Line
  }

  Invoke-CheckSection 'two procedure-local FILEs with one prefix are ambiguous (04d7b4c8 item 1)' {
    $r = Invoke-Data 'ORD:ITEM'
    Check 'a bare ORD:ITEM is ambiguous (exit 4)' ($r.Exit -eq 4) $r.Line
    Check 'naming each candidate by module' ($r.Line -eq $AmbiguousOrdItem) $r.Line
    $a = Invoke-Data 'filescope_a.clw!ORD:ITEM'
    $b = Invoke-Data 'filescope_b.clw!ORD:ITEM'
    Check 'filescope_a.clw!ORD:ITEM resolves to ProcA''s record' (($a.Exit -eq 0) -and ((Get-DataRva $a.Line) -eq $script:rvaA)) $a.Line
    Check 'filescope_b.clw!ORD:ITEM resolves to ProcB''s record' (($b.Exit -eq 0) -and ((Get-DataRva $b.Line) -eq $script:rvaB)) $b.Line
    $rec = Invoke-Data 'ORDERS$ORD:RECORD'
    Check 'the bare record name is ambiguous too' (($rec.Exit -eq 4) -and ($rec.Line -eq 'ORDERS$ORD:RECORD: ambiguous: filescope_a.clw!ORDERS$ORD:RECORD, filescope_b.clw!ORDERS$ORD:RECORD - watch one of these')) $rec.Line
    $path = Invoke-Data 'ORDERS$ORD:RECORD.ORD:ITEM'
    Check 'so is a path through it, with the member in each form' (($path.Exit -eq 4) -and ($path.Line -match 'filescope_a\.clw!ORDERS\$ORD:RECORD\.ORD:ITEM, filescope_b\.clw!ORDERS\$ORD:RECORD\.ORD:ITEM')) $path.Line
    $qpath = Invoke-Data 'filescope_b.clw!ORDERS$ORD:RECORD.ORD:ITEM'
    Check 'a qualified path resolves its head' (($qpath.Exit -eq 0) -and ($qpath.Line -match "RVA $($script:rvaB) in filescope\.exe filescope_b\.clw")) $qpath.Line
    $img = Invoke-Data 'filescope.exe!ORD:ITEM'
    Check 'an image qualifier alone does not settle it, and is kept in each form' `
      (($img.Exit -eq 4) -and ($img.Line -match 'filescope\.exe!filescope_a\.clw!ORD:ITEM, filescope\.exe!filescope_b\.clw!ORD:ITEM')) $img.Line
  }

  Invoke-CheckSection 'the History:: copy never wins a FILE field' {
    $h = Invoke-Data 'filescope_a.clw!ORD:ITEM'
    Check 'ProcA''s ORD:ITEM is the record, not HISTORY::ORD:RECORD' ($h.Line -match 'container ORDERS\$ORD:RECORD$') $h.Line
    $own = Invoke-Data 'HISTORY::ORD:RECORD'
    Check 'the copy is still watchable by its own name' ($own.Exit -eq 0) $own.Line
  }
}
finally {
  if (Test-Path -LiteralPath $script:work) { Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue }
}

# The backstop for a section that returns early without throwing (lib-check.ps1, guard (b)). Update the
# number deliberately when adding or removing a check.
$EXPECTED_CHECKS = 22
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
Write-Host 'NOT PROVED HERE: two images, or a live watch. See the header.'
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0
