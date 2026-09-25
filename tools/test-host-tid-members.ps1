# Asserts, against the ADD-IN'S OWN SOURCE, that no host file writes a thread-id JSON member by hand.
#
#   pwsh -NoProfile -File tools\test-host-tid-members.ps1
#   pwsh -NoProfile -File tools\test-host-tid-members.ps1 -SelfTest
#
# WHY THIS FILE EXISTS (ticket c299aced).
#
# The absent-tid rule -- a thread id is a real Win32 tid or the member is ABSENT, never 0, never -1 -- is a
# two-sided contract. 3b043dfc made the ENGINE side structural: one writer, and tools\test-engine-tid-members.ps1
# reading the engine's source to fail any emitter that bypasses it. The HOST side had the writer (TidMember in
# ClarionDebuggerWebView.cs) and nothing making it the only path: OnThreads still typed a row's tid inline, and
# a future emitter could type ,"tid":0 with nothing to notice. One side of a contract enforced and the other
# obeyed drifts silently, because neither side's checks can see the other's emissions.
#
# THE RULES, over every .cs file under src\ClarionDebugger.Addin (comments and char literals excluded - only
# STRING literals are searched, walked with Skip-CSharpLiteral from lib-extract.ps1):
#
#   1. BY NAME. A declared thread-id member name may appear as JSON text only as a per-row BOOLEAN flag.
#      There are exactly 2 (OnThreads' row "stopped" and "selected"). The names are READ from the WebView's
#      TidValuedMemberNames declaration, not retyped here.
#   2. BY VALUE. A member of ANY name whose appended value is a thread id (an identifier ending in tid/Tid)
#      is a bypass. This is what "any name, not just tid" means: the value is what makes it a thread id, and a
#      name nobody has declared yet is exactly the case rule 1 cannot see.
#   3. BY SHAPE. A literal that is nothing but member punctuation (,\" {\" \":) is a member being ASSEMBLED
#      around a variable - which is how TidMember itself works, so it is how a copy of it would look. Allowed
#      only inside TidMember (2) and RegsJson (1, register names out of a fixed list).
#   4. BY PREDICATE (6ac29815 #1). The absent-tid TEST - present and not 0 - is stated once, in
#      WireRules.TidIsKnown (Wire\WireRules.cs). A nullable's .Value (or GetValueOrDefault())
#      compared with 0 anywhere else in CODE is an inline copy of it; there were four, in the WebView, the
#      service, EditGrants and DisassemblyView, and one had already drifted to a different spelling.
#
# ASCII ONLY, for Windows PowerShell 5.1 (see memory: ps51-emdash-parse-trap).

[CmdletBinding()]
param(
  # Defaulted in the body, not here: Windows PowerShell 5.1 leaves $PSScriptRoot empty in this block.
  [string] $SrcRoot = '',
  # Plant each violation in memory and require the scan to catch it. A guard never seen to fail is not
  # known to be a guard.
  [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
if (-not $SrcRoot) { $SrcRoot = Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin' }

$ruleRel = 'Terminal\ClarionDebuggerWebView.cs'

# ---------------------------------------------------------------- the declared name set, read off the code

function Get-DeclaredNames([string] $Src) {
  $consts = @{}
  foreach ($m in [regex]::Matches($Src, 'private\s+const\s+string\s+(TidMember\w+)\s*=\s*"([^"]+)"\s*;')) {
    $consts[$m.Groups[1].Value] = $m.Groups[2].Value
  }
  $decl = Get-CSharpStatement 'private static readonly string[] TidValuedMemberNames' $Src
  if (-not $decl) { return @() }
  $names = @()
  foreach ($m in [regex]::Matches($decl, 'TidMember\w+')) {
    if ($consts.ContainsKey($m.Value)) { $names += $consts[$m.Value] } else { $names += "<unresolved:$($m.Value)>" }
  }
  return $names
}

# ---------------------------------------------------------------- the literal walk

function Get-StringLiterals([string] $Src) {
  $out = New-Object System.Collections.ArrayList
  $n = $Src.Length
  $j = 0
  while ($j -lt $n) {
    $c0 = $Src[$j]
    if ($c0 -ne '/' -and $c0 -ne '"' -and $c0 -ne "'" -and $c0 -ne '@' -and $c0 -ne '$') { $j++; continue }
    $k = Skip-CSharpLiteral $Src $j
    if ($k -ne $j) {
      $c = $Src[$j]
      $isString = ($c -eq '"') -or (($c -eq '@' -or $c -eq '$') -and $j + 1 -lt $n -and $Src[$j + 1] -eq '"')
      if ($isString) { [void] $out.Add([pscustomobject] @{ Start = $j; End = $k; Text = $Src.Substring($j, $k - $j) }) }
      $j = $k
      continue
    }
    $j++
  }
  return $out
}

function Get-LineOf([string] $Src, [int] $At) { ($Src.Substring(0, $At) -split "`n").Count }

# The argument of the .Append( that directly follows a literal, delimited by its own matching parenthesis;
# or the operand of a directly following ` + `. $null when the literal is followed by neither.
function Get-AppendedValue([string] $Src, [int] $LiteralEnd) {
  $tail = $Src.Substring($LiteralEnd, [Math]::Min(400, $Src.Length - $LiteralEnd))
  $m = [regex]::Match($tail, '^\s*\)\s*\.Append\(')
  if ($m.Success) {
    $i = $m.Length; $depth = 1
    while ($i -lt $tail.Length) {
      $k = Skip-CSharpLiteral $tail $i
      if ($k -ne $i) { $i = $k; continue }
      $c = $tail[$i]
      if ($c -eq '(') { $depth++ } elseif ($c -eq ')') { $depth--; if ($depth -eq 0) { break } }
      $i++
    }
    if ($depth -ne 0) { return $null }
    return $tail.Substring($m.Length, $i - $m.Length)
  }
  $p = [regex]::Match($tail, '^\s*\+\s*([^;+]+)')
  if ($p.Success) { return $p.Groups[1].Value }
  return $null
}

function Test-IsBoolean([string] $Value) { $null -ne $Value -and $Value -match '\?\s*"true"\s*:\s*"false"\s*$' }
# An identifier ending in tid/Tid: tid, t.Tid, list.StoppedTid, seltid. Not TidMember(/TidJson( calls, which
# are the writer.
function Test-IsTidValue([string] $Value) {
  $null -ne $Value -and $Value -notmatch '\bTid(Member|Json)\s*\(' -and $Value -cmatch '(?<![A-Za-z0-9_])[A-Za-z0-9_.]*(tid|Tid)\b'
}

# ---------------------------------------------------------------- the scan

function Invoke-Scan([hashtable] $Sources, [string[]] $Names) {
  $r = [pscustomobject] @{ ByName = @(); Booleans = @(); ByValue = @(); Nameless = @() }
  $byName = New-Object System.Collections.ArrayList
  $bools = New-Object System.Collections.ArrayList
  $byValue = New-Object System.Collections.ArrayList
  $nameless = New-Object System.Collections.ArrayList
  foreach ($f in ($Sources.Keys | Sort-Object)) {
    $src = $Sources[$f]
    # The two blocks allowed to assemble a member around a variable.
    $allowed = @()
    if ($f -eq $ruleRel) {
      foreach ($sig in @('private static string TidMember(string name, uint? tid)', 'private static string RegsJson(')) {
        $b = Get-CSharpBlock $sig $src
        if ($null -ne $b) { $at = $src.IndexOf($b, [StringComparison]::Ordinal); $allowed += [pscustomobject] @{ S = $at; E = $at + $b.Length; Sig = $sig } }
      }
    }
    foreach ($lit in (Get-StringLiterals $src)) {
      $line = Get-LineOf $src $lit.Start
      $value = $null; $valueRead = $false
      foreach ($name in $Names) {
        if ($lit.Text.IndexOf("\`"$name\`":", [StringComparison]::Ordinal) -lt 0) { continue }
        if (-not $valueRead) { $value = Get-AppendedValue $src $lit.End; $valueRead = $true }
        $hit = [pscustomobject] @{ File = $f; Line = $line; Name = $name; Literal = $lit.Text }
        if (Test-IsBoolean $value) { [void] $bools.Add($hit) } else { [void] $byName.Add($hit) }
      }
      $mm = [regex]::Match($lit.Text, '\\"(\w+)\\":"$')
      if ($mm.Success) {
        if (-not $valueRead) { $value = Get-AppendedValue $src $lit.End; $valueRead = $true }
        if (Test-IsTidValue $value) {
          [void] $byValue.Add([pscustomobject] @{ File = $f; Line = $line; Name = $mm.Groups[1].Value; Value = $value.Trim() })
        }
      }
      if ($lit.Text.Length -ge 2 -and $lit.Text[0] -eq '"') {
        $body = $lit.Text.Substring(1, $lit.Text.Length - 2)
        if (@(',\"', '{\"', '\":') -contains $body) {
          $in = @($allowed | Where-Object { $lit.Start -ge $_.S -and $lit.Start -lt $_.E })
          [void] $nameless.Add([pscustomobject] @{ File = $f; Line = $line; Text = $lit.Text; Allowed = ($in.Count -gt 0); In = $(if ($in.Count) { $in[0].Sig } else { '' }) })
        }
      }
    }
  }
  $r.ByName = $byName.ToArray(); $r.Booleans = $bools.ToArray(); $r.ByValue = $byValue.ToArray(); $r.Nameless = $nameless.ToArray()
  $p = Invoke-PredicateScan $Sources
  $r | Add-Member -NotePropertyName Predicate -NotePropertyValue $p.Inline
  $r | Add-Member -NotePropertyName PredicateDefs -NotePropertyValue $p.Definitions
  $r | Add-Member -NotePropertyName PredicateInWriter -NotePropertyValue $p.InsideWriter
  return $r
}

# Rule 4. Comments are stripped first (Get-CSharpCodeOnly), so a comment explaining the rule is not a copy.
$predicateRel = 'Wire\WireRules.cs'
$predicateSig = 'internal static bool TidIsKnown(uint? tid)'
$predicateRx = '\.(Value|GetValueOrDefault\(\))\s*(?:[!=]=|>)\s*0u?\b'
function Invoke-PredicateScan([hashtable] $Sources) {
  $inline = New-Object System.Collections.ArrayList
  $defs = 0; $inWriter = 0
  foreach ($f in ($Sources.Keys | Sort-Object)) {
    $code = Get-CSharpCodeOnly $Sources[$f]
    $defs += [regex]::Matches($code, 'static\s+bool\s+TidIsKnown\s*\(').Count
    $bs = -1; $be = -1
    if ($f -eq $predicateRel) {
      $body = Get-CSharpBlock $predicateSig $code
      if ($null -ne $body) { $bs = $code.IndexOf($body, [StringComparison]::Ordinal); $be = $bs + $body.Length }
    }
    foreach ($m in [regex]::Matches($code, $predicateRx)) {
      if ($bs -ge 0 -and $m.Index -ge $bs -and $m.Index -lt $be) { $inWriter++; continue }
      [void] $inline.Add([pscustomobject] @{ File = $f; Line = (Get-LineOf $code $m.Index); Text = $m.Value })
    }
  }
  [pscustomobject] @{ Inline = $inline.ToArray(); Definitions = $defs; InsideWriter = $inWriter }
}

function Read-Sources {
  $root = (Resolve-Path $SrcRoot).Path
  $h = @{}
  foreach ($f in (Get-ChildItem -Path $root -Filter *.cs -File -Recurse | Where-Object { $_.FullName -notmatch '\\(obj|bin)\\' })) {
    $h[$f.FullName.Substring($root.Length).TrimStart('\')] = [IO.File]::ReadAllText($f.FullName)
  }
  return $h
}

function Show([object[]] $Items, [scriptblock] $Fmt) { if ($Items.Count) { ($Items | ForEach-Object $Fmt) -join ' | ' } else { '' } }

# A scan's verdict as a list of broken rules, so the self-test can ask "did THIS rule catch it".
function Get-Violations($Scan) {
  $v = @()
  if (@($Scan.ByName).Count -gt 0) { $v += 'name' }
  if (@($Scan.Booleans).Count -ne 2) { $v += 'booleans' }
  if (@($Scan.ByValue).Count -gt 0) { $v += 'value' }
  if (@($Scan.Nameless | Where-Object { -not $_.Allowed }).Count -gt 0) { $v += 'shape' }
  if (@($Scan.Predicate).Count -gt 0 -or $Scan.PredicateDefs -ne 1 -or $Scan.PredicateInWriter -ne 1) { $v += 'predicate' }
  return ,$v
}

$sources = Read-Sources
if (-not $sources.ContainsKey($ruleRel)) { Write-Host "  FAIL  $ruleRel not found under $SrcRoot"; exit 1 }
$ruleSrc = $sources[$ruleRel]
$names = @(Get-DeclaredNames $ruleSrc)

# Sections and an explicit total per mode (lib-check.ps1): a section that throws, returns early, terminates
# the script or asserts nothing is a FAILURE, never a shorter "ALL N CHECKS PASSED". The scan runs once, up
# front; the sections read it.
function Copy-Sources { $m = @{}; foreach ($k in $sources.Keys) { $m[$k] = $sources[$k] }; $m }

if ($SelfTest) {
  Write-Host 'test-host-tid-members -SelfTest: each planted violation must be caught, by the rule meant to catch it'
  Write-Host ''
  Invoke-CheckSection 'the shipped source is the clean baseline' {
    $scan0 = Invoke-Scan $sources $names
    Check 'CONTROL: the shipped source is clean, so every red below is the plant' ((Get-Violations $scan0).Count -eq 0) ((Get-Violations $scan0) -join ',')
  }
  Invoke-CheckSection 'each planted violation is caught by its own rule' {
    $plants = @(
      @('a row tid typed inline again', 'name',
        '.Append(TidMember(TidMemberTid, t.Tid))', '.Append(",\"tid\":").Append(t.Tid)'),
      @('a top-level stopped written as a bare number', 'name',
        '.Append(TidMember(TidMemberStopped, list.StoppedTid))', '.Append(",\"stopped\":").Append(list.StoppedTid)'),
      @('a NEW, undeclared name carrying a tid', 'value',
        '.Append(TidMember(TidMemberTid, t.Tid))', '.Append(TidMember(TidMemberTid, t.Tid)).Append(",\"ownerThread\":").Append(t.Tid)'),
      @('a tid concatenated rather than appended', 'value',
        'Post("{\"type\":\"engineerror\",\"message\":" + Str(msg) + "}");', 'Post("{\"type\":\"engineerror\",\"lastTid\":" + _lastTid + "}");'),
      @('a member assembled around a variable, outside the writer', 'shape',
        '.Append(TidMember(TidMemberTid, t.Tid))', '.Append(",\"").Append(TidMemberTid).Append("\":").Append(t.Tid)')
    )
    foreach ($p in $plants) {
      $n = ([regex]::Matches($ruleSrc, [regex]::Escape($p[2]))).Count
      if ($n -ne 1) { Check "plant applies: $($p[0])" $false "anchor found $n time(s)"; continue }
      $mut = Copy-Sources
      $mut[$ruleRel] = $ruleSrc.Replace($p[2], $p[3])
      $v = Get-Violations (Invoke-Scan $mut $names)
      Check "caught by the $($p[1]) rule: $($p[0])" ($v -contains $p[1]) "rules broken: $(if ($v.Count) { $v -join ',' } else { 'none' })"
    }
  }
  Invoke-CheckSection 'an inline copy of the absent-tid test is caught in any host file (6ac29815 #1)' {
    $plants = @(
      @('a fifth inline copy, in the service', 'Services\ClarionDebuggerService.cs',
        'if (!WireRules.TidIsKnown(rowTid)) continue;', 'if (!rowTid.HasValue || rowTid.Value == 0) continue;'),
      @('the view''s old TidOf, in its != spelling', 'Disassembly\DisassemblyView.cs',
        'WireRules.TidIsKnown(t) ? t.Value : 0u', '(t != null && t.Value != 0) ? t.Value : 0u'),
      @('a second definition of the test', $ruleRel,
        'private static string TidMember(string name, uint? tid)', 'private static bool TidIsKnown(uint? t) { return WireRules.TidIsKnown(t); } private static string TidMember(string name, uint? tid)')
    )
    foreach ($p in $plants) {
      if (-not $sources.ContainsKey($p[1])) { Check "plant applies: $($p[0])" $false "no $($p[1])"; continue }
      $n = ([regex]::Matches($sources[$p[1]], [regex]::Escape($p[2]))).Count
      if ($n -ne 1) { Check "plant applies: $($p[0])" $false "anchor found $n time(s) in $($p[1])"; continue }
      $mut = Copy-Sources
      $mut[$p[1]] = $sources[$p[1]].Replace($p[2], $p[3])
      $v = Get-Violations (Invoke-Scan $mut $names)
      Check "caught by the predicate rule: $($p[0])" ($v -contains 'predicate') "rules broken: $(if ($v.Count) { $v -join ',' } else { 'none' })"
    }
    $mut = Copy-Sources
    $mut[$ruleRel] = $ruleSrc + "`n// never write if (!tid.HasValue || tid.Value == 0) by hand`n"
    Check 'CONTROL: the test inside a comment is not reported' ((Get-Violations (Invoke-Scan $mut $names)).Count -eq 0) ''
  }
  Invoke-CheckSection 'the scope reaches every host file, and not the comments' {
    $other = @($sources.Keys | Where-Object { $_ -ne $ruleRel -and $_ -like 'Services\*' } | Select-Object -First 1)
    if ($other.Count -eq 0) { Check 'a second host file exists to plant into' $false 'no Services\*.cs found' }
    else {
      $mut = Copy-Sources
      $mut[$other[0]] = $mut[$other[0]] + "`nclass Planted { string J(uint tid) { return `"{\`"tid\`":`" + tid + `"}`"; } }`n"
      $v = Get-Violations (Invoke-Scan $mut $names)
      Check "caught in another host file ($($other[0]))" (($v -contains 'name') -and ($v -contains 'value')) "rules broken: $($v -join ',')"
    }
    $mut = Copy-Sources
    $mut[$ruleRel] = $ruleSrc + "`n// never write .Append(`",\`"tid\`":`").Append(t.Tid) by hand`n"
    Check 'CONTROL: the idiom inside a comment is not reported' ((Get-Violations (Invoke-Scan $mut $names)).Count -eq 0) ''
  }
  Assert-CheckTotal 12
  Write-Host ''
  if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}

Write-Host 'test-host-tid-members: no thread-id JSON member is written outside the host''s shared writer'
Write-Host ''

Invoke-CheckSection 'the declared name set, read off the WebView' {
  Check 'the WebView declares the thread-id member names in one array' ($names.Count -gt 0) $(if ($names.Count) { '' } else { 'TidValuedMemberNames was not found' })
  Check 'every declared name resolved through its TidMember* constant' (-not ($names | Where-Object { $_ -like '<unresolved:*' })) ($names -join ', ')
  Check 'the host declares 3 thread-id member names' ($names.Count -eq 3) "got $($names.Count): $($names -join ', ')"
}

Invoke-CheckSection 'the shared writer' {
  $writer = Get-CSharpBlock 'private static string TidMember(string name, uint? tid)' $ruleSrc
  Check 'the shared writer exists' ($null -ne $writer) $(if ($writer) { '' } else { 'TidMember was not found' })
  $typed = @(if ($writer) { $names | Where-Object { $writer.IndexOf("\`"$_\`":", [StringComparison]::Ordinal) -ge 0 } } else { '(no writer)' })
  Check 'the shared writer types no member name of its own' ($typed.Count -eq 0) ($typed -join ', ')
}

$scan = Invoke-Scan $sources $names
Invoke-CheckSection 'the scan of every host source file' {
  Check "scanned $($sources.Count) host source file(s), the WebView among them" ($sources.Count -gt 1) ''
  Check 'no declared thread-id member name is written as JSON text outside the writer' (@($scan.ByName).Count -eq 0) `
    (Show $scan.ByName { "$($_.File):$($_.Line) typed $($_.Name) as $($_.Literal)" })
  # The per-row BOOLEANS that share these names. Exactly two, each named, so a third is a decision:
  #   Terminal\ClarionDebuggerWebView.cs  OnThreads row "stopped"  (is this the thread execution halted on?)
  #   Terminal\ClarionDebuggerWebView.cs  OnThreads row "selected" (is this the thread the reads point at?)
  Check 'exactly 2 same-named members are per-row booleans' (@($scan.Booleans).Count -eq 2) `
    (Show $scan.Booleans { "$($_.File):$($_.Line) $($_.Name)" })
  Check 'no member of ANY name is handed a thread id outside the writer' (@($scan.ByValue).Count -eq 0) `
    (Show $scan.ByValue { "$($_.File):$($_.Line) $($_.Name) <- $($_.Value)" })
  $bad = @($scan.Nameless | Where-Object { -not $_.Allowed })
  Check 'no member name is ASSEMBLED around a variable outside the writer and RegsJson' ($bad.Count -eq 0) `
    (Show $bad { "$($_.File):$($_.Line) $($_.Text)" })
  # CONTROL: the writer's own punctuation is still FOUND, or the check above passes because the walk sees
  # nothing. THREE: TidMember's ,\" and \": and RegsJson's \":.
  $ok = @($scan.Nameless | Where-Object { $_.Allowed })
  Check 'and the two allowed blocks still assemble their own (3 delimiter literals)' ($ok.Count -eq 3) `
    (Show $ok { "$($_.File):$($_.Line) $($_.Text)" })
}

Invoke-CheckSection 'the absent-tid test is stated once (6ac29815 #1)' {
  Check 'the host defines TidIsKnown exactly once (WireRules, Wire\WireRules.cs)' ($scan.PredicateDefs -eq 1) "$($scan.PredicateDefs) definition(s)"
  Check 'no host file compares a nullable''s Value with 0 outside it (an inline copy of the test)' (@($scan.Predicate).Count -eq 0) `
    (Show $scan.Predicate { "$($_.File):$($_.Line) $($_.Text)" })
  # CONTROL: the scan still FINDS the test where it is allowed, or the check above passes because it sees nothing.
  Check 'CONTROL: and the scan finds the one allowed statement of it, inside TidIsKnown' ($scan.PredicateInWriter -eq 1) "$($scan.PredicateInWriter) inside"
}

Assert-CheckTotal 14
Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) of $($script:checks) CHECKS FAILED"; exit 1 }
Write-Host "ALL $($script:checks) CHECKS PASSED"
exit 0