# Asserts, against the ENGINE'S OWN SOURCE, that no file writes a thread-id JSON member by hand.
#
#   pwsh -NoProfile -File tools\test-engine-tid-members.ps1
#   pwsh -NoProfile -File tools\test-engine-tid-members.ps1 -SelfTest
#
# WHY THIS FILE EXISTS (ticket 3b043dfc, hole 2).
#
# The absent-tid rule -- a thread id is a real Win32 tid or the member is ABSENT, never 0, never -1 -- has
# been broken four times now, and every single time on a path that BYPASSED the helper the rule lived in.
# Three of those were caught by a person looking, not by a test. a39d9477 gave the rule one holder, and
# 3b043dfc widened it past the name "tid" to every member that carries a thread id. Neither of those closes
# the actual hole, which is this: C# cannot stop the next person typing
#
#     sb.Append(",\"tid\":").Append(someTid);
#
# into a StringBuilder, and `ClarionDbg protocolcheck` will not grow to cover a new emitter by itself --
# it runs the builders it was told about, so an emitter nobody told it about is invisible to it. It also
# cannot do this job even in principle: protocolcheck has no source tree at runtime.
#
# So the enforcement has to read the source, and it does. The rule this asserts is an ABSOLUTE with one
# named exception class, which is the only shape of rule that survives someone adding a file:
#
#     A declared thread-id member name may appear as JSON text in src\ClarionDbg.Cli only as a per-row
#     BOOLEAN flag. There are exactly 3 of those and they are listed below. Every other occurrence is a
#     hand-written thread-id member, i.e. a bypass, and fails.
#
# The emitters pass a TidMember* CONSTANT to AppendTidValuedMember and WithTid builds its head from one
# too, so after 3b043dfc there is no legitimate reason for the text `\"tid\":` to exist in an engine
# source file at all. That is what makes the absolute honest rather than convenient.
#
# HOW IT READS THE SOURCE. Not with a regex over the whole file: a member name in a COMMENT (this repo's
# comments discuss `,"tid":` at length, including in the rule holder itself) is not an emit, and counting
# it would make the check cry wolf until someone deleted it. So the scan walks the file with
# Skip-CSharpLiteral from tools\lib-extract.ps1 -- the same routine test-addin-json.ps1 uses to lift real
# C# out of the shipped source -- which steps over comments, char literals and verbatim strings, and hands
# back each STRING LITERAL with its offset. Only literals are searched. Text that contains its own
# delimiters cannot be scanned by looking for the delimiters, which is the reason that routine exists.
#
# THE NAME SET IS NOT RETYPED HERE. It is extracted from DebugEngine.cs's own TidValuedMemberNames
# declaration and its TidMember* constants. A test holding its own copy of the set under test asserts only
# that two hand-written lists agree -- which is precisely the evidence that was missing every time this
# rule broke. Adding a fourth name to the engine puts it under this check automatically.
#
# ASCII ONLY, and deliberately: Windows PowerShell 5.1 reads a BOM-less UTF-8 .ps1 as CP1252, where the
# third byte of a UTF-8 em-dash is a smart quote it accepts as a string delimiter -- so an em-dash in a
# COMMENT can terminate a string lines away and fail the parse with a bogus "missing closing }".

[CmdletBinding()]
param(
  # Mutate the source IN MEMORY and require this check to catch each mutation. A guard that has never been
  # seen to fail is not known to be a guard; this repo has shipped one that was dead to its own test.
  [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\lib-extract.ps1"

$repo      = Split-Path -Parent $PSScriptRoot
$engineDir = Join-Path $repo 'src\ClarionDbg.Cli'
$ruleFile  = Join-Path $engineDir 'DebugEngine.cs'

# ProtocolCheck.cs is the CHECKER, not an emitter: it is full of member-name literals because asserting on
# them is its job. The exclusion is earned below rather than assumed -- a file that emits nothing to the
# wire cannot emit a bad tid to it -- and the check for that is the '@JSON' marker every emit carries.
$checkerFile = 'ProtocolCheck.cs'

$fail = 0
$pass = 0
function Check([string] $What, [bool] $Ok, [string] $Detail = '') {
  if ($Ok) { $script:pass++; Write-Host "  ok   $What" }
  else     { $script:fail++; Write-Host "  FAIL $What$(if ($Detail) { " -- $Detail" })" -ForegroundColor Red }
}

# ---------------------------------------------------------------- the declared name set, read off the code

# The TidMember* constants, by constant name -> wire name.
function Get-TidMemberConstants([string] $Src) {
  $map = @{}
  foreach ($m in [regex]::Matches($Src, 'private\s+const\s+string\s+(TidMember\w+)\s*=\s*"([^"]+)"\s*;')) {
    $map[$m.Groups[1].Value] = $m.Groups[2].Value
  }
  return $map
}

# TidValuedMemberNames, resolved through those constants. Returns the WIRE names.
function Get-DeclaredTidMemberNames([string] $Src) {
  $decl = Get-CSharpStatement 'private static readonly string[] TidValuedMemberNames' $Src
  if (-not $decl) { return @() }
  $consts = Get-TidMemberConstants $Src
  $names = @()
  foreach ($m in [regex]::Matches($decl, 'TidMember\w+')) {
    $k = $m.Value
    if ($consts.ContainsKey($k)) { $names += $consts[$k] }
    else { $names += "<unresolved:$k>" }
  }
  return $names
}

# ---------------------------------------------------------------- the literal walk

# Every STRING literal in $Src, as [pscustomobject] @{ Start; End; Text }. Comments and char literals are
# stepped over and never returned, which is the whole point.
function Get-StringLiterals([string] $Src) {
  $out = New-Object System.Collections.ArrayList
  $n = $Src.Length
  $j = 0
  while ($j -lt $n) {
    # Only these four characters can START a literal or a comment, and calling into Skip-CSharpLiteral for
    # every other one costs a PowerShell function call per character of the engine's ~500KB of source --
    # seconds under pwsh 7 and minutes under Windows PowerShell 5.1, which this must also run on. The
    # cheap pre-test changes no outcome: Skip-CSharpLiteral returns its input unchanged for anything else.
    $c0 = $Src[$j]
    if ($c0 -ne '/' -and $c0 -ne '"' -and $c0 -ne "'" -and $c0 -ne '@') { $j++; continue }
    $k = Skip-CSharpLiteral $Src $j
    if ($k -ne $j) {
      $c = $Src[$j]
      $isString = ($c -eq '"') -or ($c -eq '@' -and $j + 1 -lt $n -and $Src[$j + 1] -eq '"')
      if ($isString) {
        [void] $out.Add([pscustomobject] @{ Start = $j; End = $k; Text = $Src.Substring($j, $k - $j) })
      }
      $j = $k
      continue
    }
    $j++
  }
  return $out
}

# A member name written as JSON text looks like \"name\": in a normal literal and ""name"": in a verbatim
# one. Both forms are searched so switching a builder to @"..." cannot launder a bypass past this.
function Get-MemberNameHits([string] $LiteralText, [string] $Name) {
  $hits = 0
  foreach ($needle in @("\`"$Name\`":", "`"`"$Name`"`":")) {
    $i = 0
    while ($true) {
      $i = $LiteralText.IndexOf($needle, $i, [StringComparison]::Ordinal)
      if ($i -lt 0) { break }
      $hits++
      $i += $needle.Length
    }
  }
  return $hits
}

# Is the value appended straight after this literal a JSON BOOLEAN? That is what separates a row's
# "stopped" flag from the event's "stopped" thread id -- the NAME cannot, which is the defect this whole
# ticket is about, so the classification is made on the VALUE.
#
# It reads THIS .Append's argument and nothing past it. The obvious regex version -- match forward to a
# `? "true" : "false"` -- is wrong in exactly the way this file is about: the row members are appended in
# a chain, so a lazy or greedy scan from the "stopped" literal runs straight on into the "selected"
# member's ternary and reports a raw tid as a boolean. It was written that way first and the mutation
# self-test below caught it, which is the only reason this comment exists. So the argument is delimited by
# its own matching parenthesis, and the ternary has to be at the END of it.
function Test-BooleanValueFollows([string] $Src, [int] $LiteralEnd) {
  $tail = $Src.Substring($LiteralEnd, [Math]::Min(400, $Src.Length - $LiteralEnd))
  $m = [regex]::Match($tail, '^\s*\)\s*\.Append\(')
  if (-not $m.Success) { return $false }

  $i = $m.Length        # first character of the argument
  $depth = 1
  while ($i -lt $tail.Length) {
    $k = Skip-CSharpLiteral $tail $i
    if ($k -ne $i) { $i = $k; continue }
    $c = $tail[$i]
    if ($c -eq '(') { $depth++ }
    elseif ($c -eq ')') { $depth--; if ($depth -eq 0) { break } }
    $i++
  }
  if ($depth -ne 0) { return $false }

  $arg = $tail.Substring($m.Length, $i - $m.Length)
  return $arg -match '\?\s*"true"\s*:\s*"false"\s*$'
}

# ---------------------------------------------------------------- the scan

# Returns the findings for one file: every declared-name occurrence that is NOT a boolean row flag.
function Get-Bypasses([string] $Src, [string] $FileName, [string[]] $Names) {
  $found = New-Object System.Collections.ArrayList
  foreach ($lit in (Get-StringLiterals $Src)) {
    foreach ($name in $Names) {
      $hits = Get-MemberNameHits $lit.Text $name
      if ($hits -eq 0) { continue }
      $isBool = Test-BooleanValueFollows $Src $lit.End
      for ($h = 0; $h -lt $hits; $h++) {
        [void] $found.Add([pscustomobject] @{
          File    = $FileName
          Line    = ($Src.Substring(0, $lit.Start) -split "`n").Count
          Name    = $name
          Literal = $lit.Text
          Boolean = $isBool
        })
      }
    }
  }
  return $found
}

function Invoke-Scan([hashtable] $Sources, [string[]] $Names) {
  $all = New-Object System.Collections.ArrayList
  foreach ($f in ($Sources.Keys | Sort-Object)) {
    foreach ($x in (Get-Bypasses $Sources[$f] $f $Names)) { [void] $all.Add($x) }
  }
  return $all
}

Write-Host 'test-engine-tid-members: no thread-id JSON member is written outside the shared writer'
Write-Host ''

$ruleSrc = [IO.File]::ReadAllText($ruleFile)
$names = @(Get-DeclaredTidMemberNames $ruleSrc)

Check 'DebugEngine.cs declares the thread-id member names in one array' ($names.Count -gt 0) `
      'TidValuedMemberNames was not found -- the set this check reads is gone'
Check 'all declared names resolved through their TidMember* constants' `
      (-not ($names | Where-Object { $_ -like '<unresolved:*' })) "got: $($names -join ', ')"
# THREE, and the number is read off the code above rather than asserted against a retyped list. It is
# stated here so that adding a name is a decision someone makes on purpose, in two files, not a drift.
Check 'the engine declares 3 thread-id member names' ($names.Count -eq 3) "got $($names.Count): $($names -join ', ')"

# The writer must be name-AGNOSTIC: it builds the member from its parameter, so it contains no declared
# name as JSON text. If it ever grows one, this check's absolute would need an exception, and it does not.
$writer = Get-CSharpBlock 'private static void AppendTidValuedMember(' $ruleSrc
Check 'the shared writer exists' ($null -ne $writer) 'AppendTidValuedMember was not found in DebugEngine.cs'
if ($writer) {
  $writerHits = 0
  foreach ($n in $names) { $writerHits += (Get-MemberNameHits $writer $n) }
  Check 'the shared writer types no member name of its own' ($writerHits -eq 0) `
        'it builds the name from its parameter, so the rule below needs no exception for it'
}

# The checker's exclusion, earned rather than assumed: it writes nothing to the wire.
$checkerSrc = [IO.File]::ReadAllText((Join-Path $engineDir $checkerFile))
Check "$checkerFile emits nothing to the wire, so excluding it is safe" `
      ($checkerSrc.IndexOf('"@JSON', [StringComparison]::Ordinal) -lt 0) `
      'it now carries the @JSON emit marker and can no longer be treated as a pure checker'

$sources = @{}
foreach ($f in (Get-ChildItem -Path $engineDir -Filter *.cs -File | Sort-Object Name)) {
  if ($f.Name -eq $checkerFile) { continue }
  $sources[$f.Name] = [IO.File]::ReadAllText($f.FullName)
}
# CONTROL for the exclusion above: the marker it keys on has to be real somewhere, or the check is empty.
Check 'the @JSON emit marker exists in the scanned sources' `
      (@($sources.Values | Where-Object { $_.IndexOf('"@JSON', [StringComparison]::Ordinal) -ge 0 }).Count -gt 0) `
      'nothing emits @JSON any more -- the marker this keys on has moved'

$hits = @(Invoke-Scan $sources $names)
$bypasses = @($hits | Where-Object { -not $_.Boolean })
$booleans = @($hits | Where-Object { $_.Boolean })

Check 'no declared thread-id member name is written as JSON text outside the writer' ($bypasses.Count -eq 0) `
      ($(if ($bypasses.Count) {
           ($bypasses | ForEach-Object { "$($_.File):$($_.Line) typed $($_.Name) as $($_.Literal)" }) -join ' | '
         } else { '' }))

# The per-row BOOLEANS that share these names. THREE of them, each named, because "some booleans are fine"
# would let a fourth one in without anybody looking at it. They are:
#   DebugEngine.Threads.cs    a row's "stopped"  (is this the thread execution halted on?)
#   DebugEngine.Threads.cs    a row's "selected" (is this the thread the reads are pointed at?)
#   DebugEngine.ThreadScan.cs a row's "stopped"
Check 'exactly 3 same-named members are per-row booleans' ($booleans.Count -eq 3) `
      "got $($booleans.Count): $(($booleans | ForEach-Object { "$($_.File):$($_.Line) $($_.Name)" }) -join ', ')"

# ---------------------------------------------------------------- mutation self-test
#
# Each mutation is applied to a COPY of the real source and the scan is re-run over it. The check must go
# from clean to a finding. This is the part that distinguishes a guard from a line of code that has never
# been asked a question it could answer wrongly.

if ($SelfTest) {
  Write-Host ''
  Write-Host '  -- mutation self-test (each must be CAUGHT) --'

  function Test-Mutation([string] $What, [string] $File, [string] $Find, [string] $Replace, [string] $Expect) {
    $mut = @{}
    foreach ($k in $sources.Keys) { $mut[$k] = $sources[$k] }
    if (-not $mut.ContainsKey($File)) { Check "mutation '$What'" $false "no such file $File"; return }
    if ($mut[$File].IndexOf($Find, [StringComparison]::Ordinal) -lt 0) {
      Check "mutation '$What'" $false "the text it mutates is not in $File -- the mutation is vacuous"
      return
    }
    $mut[$File] = $mut[$File].Replace($Find, $Replace)
    $h = @(Invoke-Scan $mut $names)
    $b = @($h | Where-Object { -not $_.Boolean })
    $bl = @($h | Where-Object { $_.Boolean })
    $caught = switch ($Expect) {
      'bypass'  { $b.Count -gt 0 }
      'boolean' { $bl.Count -ne 3 }
      default   { $false }
    }
    Check "CAUGHT: $What" $caught "bypasses=$($b.Count) booleans=$($bl.Count)"
  }

  # 1. The exact defect the rule exists to stop: a new emitter types the member.
  Test-Mutation 'a fifth emitter types ,"tid": into a StringBuilder' 'DebugEngine.Threads.cs' `
    'sb.Append("{\"event\":\"threads\"");' `
    'sb.Append("{\"event\":\"threads\"").Append(",\"tid\":").Append(stoppedTid);' 'bypass'

  # 2. The same thing under one of the OTHER names -- the hole this ticket was opened for.
  Test-Mutation 'a top-level "stopped" goes back to a raw append' 'DebugEngine.ThreadScan.cs' `
    'AppendTidValuedMember(sb, TidMemberStopped, stoppedTid);' `
    'sb.Append(",\"stopped\":").Append(stoppedTid);' 'bypass'

  # 3. A row's boolean flag turned into a thread id -- the name is unchanged, so only the VALUE test sees
  #    it. This is the case a name-based scanner would wave through.
  Test-Mutation 'a row boolean is swapped for a raw tid under the same name' 'DebugEngine.Threads.cs' `
    '.Append(",\"stopped\":").Append(p.IsStopped ? "true" : "false")' `
    '.Append(",\"stopped\":").Append(p.Tid)' 'bypass'

  # 4. A bypass hidden in a verbatim string, which the escape form would miss.
  Test-Mutation 'a bypass laundered through a verbatim string' 'DebugEngine.Threads.cs' `
    'sb.Append("{\"event\":\"threads\"");' `
    'sb.Append("{\"event\":\"threads\"").Append(@",""tid"":").Append(stoppedTid);' 'bypass'

  # 5. A boolean row flag deleted: the count is a claim, so it has to fail when it stops being true.
  Test-Mutation 'a per-row boolean disappears' 'DebugEngine.ThreadScan.cs' `
    '.Append(",\"stopped\":").Append(p.IsStopped ? "true" : "false")' `
    '.Append("")' 'boolean'

  # 6. THE CONTROL FOR THE WALK ITSELF. A member name typed in a COMMENT must NOT be reported -- the rule
  #    holder's own comments are full of them, and a check that cries wolf on prose gets deleted.
  $mut = @{}
  foreach ($k in $sources.Keys) { $mut[$k] = $sources[$k] }
  $mut['DebugEngine.Threads.cs'] = $mut['DebugEngine.Threads.cs'].Replace(
    'sb.Append("{\"event\":\"threads\"");',
    "// a comment that writes ,\`"tid\`": and ,\`"stopped\`": in prose" + [Environment]::NewLine +
    '            sb.Append("{\"event\":\"threads\"");')
  $h = @(Invoke-Scan $mut $names)
  Check 'NOT caught (correctly): the same text in a COMMENT' `
        ((@($h | Where-Object { -not $_.Boolean })).Count -eq 0) `
        'a member name discussed in prose was reported as an emit'
}

Write-Host ''
if ($fail -eq 0) {
  Write-Host "test-engine-tid-members: PASS ($pass checks). Every thread-id member the engine writes goes"
  Write-Host "  through AppendTidValuedMember or WithTid. The $($names.Count) declared names"
  Write-Host "  ($($names -join ', ')) appear as JSON text in $($sources.Count) engine source file(s) only as the 3"
  Write-Host '  per-row booleans that share them; a hand-written thread-id member anywhere else fails this.'
  exit 0
}
Write-Host "test-engine-tid-members: FAIL ($fail of $($fail + $pass) checks)" -ForegroundColor Red
exit 1
