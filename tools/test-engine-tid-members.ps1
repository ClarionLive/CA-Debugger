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
$ruleFileName = 'DebugEngine.cs'
$ruleFile  = Join-Path $engineDir $ruleFileName

# ProtocolCheck.cs is the CHECKER, not an emitter: it is full of member-name literals because asserting on
# them is its job. The exclusion is earned below rather than assumed -- a file that emits nothing to the
# wire cannot emit a bad tid to it -- and the check for that is the '@JSON' marker every emit carries.
$checkerFile = 'ProtocolCheck.cs'

# Check now comes from lib-check.ps1 (via lib-extract.ps1 above). This file used to carry its own, printing
# "  ok   " with a " -- " separator and counting into $pass/$fail - a private vocabulary for the same two
# outcomes every other suite reports. The visible output changes to "  PASS  " / "  ->  " deliberately: one
# way of saying "this failed" across the folder is the point of the hoist.

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

Invoke-CheckSection 'the declared thread-id member names are read off DebugEngine.cs' {
  Check 'DebugEngine.cs declares the thread-id member names in one array' ($names.Count -gt 0) `
        'TidValuedMemberNames was not found -- the set this check reads is gone'
  Check 'all declared names resolved through their TidMember* constants' `
        (-not ($names | Where-Object { $_ -like '<unresolved:*' })) "got: $($names -join ', ')"
  # THREE, and the number is read off the code above rather than asserted against a retyped list. It is
  # stated here so that adding a name is a decision someone makes on purpose, in two files, not a drift.
  Check 'the engine declares 3 thread-id member names' ($names.Count -eq 3) "got $($names.Count): $($names -join ', ')"
}

# The writer must be name-AGNOSTIC: it builds the member from its parameter, so it contains no declared
# name as JSON text. If it ever grows one, this check's absolute would need an exception, and it does not.
Invoke-CheckSection 'the shared writer types no member name of its own' {
  $writer = Get-CSharpBlock 'private static void AppendTidValuedMember(' $ruleSrc
  Check 'the shared writer exists' ($null -ne $writer) 'AppendTidValuedMember was not found in DebugEngine.cs'
  if ($writer) {
    $writerHits = 0
    foreach ($n in $names) { $writerHits += (Get-MemberNameHits $writer $n) }
    Check 'the shared writer types no member name of its own' ($writerHits -eq 0) `
          'it builds the name from its parameter, so the rule below needs no exception for it'
  }
}

# The checker's exclusion, earned rather than assumed: it writes nothing to the wire.
Invoke-CheckSection 'the checker''s exclusion is earned' {
  $checkerSrc = [IO.File]::ReadAllText((Join-Path $engineDir $checkerFile))
  Check "$checkerFile emits nothing to the wire, so excluding it is safe" `
        ($checkerSrc.IndexOf('"@JSON', [StringComparison]::Ordinal) -lt 0) `
        'it now carries the @JSON emit marker and can no longer be treated as a pure checker'
}

$sources = @{}
foreach ($f in (Get-ChildItem -Path $engineDir -Filter *.cs -File | Sort-Object Name)) {
  if ($f.Name -eq $checkerFile) { continue }
  $sources[$f.Name] = [IO.File]::ReadAllText($f.FullName)
}
# CONTROL for the exclusion above: the marker it keys on has to be real somewhere, or the check is empty.
Invoke-CheckSection 'the @JSON emit marker is real in the scanned sources' {
  Check 'the @JSON emit marker exists in the scanned sources' `
        (@($sources.Values | Where-Object { $_.IndexOf('"@JSON', [StringComparison]::Ordinal) -ge 0 }).Count -gt 0) `
        'nothing emits @JSON any more -- the marker this keys on has moved'
}

Invoke-CheckSection 'no thread-id member name is typed as JSON text outside the writer' {
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
}

# ---------------------------------------------------------------- the hole in the check above
#
# Everything so far searches for the NAME. That is blind to the one shape it cannot see: a member whose
# name is not in the literal at all, because it was assembled around a variable --
#
#     sb.Append(",\"").Append(someName).Append("\":").Append(tid);
#
# which is EXACTLY what the shared writer does, and therefore exactly what a bypass would look like if
# someone copied it. No declared name appears anywhere in that line, so the scan above says nothing.
#
# Nobody would write that by accident. That is also what was said about the four breakages that have
# already happened, so it is closed rather than argued about: a string literal consisting of NOTHING BUT
# the punctuation around a member name is only legitimate inside the rule holder. There are exactly 2 in
# the engine's emitting sources today -- `,\"` and `\":` in AppendTidValuedMember, and `\":` in WithTid --
# and all of them are inside the two blocks that hold the rule.

# A literal that carries JSON member punctuation and NO NAME: the name is coming from somewhere else.
#
# A bare `\"` is NOT in this set and must not be: Json.cs's string escaper emits one constantly, and
# including it flagged 20 lines of the escaper as thread-id bypasses. The set is the punctuation that
# OPENS or CLOSES a member name specifically -- a leading `,\"` or `{\"`, and the closing `\":`.
$nameless = @(',\"', '{\"', '\":')

function Get-AllowedRanges([string] $Src) {
  # PSCustomObjects rather than nested arrays on purpose: PowerShell unrolls an array returned from a
  # function, so @(@(a,b),@(c,d)) can arrive as four loose integers and the range test then silently
  # matches nothing. That is how the first version of this check reported the writer's own delimiters as
  # bypasses -- a check that fails loudly, at least, unlike the reverse.
  $ranges = New-Object System.Collections.ArrayList
  foreach ($sig in @('private static void AppendTidValuedMember(', 'private static string WithTid(')) {
    $block = Get-CSharpBlock $sig $Src
    if ($null -eq $block) { continue }
    $at = $Src.IndexOf($block, [StringComparison]::Ordinal)
    if ($at -ge 0) { [void] $ranges.Add([pscustomobject] @{ Start = $at; End = $at + $block.Length }) }
  }
  return ,$ranges.ToArray()
}

function Get-NamelessDelimiters([hashtable] $Sources, [array] $AllowedRanges) {
  $out = New-Object System.Collections.ArrayList
  foreach ($f in ($Sources.Keys | Sort-Object)) {
    $src = $Sources[$f]
    foreach ($lit in (Get-StringLiterals $src)) {
      # the literal's CONTENT, i.e. the source text with its surrounding quotes removed
      if ($lit.Text.Length -lt 2 -or $lit.Text[0] -ne '"') { continue }
      $body = $lit.Text.Substring(1, $lit.Text.Length - 2)
      if ($nameless -notcontains $body) { continue }
      $allowed = $false
      if ($f -eq $ruleFileName) {
        foreach ($r in $AllowedRanges) {
          if ($lit.Start -ge $r.Start -and $lit.Start -lt $r.End) { $allowed = $true }
        }
      }
      [void] $out.Add([pscustomobject] @{
        File = $f; Line = ($src.Substring(0, $lit.Start) -split "`n").Count; Text = $lit.Text; Allowed = $allowed
      })
    }
  }
  return $out
}

Invoke-CheckSection 'no member name is assembled around a variable outside the rule holder' {
  $allowedRanges = Get-AllowedRanges $ruleSrc
  Check 'both rule-holder blocks were located in DebugEngine.cs' ($allowedRanges.Count -eq 2) `
        "found $($allowedRanges.Count) of 2 (AppendTidValuedMember, WithTid) - without them every writer line reads as a bypass"

  $nameless_hits = @(Get-NamelessDelimiters $sources $allowedRanges)
  $namelessBad = @($nameless_hits | Where-Object { -not $_.Allowed })
  Check 'no member name is ASSEMBLED around a variable outside the rule holder' ($namelessBad.Count -eq 0) `
        ($(if ($namelessBad.Count) {
             ($namelessBad | ForEach-Object { "$($_.File):$($_.Line) $($_.Text)" }) -join ' | '
           } else { '' }))
  # CONTROL: the writer's own delimiters must still be FOUND, or the check above passes because the walk
  # sees nothing rather than because there is nothing to see. FOUR, and the number is checkable against the
  # two rule holders: AppendTidValuedMember opens with `,\"` and closes with `\":`, WithTid opens with `{\"`
  # and closes with `\":`. (It said 3 first, from a grep that did not show WithTid's opener; the check
  # disagreed with the claim and the check was right, which is the entire argument for stating a number.)
  $namelessOk = @($nameless_hits | Where-Object { $_.Allowed })
  Check 'and the rule holder still assembles its own (4 delimiter literals)' ($namelessOk.Count -eq 4) `
        "got $($namelessOk.Count): $(($namelessOk | ForEach-Object { "$($_.File):$($_.Line) $($_.Text)" }) -join ', ')"
}

# ---------------------------------------------------------------- a thread id headed for a HUMAN
#
# WHY THIS IS HERE AS WELL AS IN ProtocolCheck. Piper2's TidText claim (c54f230) drives the real refusal
# paths, so it catches a REVERTED site: an existing TidText(...) changed back to a raw id. It cannot catch
# a site NOBODY HAS WRITTEN YET, and he measured that only 2 of the 7 TidText sites are reachable without
# a live debuggee. This scan reads the source, so it catches the unwritten one. NEITHER ALONE IS THE
# COVERAGE - the runtime check owns "someone broke this", the source scan owns "someone wrote a new one
# without it", and the two together are what the rule actually needs.
#
# THE RULE: a string literal ending in "thread " and concatenated onward with ` + ` must be concatenated
# with TidText(...). A bare uint reaches the user as "thread 0" or "thread 4294967295" for exactly the two
# sentinels TidIsKnown rejects.
$tidTextFiles = @('DebugEngine.VarEdit.cs', 'DebugEngine.Locals.cs', 'DebugEngine.Threads.cs')

# THREE SITES ARE EXEMPT, for three DIFFERENT reasons, and the count is asserted below so the list cannot
# grow quietly. Measured 2026-09-20 against integration/w2run2. Keyed on (file, literal) rather than on a
# line number, which drifts; a fourth exemption is a decision someone has to make, not a chore.
#   Threads.cs  "  [Clarion thread "        NOT AN OS TID AT ALL. The Clarion thread NUMBER is a different
#       namespace, where TidIsKnown's 0 / uint.MaxValue sentinels mean nothing - TidText would be wrong
#       here, not merely unnecessary.
#   Threads.cs  "unknown or exited thread " ECHOES THE ID THE USER TYPED. "unknown or exited thread
#       (unknown)" is worse than useless; repeating what they asked for is the honest reply.
#   Threads.cs  "thread "                   also an echo, in the injected-break-thread refusal, reached
#       only after _threads.Contains(tid) - so the id is live and TidText would render it identically.
#       Exempt because it is an ECHO, not because it happens to be harmless: if that message ever moves
#       off the validated path it needs TidText like any other.
$tidTextExempt = @(
  @{ File = 'DebugEngine.Threads.cs'; Literal = '"  [Clarion thread "' },
  @{ File = 'DebugEngine.Threads.cs'; Literal = '"unknown or exited thread "' },
  @{ File = 'DebugEngine.Threads.cs'; Literal = '"thread "' }
)

function Get-ThreadPrefixSites([hashtable] $Sources) {
  $out = New-Object System.Collections.ArrayList
  foreach ($f in ($Sources.Keys | Sort-Object)) {
    $src = $Sources[$f]
    foreach ($lit in (Get-StringLiterals $src)) {
      # The literal must END with `thread ` - that is what puts the next token in the user's sentence.
      # Comments cannot reach here: Get-StringLiterals walks through Skip-CSharpLiteral, which is the same
      # reason the member-name scan above is comment-proof.
      if ($lit.Text.Length -lt 9) { continue }
      if ($lit.Text.Substring($lit.Text.Length - 8) -cne 'thread "') { continue }
      $tail = $src.Substring($lit.End, [Math]::Min(60, $src.Length - $lit.End))
      if ($tail -notmatch '^\s*\+') { continue }          # not concatenated onward: nothing follows it
      [void] $out.Add([pscustomobject] @{
        File    = $f
        Line    = ($src.Substring(0, $lit.Start) -split "`n").Count
        Literal = $lit.Text
        ViaTidText = ($tail -match '^\s*\+\s*TidText\s*\(')
        Exempt  = [bool] @($tidTextExempt | Where-Object { $_.File -eq $f -and $_.Literal -eq $lit.Text }).Count
        Tail    = ($tail -replace '\s+', ' ').Trim()
      })
    }
  }
  return $out
}

$tidSrc = @{}
foreach ($f in $tidTextFiles) { $tidSrc[$f] = [IO.File]::ReadAllText((Join-Path $engineDir $f)) }
Invoke-CheckSection 'every thread id headed for a human goes through TidText' {
  $tidSites = @(Get-ThreadPrefixSites $tidSrc)
  $tidBad = @($tidSites | Where-Object { -not $_.ViaTidText -and -not $_.Exempt })
  Check 'every "thread " message that is not an echo renders its id through TidText' ($tidBad.Count -eq 0) `
        ($(if ($tidBad.Count) { ($tidBad | ForEach-Object { "$($_.File):$($_.Line) $($_.Literal) $($_.Tail)" }) -join ' | ' } else { '' }))
  # CONTROL: the scan must SEE the real sites, or the rule above is satisfied by finding nothing at all.
  $tidGood = @($tidSites | Where-Object { $_.ViaTidText })
  Check 'and the scan actually reaches them (9 sites go through TidText)' ($tidGood.Count -eq 9) `
        "found $($tidGood.Count)"
  # A NUMBER, not "some": a fourth exemption must be argued for, not absorbed.
  $tidEx = @($tidSites | Where-Object { $_.Exempt })
  Check 'exactly 3 exempt sites, all of them echoes or a Clarion thread number' ($tidEx.Count -eq 3) `
        "found $($tidEx.Count): $(($tidEx | ForEach-Object { "$($_.File):$($_.Line)" }) -join ', ')"
}

# ---------------------------------------------------------------- the scope this check assumes
#
# It scans src\ClarionDbg.Cli and nothing else, which is only correct while that is where the wire is
# written. ClarionDbg.Core carries no JSON emitter today; if one appears there, this check goes quiet
# rather than wrong, which is the worse failure. So the assumption is asserted rather than left implicit.
Invoke-CheckSection 'ClarionDbg.Core writes no wire JSON' {
  $coreDir = Join-Path $repo 'src\ClarionDbg.Core'
  $coreJson = @()
  if (Test-Path $coreDir) {
    $coreJson = @(Get-ChildItem -Path $coreDir -Filter *.cs -File -Recurse | Where-Object {
      $t = [IO.File]::ReadAllText($_.FullName)
      $t.IndexOf('"@JSON', [StringComparison]::Ordinal) -ge 0 -or $t.IndexOf('\"event\":', [StringComparison]::Ordinal) -ge 0
    })
  }
  Check 'ClarionDbg.Core writes no wire JSON, so scanning only ClarionDbg.Cli is the whole surface' `
        ($coreJson.Count -eq 0) `
        "$(($coreJson | ForEach-Object { $_.Name }) -join ', ') now emit(s) events - widen the scan or this check is silently partial"
}

# ---------------------------------------------------------------- mutation self-test
#
# Each mutation is applied to a COPY of the real source and the scan is re-run over it. The check must go
# from clean to a finding. This is the part that distinguishes a guard from a line of code that has never
# been asked a question it could answer wrongly.

if ($SelfTest) {
  Write-Host ''
  Invoke-CheckSection 'mutation self-test (each must be CAUGHT)' {

    # EVERY RULE THIS FILE ENFORCES, by the name Test-Mutation's switch knows it under (ticket 6874c2d1). The
    # last check below requires each to have been CAUGHT at least once, so a rule added to the file without a
    # mutation here fails the self-test instead of leaving the table claiming less than the file enforces -
    # which is what happened to the TidText rule, proved once by a pipeline verifier and then nowhere.
    $RuleKinds = @('bypass', 'boolean', 'nameless', 'namelessCount', 'tidtext', 'tidtextCount')
    $script:caughtKinds = @()

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
      # The nameless-delimiter scan re-derives its allowed ranges from the MUTATED DebugEngine.cs, or a
      # mutation that shifted offsets in that file would show up as a bypass for the wrong reason.
      $nd = @(Get-NamelessDelimiters $mut (Get-AllowedRanges $mut[$ruleFileName]))
      $ndBad = @($nd | Where-Object { -not $_.Allowed })
      $ndOk  = @($nd | Where-Object { $_.Allowed })
      # The TidText scan over the same mutated copy, restricted to the files the real scan reads.
      $mutTid = @{}
      foreach ($f in $tidTextFiles) { $mutTid[$f] = $mut[$f] }
      $ts = @(Get-ThreadPrefixSites $mutTid)
      $tsBad  = @($ts | Where-Object { -not $_.ViaTidText -and -not $_.Exempt })
      $tsGood = @($ts | Where-Object { $_.ViaTidText })
      $caught = switch ($Expect) {
        'bypass'        { $b.Count -gt 0 }
        'boolean'       { $bl.Count -ne 3 }
        'nameless'      { $ndBad.Count -gt 0 }
        'namelessCount' { $ndOk.Count -ne 4 }
        'tidtext'       { $tsBad.Count -gt 0 }
        'tidtextCount'  { $tsGood.Count -ne 9 }
        default         { $false }
      }
      if ($caught) { $script:caughtKinds += $Expect }
      Check "CAUGHT: $What" $caught `
            ("bypasses=$($b.Count) booleans=$($bl.Count) assembled-outside=$($ndBad.Count) writer-delims=$($ndOk.Count)" +
             " raw-thread-sites=$($tsBad.Count) tidtext-sites=$($tsGood.Count)")
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

    # 6. THE HOLE IN EVERY CHECK ABOVE: a member whose NAME IS NEVER IN A LITERAL, assembled around a
    #    variable the way the shared writer itself does it. Every name-based check is blind to this by
    #    construction, which is why the delimiter rule exists at all.
    Test-Mutation 'a member name assembled around a variable, outside the writer' 'DebugEngine.Threads.cs' `
      'sb.Append("{\"event\":\"threads\"");' `
      'sb.Append("{\"event\":\"threads\"").Append(",\"").Append(TidMemberStopped).Append("\":").Append(stoppedTid);' `
      'nameless'

    # 7. And the CONTROL for that rule: the writer's own 4 delimiters must still be found where they are.
    #    Without this, mutation 6 would pass just as well against a version that found nothing anywhere.
    Test-Mutation 'one of the writer''s own delimiters goes missing' 'DebugEngine.cs' `
      'sb.Append(",\"").Append(name).Append("\":").Append(tid);' `
      'sb.Append(",").Append(Json.Str(name)).Append(":").Append(tid);' `
      'namelessCount'

    # 8-9. THE TidText RULE, the two mutations the Run 2 verifier ran by hand (6874c2d1). A REVERTED site: an
    #    existing TidText(...) changed back to the raw id. It must be reported by file:line, AND the control
    #    must drop from 9 to 8 - one mutation, two rules, so it is run once per rule.
    Test-Mutation 'a TidText site reverted to the raw id is reported' 'DebugEngine.VarEdit.cs' `
      '" touches thread " + TidText(OwnerTid) + "''s copy of the "' `
      '" touches thread " + OwnerTid + "''s copy of the "' 'tidtext'
    Test-Mutation '...and the same revert drops the TidText control from 9' 'DebugEngine.VarEdit.cs' `
      '" touches thread " + TidText(OwnerTid) + "''s copy of the "' `
      '" touches thread " + OwnerTid + "''s copy of the "' 'tidtextCount'

    # 10. A BRAND-NEW raw site nobody has written yet - the case the runtime check in ProtocolCheck cannot
    #    see, and the reason this source rule exists. The 9 real sites are untouched, so only the rule fires.
    Test-Mutation 'a new raw "thread " + id site is reported' 'DebugEngine.VarEdit.cs' `
      '" and thread " + TidText(SelectedTid) + " has no instance of it";' `
      '" and thread " + TidText(SelectedTid) + " has no instance of it" + "; last written by thread " + OwnerTid;' 'tidtext'

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

    # The table covers the file: every rule above was seen to fail at least once.
    $uncovered = @($RuleKinds | Where-Object { $script:caughtKinds -notcontains $_ })
    Check "every rule has a caught self-test mutation ($($RuleKinds.Count) rules)" ($uncovered.Count -eq 0) `
          $(if ($uncovered.Count) { "no caught mutation for: $($uncovered -join ', ')" } else { '' })
  }
}

# THE COUNT, ASSERTED AND PRINTED (60344b78). This file used to PRINT a count and assert none, so a section
# that returned early simply shrank the number. Invoke-CheckSection above closes a section that throws or
# breaks out of the script; this closes one that returns early or is skipped. COUNTING RULE: the RUNTIME
# count of Check calls ($script:checks before this line) on a clean run, measured 2026-09-22 - the
# -SelfTest run adds its 12 mutation checks. Update both deliberately with the checks.
$EXPECTED_CHECKS = if ($SelfTest) { 28 } else { 16 }
Assert-CheckTotal $EXPECTED_CHECKS

Write-Host ''
$fail = $script:failures
$pass = $script:checks - $script:failures
if ($fail -eq 0) {
  Write-Host "test-engine-tid-members: PASS ($pass checks). Every thread-id member the engine writes goes"
  Write-Host "  through AppendTidValuedMember or WithTid. The $($names.Count) declared names"
  Write-Host "  ($($names -join ', ')) appear as JSON text in $($sources.Count) engine source file(s) only as the 3"
  Write-Host '  per-row booleans that share them; a hand-written thread-id member anywhere else fails this,'
  Write-Host '  and so does one whose name never appears in a literal at all because it was assembled around'
  Write-Host '  a variable -- the 4 delimiters that do that belong to the writer and are where they were.'
  Write-Host ''
  Write-Host "ALL $($script:checks) CHECKS PASSED"
  exit 0
}
Write-Host "test-engine-tid-members: FAIL ($fail of $($fail + $pass) checks)" -ForegroundColor Red
Write-Host "$fail of $($script:checks) CHECKS FAILED"
exit 1
