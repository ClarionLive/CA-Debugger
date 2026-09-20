# The shared Check/ShowVal/section runner, so a harness that dot-sources THIS file needs no second line.
# Loaded before Set-StrictMode below, which is deliberate: lib-check.ps1 must stay loadable on its own by
# suites that are not strict-clean (see its header).
. (Join-Path $PSScriptRoot 'lib-check.ps1')

# Pull a named block or declaration straight out of a C# source file, so a test can compile and drive the
# REAL shipped code instead of a paraphrase of it. Dot-source this: . "$PSScriptRoot\lib-extract.ps1"
#
# WHY IT IS NOT JUST BRACE COUNTING. The obvious version counts { and } and stops at zero, and it is wrong
# the moment the code it is extracting contains a brace inside a char literal, a string or a comment -
# which the JSON reader and the container skipper both do:
#
#     if (c == '{' || c == '[') { depth++; i++; continue; }
#
# A naive count reads that '{' as structure and stops in the wrong place, silently returning a fragment that
# either fails to compile or, worse, compiles as something other than what ships. So this skips string
# literals, verbatim strings, char literals and both comment forms before counting anything - the same
# distinction the reader under test exists to make, which is not a coincidence: text that contains its own
# delimiters cannot be scanned by looking for the delimiters.

Set-StrictMode -Version Latest

# Advance past a literal or comment starting at $j, or return $j unchanged when there is none there.
function Skip-CSharpLiteral {
  param([string] $S, [int] $J)
  $n = $S.Length
  if ($J -ge $n) { return $J }
  $c = $S[$J]

  if ($c -eq '/' -and $J + 1 -lt $n) {
    $d = $S[$J + 1]
    if ($d -eq '/') {
      while ($J -lt $n -and $S[$J] -ne "`n") { $J++ }
      return $J
    }
    if ($d -eq '*') {
      $J += 2
      while ($J + 1 -lt $n -and -not ($S[$J] -eq '*' -and $S[$J + 1] -eq '/')) { $J++ }
      return [Math]::Min($J + 2, $n)
    }
    return $J
  }

  # verbatim string: @"..."  with "" as the escaped quote
  if ($c -eq '@' -and $J + 1 -lt $n -and $S[$J + 1] -eq '"') {
    $J += 2
    while ($J -lt $n) {
      if ($S[$J] -eq '"') {
        if ($J + 1 -lt $n -and $S[$J + 1] -eq '"') { $J += 2; continue }
        return $J + 1
      }
      $J++
    }
    return $J
  }

  if ($c -eq '"' -or $c -eq "'") {
    $quote = $c
    $J++
    while ($J -lt $n) {
      if ($S[$J] -eq '\') { $J += 2; continue }
      if ($S[$J] -eq $quote) { return $J + 1 }
      $J++
    }
    return $J
  }

  return $J
}

# The text from $Signature through its matching closing brace. $null when the signature is not present.
function Get-CSharpBlock {
  param([string] $Signature, [string] $From)

  $i = $From.IndexOf($Signature, [StringComparison]::Ordinal)
  if ($i -lt 0) { return $null }

  $n = $From.Length
  $j = $i
  $depth = 0
  $started = $false

  while ($j -lt $n) {
    $skipped = Skip-CSharpLiteral $From $j
    if ($skipped -ne $j) { $j = $skipped; continue }

    $c = $From[$j]
    if ($c -eq '{') { $depth++; $started = $true; $j++; continue }
    if ($c -eq '}') {
      $depth--
      $j++
      if ($started -and $depth -eq 0) { return $From.Substring($i, $j - $i) }
      continue
    }
    $j++
  }
  return $null
}

# The text from $Signature through its terminating semicolon - for a field or const declaration, which has
# no braces to match. $null when the signature is not present.
function Get-CSharpStatement {
  param([string] $Signature, [string] $From)

  $i = $From.IndexOf($Signature, [StringComparison]::Ordinal)
  if ($i -lt 0) { return $null }

  $n = $From.Length
  $j = $i

  while ($j -lt $n) {
    $skipped = Skip-CSharpLiteral $From $j
    if ($skipped -ne $j) { $j = $skipped; continue }

    if ($From[$j] -eq ';') { return $From.Substring($i, $j - $i + 1) }
    $j++
  }
  return $null
}

# Same, for a JavaScript function or handler lifted out of the page. JS has no char literal and no verbatim
# string, but it does have both comment forms and both quote styles, which Skip-CSharpLiteral already covers.
# Template literals are not handled; nothing extracted so far uses one.
function Get-JsBlock {
  param([string] $Signature, [string] $From)
  return Get-CSharpBlock $Signature $From
}

# The source with every COMMENT removed, for a rule about what the code DOES.
#
# A raw text scan cannot tell a call from the comment explaining why that call must not be made - and the
# better the comment, the more likely it quotes the exact idiom being banned. That has now bitten three
# separate checks in this repo: the Get-Process scan in test-engine-session.ps1, the send('jump') scan in
# test-pad-bpstate.js, and a `?? _selTid` scan that found two hits in DisassemblyView.cs, BOTH of them
# comments saying "not `tid ?? _selTid`". String literals are KEPT: a rule about code usually cares about
# them, and Skip-CSharpLiteral is what tells the two apart.
function Get-CSharpCodeOnly {
  param([string] $Src)
  $sb = New-Object System.Text.StringBuilder
  $n = $Src.Length
  $j = 0
  while ($j -lt $n) {
    $c = $Src[$j]
    if ($c -ne '/' -and $c -ne '"' -and $c -ne "'" -and $c -ne '@') { [void] $sb.Append($c); $j++; continue }
    $k = Skip-CSharpLiteral $Src $j
    if ($k -eq $j) { [void] $sb.Append($c); $j++; continue }
    # A comment is dropped; a string or char literal is kept verbatim.
    $isComment = ($c -eq '/' -and $j + 1 -lt $n -and ($Src[$j + 1] -eq '/' -or $Src[$j + 1] -eq '*'))
    if ($isComment) { [void] $sb.Append(' ') } else { [void] $sb.Append($Src.Substring($j, $k - $j)) }
    $j = $k
  }
  return $sb.ToString()
}

# ------------------------------------------------------------------ the harness-facing wrappers
#
# Get-CSharpBlock above answers $null for "not there". Every harness wants the same thing from that answer -
# report it and stop - so the wrapper that does it lives here rather than in each of them. It was copied
# verbatim into three suites (as Get-Method) and a fourth (as Get-Block, same body, shorter message).
#
# THE DEFAULT SOURCE IS NOW NAMED OUT LOUD, and that is the one behavioural change in this hoist. Each copy
# ended `if (-not $From) { $From = $web }` - except test-addin-json.ps1's, which said `$src`. PowerShell
# resolves that name dynamically in the CALLER's scope, so hoisting either copy verbatim would have silently
# re-pointed the other harness's bare call sites at a different file. Extraction can still FIND a same-named
# method in the wrong file, so that failure would have been a wrong ANSWER rather than an error. Each harness
# therefore says once which text it means.
$script:ExtractSource = $null

function Set-ExtractSource {
  param([string] $Text)
  if ([string]::IsNullOrEmpty($Text)) {
    Write-Host '  FAIL  Set-ExtractSource was given no text - the source file it reads is empty or unread.'
    exit 1
  }
  $script:ExtractSource = $Text
}

# The text a bare Get-Method/Get-Statement call reads. Unset is a loud failure, never an empty search: an
# empty haystack finds nothing, and "absent from this version of the add-in" would then be a lie about the
# add-in rather than the truth about the harness.
function Resolve-ExtractSource {
  param([string] $From)
  if ($From) { return $From }
  if ([string]::IsNullOrEmpty($script:ExtractSource)) {
    Write-Host '  FAIL  no default extraction source for this harness.'
    Write-Host '        Call Set-ExtractSource <text> after dot-sourcing lib-extract.ps1, or pass the'
    Write-Host '        source text explicitly as the second argument.'
    exit 1
  }
  return $script:ExtractSource
}

function Get-ExtractMissing {
  param([string] $Signature)
  # Reported rather than thrown: a harness pointed at an add-in that predates the code under test should say
  # so plainly instead of dying halfway through, which reads like a broken test rather than the before/after
  # proof it is.
  Write-Host "  FAIL  absent from this version of the add-in: $Signature"
  Write-Host ''
  Write-Host 'This add-in predates the code these checks cover. 1 FAILURE(S)'
  exit 1
}

# A method or property block, by signature. (test-addin-hooks.ps1 called this Get-Block; one function under
# two names is the drift this hoist exists to end, so Get-Method is the single name.)
function Get-Method {
  param([string] $Signature, [string] $From)
  $block = Get-CSharpBlock $Signature (Resolve-ExtractSource $From)
  if ($null -eq $block) { Get-ExtractMissing $Signature }
  return $block
}

# A field or const declaration, which has no braces to match - read to its terminating semicolon instead.
# This is how the REAL declarations come under test rather than being re-typed into the harness.
function Get-Statement {
  param([string] $Signature, [string] $From)
  $stmt = Get-CSharpStatement $Signature (Resolve-ExtractSource $From)
  if ($null -eq $stmt) { Get-ExtractMissing $Signature }
  return $stmt
}

# Check / ShowVal / Invoke-CheckSection live in lib-check.ps1, dot-sourced on this file's first line, so a
# harness that dot-sources lib-extract gets them with no second line. See lib-check.ps1 for why they are
# not in THIS file: Set-StrictMode below would otherwise be forced on every suite that wants a Check.
