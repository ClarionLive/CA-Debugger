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
