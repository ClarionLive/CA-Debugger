# The suite list, read from the suites themselves (w8-suite-header, frozen 2026-10-03; ticket 49538b78).
#
# Every tools\test-*.ps1 and tools\test-*.js declares how it is run, one line per run variant, within its
# first 40 lines and (for a .ps1) above param():
#
#   # suite: live=no
#   # suite: live=no; args=-SelfTest
#   # suite: live=yes; args=-WithClarion
#   # suite: live=no; success='^all \d+ inline script block\(s\) parse OK$'
#   # suite: live=yes; nototal='reason'
#   // suite: live=no                                        (a .js suite)
#
# Keys: live=yes|no (required); args (optional, split on spaces); success (optional, an ANCHORED regex for
# the suite's own success line, else run-all's per-extension default); nototal (optional, .ps1 only: why it
# does not pin its total with Assert-CheckTotal). A value holding a space or ; is single-quoted, and a
# quoted value cannot hold a quote. ASCII only.
#
# Before this, run-all.ps1 held a hand-written $Suites array, and every wave's integration hand-merged it.
#
# Get-SuiteHeaders returns @{ Entries; Errors }. It FAILS CLOSED: a suite file with no suite line, a line
# that does not parse, a line past line 40 or below param(), an unanchored success, nototal on a .js, two
# lines with the same args, and a .ps1 with a $SelfTest parameter but no args=-SelfTest variant are each an
# Error, never a silent default. A line with an error contributes no entry.
#
# Shared by run-all.ps1 and test-engine-session.ps1 (which derives its harness set from live=yes). It sets
# no StrictMode and no $ErrorActionPreference, so it is safe to dot-source into either.

$SuiteHeaderMaxLine = 40

# Anything that LOOKS like a suite line, anywhere in the file: each one must then parse strictly, so a typo
# ("#suite:", "# Suite :") is a malformed line rather than a comment nothing reads.
$SuiteHeaderLoose = '^\s*(#|//)\s*suite\s*:'

function ConvertFrom-SuiteHeaderBody {
  # 'live=no; args=-SelfTest' -> ordered hashtable, or a string naming what is wrong.
  param([string] $Body)
  $kv = [ordered]@{}
  $rest = $Body
  while ($true) {
    $m = [regex]::Match($rest, "^(?<k>[a-z]+)=(?:'(?<q>[^']*)'|(?<b>[^\s;']+))(?<tail>.*)$")
    if (-not $m.Success) { return "cannot read a key=value at: $rest" }
    $k = $m.Groups['k'].Value
    if (@('live', 'args', 'success', 'nototal') -cnotcontains $k) { return "unknown key '$k'" }
    if ($kv.Contains($k)) { return "key '$k' given twice" }
    $kv[$k] = if ($m.Groups['q'].Success) { $m.Groups['q'].Value } else { $m.Groups['b'].Value }
    $tail = $m.Groups['tail'].Value
    if ($tail -eq '') { break }
    $sep = [regex]::Match($tail, '^\s*;\s*(?<r>.+)$')
    if (-not $sep.Success) { return "expected '; ' before: $tail" }
    $rest = $sep.Groups['r'].Value
  }
  return $kv
}

function Get-SuiteHeaders {
  param([Parameter(Mandatory)] [string] $ToolsDir)
  $entries = New-Object System.Collections.ArrayList
  $errors = New-Object System.Collections.ArrayList
  $files = @(Get-ChildItem -LiteralPath $ToolsDir -File |
             Where-Object { $_.Name -like 'test-*.ps1' -or $_.Name -like 'test-*.js' } | Sort-Object Name)
  foreach ($f in $files) {
    $isPs1 = $f.Extension -eq '.ps1'
    $prefix = if ($isPs1) { '# suite: ' } else { '// suite: ' }
    # ReadAllText strips a UTF-8 BOM; the TrimStart is for a BOM it did not recognise as one.
    $lines = [IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) -split "`r?`n"
    $paramLine = [int]::MaxValue
    $selfTestParam = $false
    if ($isPs1) {
      $perr = $null
      $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$perr)
      if ($perr.Count) { [void]$errors.Add(@{ File = $f.Name; Message = "does not parse: $($perr[0].Message)" }); continue }
      if ($ast.ParamBlock) {
        $paramLine = $ast.ParamBlock.Extent.StartLineNumber
        $selfTestParam = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SelfTest' }).Count -gt 0
      }
    }
    $mine = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $text = $lines[$i]
      if ($text -notmatch $SuiteHeaderLoose) { continue }
      $n = $i + 1
      $where = "line ${n}: $text"
      if (-not $text.StartsWith($prefix, [StringComparison]::Ordinal)) { [void]$errors.Add(@{ File = $f.Name; Message = "MALFORMED suite line (must start '$prefix'), $where" }); continue }
      if ($text -match '[^\x20-\x7E]') { [void]$errors.Add(@{ File = $f.Name; Message = "MALFORMED suite line (ASCII only), $where" }); continue }
      if ($n -gt $SuiteHeaderMaxLine) { [void]$errors.Add(@{ File = $f.Name; Message = "suite line past line $SuiteHeaderMaxLine, $where" }); continue }
      if ($n -ge $paramLine) { [void]$errors.Add(@{ File = $f.Name; Message = "suite line below param() (line $paramLine), $where" }); continue }
      $kv = ConvertFrom-SuiteHeaderBody $text.Substring($prefix.Length).TrimEnd()
      if ($kv -is [string]) { [void]$errors.Add(@{ File = $f.Name; Message = "MALFORMED suite line ($kv), $where" }); continue }
      if (-not $kv.Contains('live') -or @('yes', 'no') -cnotcontains $kv['live']) { [void]$errors.Add(@{ File = $f.Name; Message = "MALFORMED suite line (live=yes|no is required), $where" }); continue }
      if ($kv.Contains('success')) {
        if (-not $kv['success'].StartsWith('^')) { [void]$errors.Add(@{ File = $f.Name; Message = "UNANCHORED success regex (must start with ^), $where" }); continue }
        try { [void][regex]::new($kv['success']) } catch { [void]$errors.Add(@{ File = $f.Name; Message = "success is not a regex, $where" }); continue }
      }
      if ($kv.Contains('nototal') -and -not $isPs1) { [void]$errors.Add(@{ File = $f.Name; Message = "MALFORMED suite line (nototal is .ps1 only), $where" }); continue }
      if ($kv.Contains('nototal') -and -not $kv['nototal'].Trim()) { [void]$errors.Add(@{ File = $f.Name; Message = "MALFORMED suite line (an empty nototal reason), $where" }); continue }
      $args0 = @(if ($kv.Contains('args')) { $kv['args'] -split '\s+' | Where-Object { $_ } })
      $key = $args0 -join ' '
      if (@($mine | Where-Object { ($_.Args -join ' ') -ceq $key }).Count) { [void]$errors.Add(@{ File = $f.Name; Message = "two suite lines with args '$key', $where" }); continue }
      [void]$mine.Add([pscustomobject]@{
        File = $f.Name; Args = $args0; Live = ($kv['live'] -ceq 'yes')
        Success = $(if ($kv.Contains('success')) { $kv['success'] } else { $null })
        NoTotal = $(if ($kv.Contains('nototal')) { $kv['nototal'] } else { $null })
        Line = $n
      })
    }
    if (-not $mine.Count -and -not @($errors | Where-Object { $_.File -eq $f.Name }).Count) {
      [void]$errors.Add(@{ File = $f.Name; Message = "NO SUITE LINE: a suite nothing runs - add '${prefix}live=no' (or yes) within its first $SuiteHeaderMaxLine lines, above param()" })
    }
    if ($selfTestParam -and $mine.Count -and -not @($mine | Where-Object { $_.Args -ccontains '-SelfTest' }).Count) {
      [void]$errors.Add(@{ File = $f.Name; Message = "has a `$SelfTest parameter but no 'args=-SelfTest' suite line, so its mutation self-test never runs" })
    }
    foreach ($e in $mine) { [void]$entries.Add($e) }
  }
  return @{ Entries = @($entries); Errors = @($errors) }
}

function Format-SuiteEntry {
  # One stable line per entry, for -List and for diffing two lists.
  param($Entry)
  '{0} | args={1} | live={2} | success={3} | nototal={4}' -f $Entry.File, ($Entry.Args -join ' '),
    $(if ($Entry.Live) { 'yes' } else { 'no' }), $Entry.Success, $Entry.NoTotal
}
