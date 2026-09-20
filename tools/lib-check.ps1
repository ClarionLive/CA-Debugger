# One answer to "what does a check look like", shared by every .ps1 harness in this folder.
# Dot-source this: . "$PSScriptRoot\lib-check.ps1"   (lib-extract.ps1 already does, so a harness that
# dot-sources lib-extract gets these for free and needs no second line.)
#
# WHY THIS IS NOT IN lib-extract.ps1. Check has nothing to do with extracting C#, and lib-extract.ps1 calls
# `Set-StrictMode -Version Latest` at top level - which a dot-source imposes on the CALLER. Putting Check
# there would have meant the one suite with no extraction to do (test-engine-session.ps1, which scans
# PowerShell) could not use it: adding that dot-source makes it throw and lose 8 of its 56 checks. A library
# that changes its caller's strictness cannot also be the library everyone is required to load.
#
# This file therefore has NO StrictMode, NO extraction and NO dependencies, so anything can load it.
#
# Check was defined SIX times before this: four verbatim, and two that had drifted - one printing "  ok   "
# with a " -- " separator and its own counters, one counting a separate total and treating an empty-string
# detail as present. Two private vocabularies for "this failed" is the drift, not the line count.

# Both counters are read. $failures decides the exit code in every suite; $checks is what lets a suite print
# and ASSERT a total, which is the backstop in Invoke-CheckSection's note below.
$script:failures = 0
$script:checks = 0

function Check {
  param([string] $Label, [bool] $Ok, [string] $Detail)
  $script:checks++
  $mark = if ($Ok) { '  PASS  ' } else { '  FAIL  '; }
  if (-not $Ok) { $script:failures++ }
  # An empty detail is ABSENT, not present-and-blank: one copy tested `$null -ne $detail` and printed a bare
  # trailing "  ->  " for every check that passed '' as its detail.
  Write-Host ($mark + $Label + $(if ($Detail) { "  ->  $Detail" } else { '' }))
}

# For a Detail argument that may be $null. `(null)` rather than `null`, so it cannot be read as a value that
# happens to be the four letters n-u-l-l - a distinction worth keeping in suites about JSON. (Was ShowS in
# one harness and ShowU in another, rendering the same absence two different ways.)
function ShowVal { param($v) if ($null -eq $v) { '(null)' } else { [string] $v } }

# Run one section of a suite so that a section which DIES is a visible failure rather than a silent absence.
#
# THE DEFECT THIS CLOSES (ticket cb9324f2). test-engine-session.ps1 runs its sections as `{ ... }.Invoke()`.
# An exception inside one is written to stderr, and then the run CONTINUES, prints its success summary and
# EXITS 0. Injecting a single `throw` into section 6 produced `ALL 42 CHECKS PASSED` and `EXIT=0` - fourteen
# checks gone, exit code says success. Nothing asserted the total, so the only tell was a number nobody
# compared.
#
# TWO GUARDS, DELIBERATELY ORDERED:
#   (a) LOAD-BEARING - this function. A section that throws yields a FAILED CHECK and therefore a non-zero
#       exit. It closes the hole on its own and needs no constant kept up to date.
#   (b) BACKSTOP - Assert-CheckTotal below, which additionally catches a section that returns EARLY without
#       throwing (an unguarded `return`, a `continue` in the wrong scope). If that constant ever becomes a
#       maintenance nuisance it can go and (a) still holds. Do not reverse the order: a pinned total alone
#       would report "the number changed" rather than "this section died, here".
function Invoke-CheckSection {
  param([string] $Name, [scriptblock] $Body)
  # The runner prints the heading, so the name in the heading and the name in a failure are the SAME string
  # and cannot drift apart.
  Write-Host $Name
  try { $Body.Invoke() }
  catch {
    # The InnerException is the one the section actually threw; .Invoke() wraps it in a
    # MethodInvocationException whose own message is about Invoke, not about the bug.
    $err = $_.Exception
    if ($err.InnerException) { $err = $err.InnerException }
    Check "section '$Name' ran to completion" $false "$($err.GetType().Name): $($err.Message)"
  }
}

# The count every check in this run went through. Pinning it turns a silently skipped section into a
# failure. See the (b) note above for what it is and is not for.
function Assert-CheckTotal {
  param([int] $Expected)
  # Counted BEFORE this call, so the assertion does not count itself.
  $actual = $script:checks
  Check "every section ran: $Expected checks reported" ($actual -eq $Expected) `
    $(if ($actual -eq $Expected) { '' } else { "$actual reported - a section was skipped, returned early or was added without updating the expected total" })
}
