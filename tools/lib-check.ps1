# One answer to "what does a check look like", shared by every .ps1 harness in this folder.
# Dot-source this: . "$PSScriptRoot\lib-check.ps1"   (lib-extract.ps1 already does, so a harness that
# dot-sources lib-extract gets these for free and needs no second line.)
#
# WHY THIS IS NOT IN lib-extract.ps1.
#
# THE MEASUREMENT THAT PROMPTED THE SPLIT, dated so it cannot go stale:
#   "measured 2026-09-20, before the @(Get-PokePidArgs ...) fix in test-engine-session.ps1's poke-site
#    scan - dot-sourcing lib-extract.ps1 cost that suite 8 of its 56 checks, reporting ALL 48 CHECKS
#    PASSED."
# (That named a LINE NUMBER until the code-reviewer pointed out this header states the dating rule and
#  then breaks the companion one in its own next clause - and the first correction of it pinned two MORE
#  line numbers in the same foreign file, so the rule was broken a third time inside the fix for the
#  second. PIN THE SYMBOL, NOT THE LINE: a line number in someone else's file is the least durable pin
#  there is, and naming Get-PokePidArgs costs nothing and survives every edit above it.)
# That fault is now fixed and the file IS strict-clean, so the line above is history, not a live failure.
# It is kept verbatim because a DATED measurement is a fact about the past and cannot rot; an UNDATED claim
# about present code is a live assertion and goes stale the moment the code moves. This file had the second
# kind for about an hour, and it went false the moment the fix landed - the same way the field-order
# comments in debugger.html outlived the scanner they described. Date anything you measure into a comment.
#
# The layering is KEPT for the reasons that outlived the measurement:
#   - Check has nothing to do with extracting C#. test-engine-session.ps1 would be loading a C# extractor
#     it never calls, purely to get a Check.
#   - A library that silently changes its caller's strictness cannot also be the library everyone is
#     required to load. That is true whether or not any current caller trips over it, and it puts the next
#     suite one non-strict idiom away from the same failure.
#
# This file therefore has NO StrictMode, NO extraction and NO dependencies, so anything can load it.
#
# A HOIST IS NOT FINISHED UNTIL YOU GREP FOR REDEFINITIONS OF EVERY NAME YOU HOISTED.
# A local `function X` AFTER the dot-source silently WINS: no error, no warning, and - because these
# helpers only shape Detail text and counters - no changed verdict either. Nothing in the harness can see
# it. test-addin-json.ps1 kept its own ShowVal this way for one merge (found 2026-09-20 by the pipeline
# verifier, not by any suite), rendering absence as 'null' where this file renders '(null)', in the one
# suite whose subject is JSON. Two things made it invisible: the leftover sat one line past the end of the
# block that removed its neighbour, and a later blanket rename turned it into the hoisted NAME, so it
# read as deliberate. Grep for the names, not for the shape.
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
  $mark = if ($Ok) { '  PASS  ' } else { '  FAIL  ' }
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
# FOUR GUARDS, and each one names the route it covers. The earlier version of this comment said (a) "closes
# the hole on its own"; that was measured against the route then known and a THIRD route was found later
# (see (c)), which (a) and (b) BOTH miss. Corrected rather than softened, because a guard comment that
# overstates its coverage is how the next reader stops looking.
#   (a) a section that THROWS - this function's catch. Reported as a failed check, so a non-zero exit.
#   (b) a section that RETURNS EARLY without throwing - Assert-CheckTotal, which notices the total is short.
#       Needs the constant kept up to date; if that ever becomes a nuisance it can go, and (a), (c) and (d)
#       still hold.
#   (c) a section that TERMINATES THE SCRIPT without throwing - a bare `break`/`continue` outside a loop.
#       Uncatchable flow control, and it skips (b) as well, since nothing after it runs at all. Caught in
#       this function's `finally`, which is the only thing that still executes during that unwind.
#   (d) a section that RUNS AND ASSERTS NOTHING - the per-section count comparison at the end of this
#       function. A class rather than a route, and the one (b) can only report as a number.
# Do not reduce this to (b) alone: a pinned total reports "the number changed" where (a), (c) and (d) each
# report which section, and how it went wrong.
function Invoke-CheckSection {
  param([string] $Name, [scriptblock] $Body)
  # The runner prints the heading, so the name in the heading and the name in a failure are the SAME string
  # and cannot drift apart.
  Write-Host $Name
  $before = $script:checks
  $returned = $false
  try { $Body.Invoke(); $returned = $true }
  catch {
    # The InnerException is the one the section actually threw; .Invoke() wraps it in a
    # MethodInvocationException whose own message is about Invoke, not about the bug.
    $err = $_.Exception
    if ($err.InnerException) { $err = $err.InnerException }
    Check "section '$Name' ran to completion" $false "$($err.GetType().Name): $($err.Message)"
    $returned = $true
  }
  finally {
    if (-not $returned) {
      # (c) THE THIRD ROUTE. The body neither returned nor threw, so PowerShell FLOW CONTROL is unwinding
      # the script right now - a bare `break` or `continue` with no enclosing loop. That is not an
      # exception, so the catch above never sees it, and NOTHING after this point runs: not the remaining
      # sections, not Assert-CheckTotal, not the summary. Verified: such a script printed no summary and
      # exited 0.
      # This `finally` is the only thing that still executes during that unwind (verified likewise), which
      # is why the report and the exit code are issued from HERE rather than reported as a failed check -
      # a Check would be counted by a total nothing will ever reach.
      Write-Host "  FAIL  section '$Name' terminated the script without throwing"
      Write-Host '        (a `break` or `continue` with no enclosing loop is flow control, not an error:'
      Write-Host '         it is uncatchable, and everything after it - including the summary - is skipped)'
      exit 1
    }
  }
  # (d) A section that RAN and asserted nothing. Not this route - it is a whole class, and the commonest
  # member is a section whose setup silently produced no cases. Positive, per-section, and it sees things
  # a global total cannot attribute.
  if ($script:checks -eq $before) {
    Check "section '$Name' reported at least one check" $false 'it ran and asserted nothing'
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
