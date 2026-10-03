# tools/ - the verify set

This repo has no CI. The suites in this folder, together with `ClarionDbg.exe protocolcheck` and the two
builds, are the whole regression net. `run-all.ps1` is the one command that runs it. It DISCOVERS the
suites from a `suite:` header line in each one (`lib-suites.ps1`); there is no hand-kept list.

## Run it

```powershell
pwsh -NoProfile -File tools\run-all.ps1                  # build the engine, protocolcheck, every offline suite
pwsh -NoProfile -File tools\run-all.ps1 -IncludeLive     # ...plus the suites that drive a live debuggee
pwsh -NoProfile -File tools\run-all.ps1 -NoBuild -Only test-addin-hooks.ps1
pwsh -NoProfile -File tools\run-all.ps1 -List            # print the discovered suite list and stop
```

It prints one line per suite (`PASS`, `FAIL`, or `SKIPPED (live)`), shows the tail of any failing
suite's output, and exits non-zero if anything failed. It **fails closed**:

| Condition | Result |
|---|---|
| a suite exits non-zero | FAIL |
| a suite exits 0 but never prints its own success line (a top-level `break` does this) | FAIL |
| a `tools\test-*.ps1` / `tools\test-*.js` with no `suite:` line | FAIL (NO SUITE LINE) |
| a malformed `suite:` line, one past line 40 or below `param()`, or a `success=` not anchored with `^` | FAIL |
| a `.ps1` with a `$SelfTest` parameter but no `args=-SelfTest` line | FAIL |
| fewer entries discovered than `$MinEntries` in `run-all.ps1` (a floor that may only be raised) | FAIL |
| a `.ps1` suite that does not call `Assert-CheckTotal`, with no `nototal=` reason on its line | FAIL |
| a `.ps1` in the repo with non-ASCII bytes and no UTF-8 BOM, other than the `$EncodingPending` list | FAIL |
| a `$EncodingPending` file that no longer needs the exception | FAIL (the list may only shrink) |
| the engine build fails or warns, protocolcheck is missing, `pwsh` or `node` is missing | FAIL |
| a live suite without `-IncludeLive` | `SKIPPED (live)`, printed, never silent |

## Adding a suite

Give the suite **one header line per way it is run**, ASCII, within its first 40 lines and above
`param()` (a `.js` uses `//` for `#`). Until it has one, the runner fails with `NO SUITE LINE`.

```
# suite: live=no
# suite: live=no; args=-SelfTest
# suite: live=yes; args=-WithClarion
# suite: live=no; success='^all \d+ inline script block\(s\) parse OK$'
# suite: live=yes; nototal='reason'
```

`live=yes|no` is required. Optional keys are `args`, `success` (an anchored regex for a success line other
than the default) and `nototal` (`.ps1` only: why it does not pin its total). A value with a space or `;`
is single-quoted. `lib-suites.ps1` holds the grammar, and `test-run-all.ps1` proves each guard on it fails.

A new PowerShell suite should:

1. Dot-source `lib-check.ps1` (or `lib-extract.ps1`, which loads it) and assert with `Check`.
2. Put each block of checks inside `Invoke-CheckSection '<heading>' { ... }`. That is what turns a thrown
   section, **or a top-level `break`** (which is otherwise an exit 0 with no summary), into a failure. Each
   section is its own scope, so a variable a later section reads must be assigned `$script:x = ...`.
3. End with `$EXPECTED_CHECKS = <n>; Assert-CheckTotal $EXPECTED_CHECKS`, then print
   `ALL $($script:checks) CHECKS PASSED` or `$($script:failures) of $($script:checks) CHECKS FAILED` and
   exit 1 on failure. **Counting rule:** `<n>` is the RUNTIME count of `Check` calls on a clean run, not
   the number of lines that say `Check`. A `Check` inside a loop counts once per pass.
4. Be ASCII, or carry a UTF-8 BOM. Windows PowerShell 5.1 reads a BOM-less file as CP1252, so an em-dash
   can break the parse far from where it sits.

## The set

`pwsh -NoProfile -File tools\run-all.ps1 -List` prints it, one line per run variant, read from the suites'
own headers. What each suite guards is in that suite's header comment. A table here was dropped
(2026-10-03, ticket 49538b78): it was a second hand-kept list, and by then it had already fallen behind
the runner's.

**Live** suites launch `clbrws.exe` from the Clarion 11 examples
(`C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses`) under the engine and
post window messages to it, so they need that install and an unattended desktop. On 2026-09-22
`test-bp-threaded.ps1` flaked once (leg 1 under 8 hits): it slept a fixed 5 s per browse open. Since
ticket b3e1ade8 it waits for each open's hits instead (first hit, then 1.5 s quiet, 30 s cap); measured
2026-09-24, three runs took 34-43 s with every open landing 8 hits (one 12). It stays live because it
needs the app, not because it is flaky.

## Builds

- Engine: `dotnet build src\ClarionDbg.Cli\ClarionDbg.Cli.csproj`, which must report 0 warnings. run-all
  does this unless you pass `-NoBuild`.
- Add-in: not run by run-all, because it needs MSBuild from Visual Studio and a Clarion install. Resolve
  MSBuild with vswhere the way `deploy-addin.ps1`'s `Resolve-MSBuild` does, then run
  `msbuild src\ClarionDebugger.Addin\ClarionDebugger.Addin.csproj /t:Build /restore /p:Configuration=Debug /p:ClarionRoot=C:\Clarion12`.
