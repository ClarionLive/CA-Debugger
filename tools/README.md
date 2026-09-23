# tools/ - the verify set

This repo has no CI. The suites in this folder, together with `ClarionDbg.exe protocolcheck` and the two
builds, are the whole regression net. `run-all.ps1` is the one command that runs it, and its `$Suites`
table is the canonical list.

## Run it

```powershell
pwsh -NoProfile -File tools\run-all.ps1                  # build the engine, protocolcheck, every offline suite
pwsh -NoProfile -File tools\run-all.ps1 -IncludeLive     # ...plus the suites that drive a live debuggee
pwsh -NoProfile -File tools\run-all.ps1 -NoBuild -Only test-addin-hooks.ps1
```

It prints one line per suite (`PASS`, `FAIL`, or `SKIPPED (live)`), shows the tail of any failing
suite's output, and exits non-zero if anything failed. It **fails closed**:

| Condition | Result |
|---|---|
| a suite exits non-zero | FAIL |
| a suite exits 0 but never prints its own success line (a top-level `break` does this) | FAIL |
| a `tools\test-*.ps1` / `tools\test-*.js` on disk that is not in `$Suites` | FAIL (UNLISTED) |
| a `$Suites` entry whose file is gone | FAIL |
| a listed `.ps1` suite that does not call `Assert-CheckTotal`, with no `NoTotal` reason in its entry | FAIL |
| a `.ps1` in the repo with non-ASCII bytes and no UTF-8 BOM, other than the `$EncodingPending` list | FAIL |
| a `$EncodingPending` file that no longer needs the exception | FAIL (the list may only shrink) |
| the engine build fails or warns, protocolcheck is missing, `pwsh` or `node` is missing | FAIL |
| a live suite without `-IncludeLive` | `SKIPPED (live)`, printed, never silent |

## Adding a suite

Add **one line** to `$Suites` in `run-all.ps1`, for example `@{ File = 'test-disasm-seat.ps1' }`. Until
you do, the runner fails with `UNLISTED`. Optional fields are `Args`, `Live = $true`, `Success` (a regex
for a success line other than the default) and `NoTotal` (the reason a `.ps1` does not pin its total).

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

As of 2026-09-22. The list in `run-all.ps1` is authoritative. This table only explains it.

| Suite | Kind | What it guards |
|---|---|---|
| `protocolcheck` (engine binary) | engine | the wire protocol builders, one claim per check |
| `test-addin-bpident.ps1` | offline | which file a breakpoint row means when two DLLs share a `.clw` name |
| `test-addin-bpremove.ps1` | offline | the pad's staging list is trimmed only when the engine took the removal |
| `test-addin-hooks.ps1` | offline | the reflection hooks into ClarionAssistant, one child process per scenario |
| `test-addin-json.ps1` | offline | the add-in's JSON reader and writer |
| `test-addin-attach.ps1` (plain and `-SelfTest`) | offline | attach host side (3f2d747f): only a host-listed pid is attached, Stop sends `detach` (not `quit`) and waits 8 s, the `detached` event resets the pad; `-SelfTest` breaks each guard (23 mutations) and requires red |
| `test-engine-bpowner.ps1` | offline | breakpoint ownership across images (not yet total-pinned: ticket 6493d226) |
| `test-engine-session.ps1` | offline | the shared engine-session lifecycle, and that harnesses use it |
| `test-engine-tid-members.ps1` (plain and `-SelfTest`) | offline | no thread-id JSON member written by hand; thread ids to users go through TidText |
| `test-engine-hover-sites.ps1` (plain and `-SelfTest`) | offline | PausedWait resets the hover tracker as an unconditional top-level statement before its command loop (position, not text) |
| `test-pad-*.js` | offline (node) | the debugger pad page |
| `test-bp-threaded.ps1` | **live** | a tracepoint over a THREADed name, hit repeatedly without pausing |
| `test-watch-threaded.ps1` | **live** | a watch reads a THREADed name from its instance, not a HISTORY:: copy |
| `test-interactive.ps1` | **live** | step / stepover / stepout from a startup breakpoint |
| `test-engine-setip-sites.ps1` (plain and `-SelfTest`) | offline | every resume cuts setip's observations back as ArmResume's first statement, and every step trap records its ESP (position, not text) |
| `test-setip.ps1` | **live** | set next statement on SplashScreen: back via `observed`, forward refused (stack-unproven), both breakpoints still fire around a setip, Step starts from the new line, nothing observed survives a continue or a step-out, and the ACCEPT-boundary, prologue, routine and Pause-stop refusals |

**Live** suites launch `clbrws.exe` from the Clarion 11 examples
(`C:\Users\Public\Documents\SoftVelocity\Clarion11\Examples\HowToClarion\Browses`) under the engine and
post window messages to it, so they need that install and an unattended desktop. On 2026-09-22
`test-bp-threaded.ps1` took about 55 s and flaked once (leg 1 under 8 hits, ticket b3e1ade8), which is why
it is not in the default set.

## Builds

- Engine: `dotnet build src\ClarionDbg.Cli\ClarionDbg.Cli.csproj`, which must report 0 warnings. run-all
  does this unless you pass `-NoBuild`.
- Add-in: not run by run-all, because it needs MSBuild from Visual Studio and a Clarion install. Resolve
  MSBuild with vswhere the way `deploy-addin.ps1`'s `Resolve-MSBuild` does, then run
  `msbuild src\ClarionDebugger.Addin\ClarionDebugger.Addin.csproj /t:Build /restore /p:Configuration=Debug /p:ClarionRoot=C:\Clarion12`.
