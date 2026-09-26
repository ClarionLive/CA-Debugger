# racebp: a breakpoint two threads run through (ticket ca29e2da)

A hand-coded Clarion 11 app, built with full debug info. `Worker` is STARTed twice, and each calls `Bump`
`Iterations` times, so a breakpoint on `Bump`'s body (`Calls += 1`) must be hit exactly 2 x Iterations times.
The main program waits in an ACCEPT loop on a timer window: a STARTed thread gets its first run from the
starting thread's ACCEPT loop, and the first version, which waited in a plain LOOP, hung with neither worker
ever running (measured 2026-09-25).

The second part of `tools/test-bp-threaded.ps1` copies it to a temp folder, builds it and runs the engine on it
with a tracepoint on that line (a tracepoint never pauses, so every hit takes the silent re-arm route).

## Rebuild

```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe racebp.cwproj /p:ClarionBinPath=C:\Clarion11\bin
```

The Clarion compiler rejects LF line endings, so `.gitattributes` here checks the `.clw` files out as CRLF.
