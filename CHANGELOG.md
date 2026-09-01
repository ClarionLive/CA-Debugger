# Changelog

All notable changes to CA Debugger are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## v1.2.0 — 2026-09-01

The debugger panel now tells you what it's pointed at and keeps up with the IDE
on its own, instead of waiting to be refreshed.

### Added

- **Target bar.** The resolved target EXE is shown in the panel, full path,
  always visible — click it to reveal the file in Explorer. It previously
  appeared only in the Debug Console, which is a section you can hide, so with it
  collapsed there was no way to see what was about to be launched.
- **Live solution tracking.** Open a project and the target and Procedures list
  populate on their own; close the solution and they clear. Previously the panel
  resolved these only when it first opened or when you pressed ↻, so a solution
  opened afterwards left it looking empty indefinitely.
- **About panel**, on the ⓘ button — version, publisher, debug engine and
  WebView2 runtime.
- **Documentation button**, opening the user guide (the installed copy if you
  have it, otherwise the published one).
- **Version in the pad caption** — the docked tab reads `CA Debugger v1.2.0.<build>`,
  where the build number is the commit the build came from.

### Fixed

- **Messages sent to the panel as it started up were silently discarded.** The
  page announces itself while it is still loading, but the host treated it as not
  yet ready and dropped everything it sent back — the initial run state, the
  About details, and the auto-detected target message. They are now held and
  delivered once the panel is live.
- **Duplicate console lines** when a project opened: the target was announced on
  every IDE event, whether or not it had changed.
- The panel's initialization-failure message advised reopening the pad, which
  could never have worked — closing a pad only hides it, so reopening reuses the
  same instance. It now says to restart the IDE.

### Changed

- The panel header shows the product name larger and in colour, without
  repeating the version already in the tab caption.

### Requirements

- Clarion 10, 11, or 12 (32-bit).
- Microsoft Edge WebView2 Runtime (for the debugger pad UI).
- The target application must be compiled with **Full** debug information.

### Install

Download `CA-Debugger-1.2.0-Setup.exe` from the release assets and run it (close
the Clarion IDE first). See the [User Guide](https://htmlpreview.github.io/?https://github.com/ClarionLive/CA-Debugger/blob/main/docs/user-guide.html) for usage.

## v1.1.1 — 2026-08-31

A patch release: stepping and breakpoint fixes contributed by the community, plus
a versioning fix that matters for anyone installing through AddinFinder.

### Fixed

- **"Update available" showed forever in AddinFinder.** The addin manifest shipped
  in v1.1.0 still declared version `1.0.0` while the release was tagged `v1.1.0`.
  AddinFinder compares the installed manifest's version against the release tag,
  so every v1.1.0 install reported an update that reinstalling could never clear.
  All version numbers now come from one source and are checked at build time, so
  the release tag and the shipped manifest cannot drift apart again.
- **Step Out** no longer stops mid-epilogue on a procedure's own `RETURN` record.
  Thanks to [@geircodes](https://github.com/geircodes) (#22).
- **Step Over** no longer runs past a procedure's own prologue.
  Thanks to [@geircodes](https://github.com/geircodes) (#25).
- **Removing a breakpoint while the target is running** no longer resurrects it on
  the next debug session. Thanks to [@geircodes](https://github.com/geircodes) (#23).
- **Unnamed `GROUP` members and the `_main` symbol** are now recovered from TSWD
  debug info, so they resolve by name instead of appearing blank.
  Thanks to [@geircodes](https://github.com/geircodes) (issues #19, #21).
- **Locals and frame names** resolve correctly when a symbol's `moduleIdx` space
  diverges from the module table. Thanks to
  [@msarson](https://github.com/msarson) (#17).

### Changed

- **Run to cursor** now reads the live cursor position from the active Monaco
  editor rather than the debugger's own Source panel, so it follows where you are
  actually looking. Based on a spike by
  [@geircodes](https://github.com/geircodes) (#24).
- `deploy-addin.ps1` again finds Clarion installs on `C:` alongside `D:` paths.

### Requirements

- Clarion 10, 11, or 12 (32-bit).
- Microsoft Edge WebView2 Runtime (for the debugger pad UI).
- The target application must be compiled with **Full** debug information.

### Install

Download `CA-Debugger-1.1.1-Setup.exe` from the release assets and run it (close
the Clarion IDE first). See the [User Guide](https://htmlpreview.github.io/?https://github.com/ClarionLive/CA-Debugger/blob/main/docs/user-guide.html) for usage.

## v1.1.0 — 2026-06-16

A large feature release focused on the debugging experience — richer breakpoints,
live value editing, faster navigation, and a more flexible layout — on top of the
same proven 32-bit engine + WebView2 front-end.

### Added

- **Advanced breakpoints** — give any breakpoint a **condition** (break only when
  an expression is true), a **hit-count rule** (break on the Nth hit, every Nth, or
  when hits ≥ N), or turn it into a **tracepoint** (log an interpolated `{var}`
  message and keep running — never pauses). Edited from the Breakpoints pane.
- **Run to cursor** — while paused, right-click a line in the debugger's Source
  panel to resume and stop there. It plants a one-shot breakpoint that removes
  itself automatically and leaves nothing behind in the Breakpoints pane.
- **Break on procedure entry** — right-click a row in the new Procedures pane to
  drop a breakpoint at that procedure's definition line.
- **Edit variable values** — type a new value into a variable's value cell (in the
  Variables tree or Watch) to write it into the live process.
- **Procedures pane** — a filterable, clickable list of every procedure/method in
  the target; click to jump to its `.clw` definition.
- **Disassembly view** — a gated x86 disassembly of the current location, with
  **instruction-level stepping** (step one instruction, into or over calls).
- **Filter & sort** — per-pane filter boxes and a name sort on the Variables and
  Call Stack panes.
- **DATE / TIME view-as** — render a Clarion `LONG` holding a Standard Date or Time
  as a formatted date/time instead of the raw number.
- **Variables tree overhaul** — call-stack-frame-scoped locals (frame-aware
  Procedure Data / Method Data), array elements, and lazy on-demand expansion of
  by-reference structures (GROUP / CLASS / QUEUE), plus module-scope data.
- **Rearrangeable layout** — a two-column workspace; drag to reorder, collapse, or
  hide sections, with your arrangement remembered.
- **Pause / break-into** a running target, and **multi-DLL** debugging —
  breakpoints, hits, and stack frames resolve correctly across DLL boundaries.
- **Debug Console** copy / clear actions.

### Changed

- Pause/step navigation is **Monaco-aware** — when the ClarionAssistant Monaco
  overlay is active, the editor scrolls to and highlights the current line.
- Call stack is walked via the **EBP chain** (with at-entry caller and
  monotonic-frame guards), replacing the older over-inclusive stack scan.

### Fixed

- **Step Over** no longer skips a line that immediately follows a procedure call.
- Breakpoint and call-stack clicks navigate reliably to the target line (including
  under the Monaco overlay).
- Removing one of several gutter lines that snapped to the same code line no longer
  leaves the shared breakpoint planted and firing (ref-counted INT3).

### Requirements

- Clarion 10, 11, or 12 (32-bit).
- Microsoft Edge WebView2 Runtime (for the debugger pad UI).
- The target application must be compiled with **Full** debug information.

### Install

Download `CA-Debugger-1.1.0-Setup.exe` from the release assets and run it (close
the Clarion IDE first). See the [User Guide](https://htmlpreview.github.io/?https://github.com/ClarionLive/CA-Debugger/blob/main/docs/user-guide.html) for usage.

## v1.0.1 — 2026-06-10

First public release of CA Debugger — a modern, source-level debugger addin for
the Clarion IDE (Clarion 10, 11, and 12). It plugs into the IDE's existing
breakpoint/jump-to-line plumbing and supplies its own 32-bit debug engine plus a
clean WebView2 front-end.

### Highlights

- **Source-level debugging** — set breakpoints in the Clarion editor gutter,
  Start/Continue/Step Over/Step Into/Step Out/Stop, with a live current-line bar.
- **Real call stack** with procedure names and `module : line`; click a frame to
  jump to it.
- **Watch by name** — type-ahead add, ★-pin from the Variables tree, right-click
  multi-add, and hover data-tips that show value/type with pin & copy actions.
- **Variables tree** — file record buffers (Tables) and Global Variables, with
  live values resolved while visible.
- **Registers** view while paused.

### Added

- **Auto-resolve Target EXE** from the IDE's active project (reads the project's
  output type/name), so the field is usually pre-filled.
- **Settings popup with configurable debug shortcut keys.** Debug commands ship
  unbound (the IDE claims F5/F10/F11); bind your own combinations via the gear
  menu. Bindings persist locally.
- **Inno Setup installer** — picks up Clarion 10/11/12 automatically and lets you
  choose which version(s) to install into.

### Changed

- Focus returns to the debugger pad after stepping, so configured step shortcuts
  keep working in a loop.

### Fixed

- **Light theme readability.** Variable names, the primary **Start** button,
  record fields, and the **TARGET EXE** label were hardcoded to light colors that
  were unreadable on the light background. They now use theme-aware colors
  (a darker blue for identifiers, near-black for fields, off-white for the
  exebar label).

### Requirements

- Clarion 10, 11, or 12 (32-bit).
- Microsoft Edge WebView2 Runtime (for the debugger pad UI).
- The target application must be compiled with **Full** debug information.

### Install

Download `CA-Debugger-1.0.1-Setup.exe` from the release assets and run it (close
the Clarion IDE first). See the [User Guide](https://htmlpreview.github.io/?https://github.com/ClarionLive/CA-Debugger/blob/main/docs/user-guide.html) for usage.
