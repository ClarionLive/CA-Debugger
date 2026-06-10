# Changelog

All notable changes to CA Debugger are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
