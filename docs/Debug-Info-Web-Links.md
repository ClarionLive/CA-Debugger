# Debug-Info Web Links

A running collection of web references on executable debug information — its on-disk
formats, how compilers/linkers generate it, and how debuggers match symbols back to a
module. Seeded from [issue #13](https://github.com/ClarionLive/CA-Debugger/issues/13)
(@CarlTBarnes). Add links as we find them, and leave a one-line note on each — it saves
the next person a click.

See also our own **[TSWD-format.md](TSWD-format.md)** — the decoded Clarion / TopSpeed
debug format this project parses. It is a *custom* format (**not** CodeView/PDB), but it
is reached through the standard PE Debug Directory the links below describe.

## debuginfo.com (Oleg Starodumov)

In-depth articles on Windows debugging, symbols, and crash dumps.

- [Articles index](https://www.debuginfo.com/articles.html) — the full article list
  (symbols, minidumps, PDB handling, post-mortem debugging). Good jumping-off point.
- [Matching debug information](https://www.debuginfo.com/articles/debuginfomatch.html) —
  how a debugger decides whether a symbol/debug file actually matches a loaded module
  (signature, age/GUID, timestamp). Relevant to any "are these the right symbols for this
  build?" check.
- [Generating debug information](https://www.debuginfo.com/articles/gendebuginfo.html) —
  how the Visual C++ toolchain emits debug info (`/Zi`, `/DEBUG`, PDB vs. embedded), and
  what ends up where. Useful context for how non-Clarion modules in a process carry
  their symbols.

## Microsoft Learn — PE format & debug directory

The standard PE container our TSWD blob is referenced from (PE Data Directory **index 6**,
the Debug Directory).

- [IMAGE_DEBUG_DIRECTORY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_debug_directory)
  — the 28-byte debug-directory entry struct (`Type`, `SizeOfData`, `PointerToRawData`,
  …). Clarion's TSWD blob is pointed to by one of these, with a custom `Type` code
  `0x44575354` (ASCII `TSWD`). See TSWD-format.md → "Locating the blob".
- [PE Format — the debug section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-debug-section)
  — the PE/COFF specification's treatment of the debug directory and the documented
  `IMAGE_DEBUG_TYPE_*` codes (CodeView/PDB, etc.). Our `TSWD` type is not among them,
  which is why no off-the-shelf parser reads it.
