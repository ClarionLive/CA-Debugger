# Regression check: which FILE a breakpoint row means, when two loaded DLLs each hold a .clw of that name.
#
# A breakpoint is named on the wire by a bare .clw BASENAME. In a multi-DLL app two images can each carry a
# clbrws011.clw, and if both are bookmarked at the same line the host has two files and one name. Two things
# then went wrong, both silently, and neither reachable from the engine-side suites:
#
#   - SendBps built its (module|line) -> path map with a plain assignment, so the SECOND gutter bookmark
#     overwrote the first. A pane row could carry the OTHER file's path, and clicking the filename opened
#     the wrong source. OpenBp's File.Exists cannot catch that: both files exist.
#   - RemoveByModuleLine removed the FIRST bookmark whose module/line matched, so the pane's "x" on one
#     breakpoint could clear the other file's red dot.
#
# Task e80072f1. This compiles the REAL ClaimGutterPath / GutterPathFor out of ClarionDebuggerWebView.cs and
# the REAL RemoveByModuleLine / TryMap out of EditorBreakpointService.cs - extracted by brace matching, the
# same trick tools/test-addin-json.ps1 and tools/test-addin-bpremove.ps1 use - against stub collaborators,
# so what is under test is the shipped code and not a paraphrase of it. The breakpoint record is the
# shipped one too, lifted out of ClarionDebuggerService.cs.
#
#   pwsh tools/test-addin-bpident.ps1
# Exit code 0 = all checks passed.

param(
  [string] $WebViewPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Terminal\ClarionDebuggerWebView.cs'),
  [string] $EditorBpPath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\EditorBreakpointService.cs'),
  [string] $ServicePath = (Join-Path $PSScriptRoot '..\src\ClarionDebugger.Addin\Services\ClarionDebuggerService.cs')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib-extract.ps1')
$web = Get-Content -Raw -LiteralPath $WebViewPath
$edt = Get-Content -Raw -LiteralPath $EditorBpPath
$svc = Get-Content -Raw -LiteralPath $ServicePath

# Get-Method / Check / ShowVal live in lib-extract.ps1 (dot-sourced above).
#
# No Set-ExtractSource here, unlike the other three harnesses: every extraction below names its source
# explicitly ($web / $edt / $svc, three different files), so a default would be a line nothing reads. It was
# added and then removed after mutation-testing showed it dead - pointing it at the wrong file left this
# suite green, which is the same evidence that proves the other three need theirs. If a bare Get-Method ever
# appears here it fails loudly with "no default extraction source for this harness", which says what to do.

$mapMethods = @(
  (Get-Method 'private static void ClaimGutterPath(Dictionary<string, string> paths, string key, string path)' $web),
  (Get-Method 'private static string GutterPathFor(Dictionary<string, string> paths, DebugBreakpoint b)' $web)
) -join "`n"

$gutterMethods = @(
  (Get-Method 'public bool RemoveByModuleLine(string module, int line, string filePath)' $edt),
  (Get-Method 'private static bool TryMap(BreakpointBookmark bb, out string module, out int line)' $edt)
) -join "`n"

$shim = @"
using System;
using System.Collections.Generic;
using System.IO;

$(Get-Method 'public sealed class DebugBreakpoint' $svc)

// ---- the IDE collaborators, stubbed. The stub NAMES are the real ones so both extracted bodies compile
// verbatim, with nothing rewritten but the access modifier.
public class BreakpointBookmark { public string FileName; public int LineNumber; public object Document; }

public static class DebuggerService {
    public static List<BreakpointBookmark> Breakpoints = new List<BreakpointBookmark>();
    public static List<string> Toggled = new List<string>();   // what the IDE was asked to un-bookmark
    public static void ToggleBreakpointAt(object doc, string file, int line) { Toggled.Add(file + "|" + line); }
}

namespace ICSharpCode.SharpDevelop.Bookmarks {
    public static class BookmarkManager {
        public static List<string> Removed = new List<string>();
        public static void RemoveMark(global::BreakpointBookmark bb) { Removed.Add(bb.FileName + "|" + bb.LineNumber); }
    }
}

public static class BpMap {
$($mapMethods -replace 'private static', 'public static')
}

public class GutterProbe {
$($gutterMethods -replace 'public bool RemoveByModuleLine', 'public bool RemoveByModuleLine' -replace 'private static bool TryMap', 'public static bool TryMap')
}
"@

Add-Type -TypeDefinition $shim -Language CSharp | Out-Null


# The case throughout: one .clw basename, two DLLs, both bookmarked at line 50.
$dll1Clw = 'H:\App\Dll1\clbrws011.clw'
$dll2Clw = 'H:\App\Dll2\clbrws011.clw'
$module = 'clbrws011.clw'
$line = 50

function New-Bp { param($mod, $req, $planted, $path)
  $b = New-Object DebugBreakpoint
  $b.Module = $mod; $b.RequestedLine = $req; $b.Line = $planted; $b.Path = $path
  $b
}
function New-Map { New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase) }
function Claim { param($map, $path, $req, $planted)
  # what GutterPathsByModuleLine does per bookmark: claim under both of the entry's lines
  [BpMap]::ClaimGutterPath($map, "$module|$planted", $path)
  [BpMap]::ClaimGutterPath($map, "$module|$req", $path)
}

Write-Host 'one bookmark: the map still hands back its exact path'
# CONTROL. Everything below turns on a path becoming unavailable, and a suite where the map never produced
# one would pass all of it while click-to-open was simply broken.
$solo = New-Map
Claim $solo $dll1Clw $line $line
$soloPath = [BpMap]::GutterPathFor($solo, (New-Bp $module $line $line $null))
Check 'a lone gutter bookmark resolves to its own file' ($soloPath -eq $dll1Clw) (ShowVal $soloPath)

Write-Host ''
Write-Host 'two DLLs at one module|line: the map refuses to guess instead of handing back the last writer'
$both = New-Map
Claim $both $dll1Clw $line $line
Claim $both $dll2Clw $line $line
$ambig = [BpMap]::GutterPathFor($both, (New-Bp $module $line $line $null))
# The defect was that this answered $dll2Clw - the second writer - with nothing to say it had guessed.
Check 'a contested module|line resolves to NO path, not to the second bookmark' ($null -eq $ambig) (ShowVal $ambig)
Check 'and specifically not to either of the two candidates' `
  (($ambig -ne $dll1Clw) -and ($ambig -ne $dll2Clw)) (ShowVal $ambig)
# A row with no path falls back to the page's `jump` action and the .red resolution behind it. That is a
# best effort that ADMITS it is one, which is the whole difference from opening the wrong file confidently.

Write-Host ''
Write-Host 'the poisoning is order-independent and cannot be undone by a later claim'
$reverse = New-Map
Claim $reverse $dll2Clw $line $line
Claim $reverse $dll1Clw $line $line
Check 'claiming in the other order gives the same refusal' ($null -eq [BpMap]::GutterPathFor($reverse, (New-Bp $module $line $line $null))) ''
$third = New-Map
Claim $third $dll1Clw $line $line
Claim $third $dll2Clw $line $line
Claim $third $dll1Clw $line $line
Check 'and a third claim from the first file does not un-poison the key' `
  ($null -eq [BpMap]::GutterPathFor($third, (New-Bp $module $line $line $null))) ''
# ISOLATION: the same file claiming the same key twice is ordinary, not a collision. A guard that poisoned
# on any repeat claim would pass every check above and break click-to-open for every single breakpoint,
# because GutterPathsByModuleLine claims each bookmark under both its lines and they are usually equal.
$twice = New-Map
Claim $twice $dll1Clw $line $line
Claim $twice $dll1Clw $line $line
Check 'the SAME file claiming its key twice is not a collision' `
  ([BpMap]::GutterPathFor($twice, (New-Bp $module $line $line $null)) -eq $dll1Clw) `
  (ShowVal ([BpMap]::GutterPathFor($twice, (New-Bp $module $line $line $null))))
# ...and a row whose PLANTED line is contested may still have an uncontested requested line. 40 and 41 both
# snapped to 50 in Dll1; only 50 is contested, so the row requested at 40 still knows its file.
$mixed = New-Map
Claim $mixed $dll1Clw 40 50
Claim $mixed $dll2Clw 50 50
$viaRequested = [BpMap]::GutterPathFor($mixed, (New-Bp $module 40 50 $null))
Check 'a contested planted line still resolves through an uncontested requested line' ($viaRequested -eq $dll1Clw) (ShowVal $viaRequested)

Write-Host ''
Write-Host 'a row that knows its own file always opens THAT file - which is how the link stays right'
# _pending entries merged from _gutter.Snapshot() carry Path = the bookmark's own FileName. So even with the
# module|line key contested, each of the two rows resolves to its own source and the filename link opens the
# right file. This is the positive half of the test bar; the refusal above is what happens when there is no
# such path to fall back on.
$rowD1 = New-Bp $module $line $line $dll1Clw
$rowD2 = New-Bp $module $line $line $dll2Clw
Check 'the Dll1 row opens the Dll1 file' ([BpMap]::GutterPathFor($both, $rowD1) -eq $dll1Clw) (ShowVal ([BpMap]::GutterPathFor($both, $rowD1)))
Check 'the Dll2 row opens the Dll2 file' ([BpMap]::GutterPathFor($both, $rowD2) -eq $dll2Clw) (ShowVal ([BpMap]::GutterPathFor($both, $rowD2)))
Check 'and the two rows do not resolve to the same file' `
  ([BpMap]::GutterPathFor($both, $rowD1) -ne [BpMap]::GutterPathFor($both, $rowD2)) ''

# ---------------------------------------------------------------- the removal half
function Reset-Gutter {
  param([string[]] $Files, [int] $Line)
  [DebuggerService]::Breakpoints.Clear()
  [DebuggerService]::Toggled.Clear()
  [ICSharpCode.SharpDevelop.Bookmarks.BookmarkManager]::Removed.Clear()
  foreach ($f in $Files) {
    $bb = New-Object BreakpointBookmark
    $bb.FileName = $f
    $bb.LineNumber = $Line - 1     # ICSharpCode bookmarks are 0-based; TryMap adds the 1
    $bb.Document = New-Object Object
    [DebuggerService]::Breakpoints.Add($bb)
  }
}
$probe = New-Object GutterProbe
# Every CALLER wraps this in @(): PowerShell unrolls a single-element pipeline output to a scalar, and a
# scalar string answers .Length where the checks below ask for .Count.
function Cleared { @([DebuggerService]::Toggled) + @([ICSharpCode.SharpDevelop.Bookmarks.BookmarkManager]::Removed) }

Write-Host ''
Write-Host 'the pane "x" clears the bookmark in the file the row means, not the first one enumerated'
Reset-Gutter @($dll1Clw, $dll2Clw) $line
$ok = $probe.RemoveByModuleLine($module, $line, $dll2Clw)
$cleared = @(Cleared)
# The defect: the loop took the FIRST module/line match, which is Dll1 here whatever the user clicked.
Check 'naming the Dll2 file removes the Dll2 bookmark' ($ok -and $cleared.Count -eq 1 -and $cleared[0] -eq "$dll2Clw|$($line - 1)") (($cleared -join ', '))
Check 'and leaves the Dll1 bookmark alone' ($cleared -notcontains "$dll1Clw|$($line - 1)") (($cleared -join ', '))
# ...and the other way round, so the result is not an artefact of enumeration order agreeing with us once.
Reset-Gutter @($dll1Clw, $dll2Clw) $line
$ok = $probe.RemoveByModuleLine($module, $line, $dll1Clw)
$cleared = @(Cleared)
Check 'naming the Dll1 file removes the Dll1 bookmark instead' ($ok -and $cleared.Count -eq 1 -and $cleared[0] -eq "$dll1Clw|$($line - 1)") (($cleared -join ', '))

Write-Host ''
Write-Host 'with no file named, it removes a lone bookmark and DECLINES an ambiguous one'
# One candidate cannot be the wrong one, so the old behaviour is kept exactly where it was never a guess.
Reset-Gutter @($dll1Clw) $line
$ok = $probe.RemoveByModuleLine($module, $line, $null)
Check 'a single bookmark is still removed when no file is named' ($ok -and @(Cleared).Count -eq 1) (@(Cleared) -join ', ')
# Two candidates and nothing to choose between them: clearing one is a coin toss whose losing side takes a
# dot the user still wants. Returning false hands RemoveBp its existing fallback, which keeps the pane and
# the engine consistent without touching the gutter at all.
Reset-Gutter @($dll1Clw, $dll2Clw) $line
$ok = $probe.RemoveByModuleLine($module, $line, $null)
Check 'two candidates and no file named: it reports failure' (-not $ok) ''
Check 'and clears NEITHER dot rather than guessing' (@(Cleared).Count -eq 0) (@(Cleared) -join ', ')
# ISOLATION: declining must be about the AMBIGUITY, not about the caller having named nothing. Same two
# bookmarks, a file named, and it removes - so the refusal above is the count and not the null path.
Reset-Gutter @($dll1Clw, $dll2Clw) $line
Check 'the same two bookmarks WITH a file named are removable, so the refusal is the ambiguity' `
  ($probe.RemoveByModuleLine($module, $line, $dll2Clw)) ''

Write-Host ''
Write-Host 'a named file nobody has falls back to the lone bookmark, and never to an arbitrary one'
Reset-Gutter @($dll1Clw) $line
Check 'one candidate, a stale path named: still removed' ($probe.RemoveByModuleLine($module, $line, 'H:\Gone\clbrws011.clw')) ''
Reset-Gutter @($dll1Clw, $dll2Clw) $line
Check 'two candidates, a stale path named: declined' (-not $probe.RemoveByModuleLine($module, $line, 'H:\Gone\clbrws011.clw')) ''

Write-Host ''
Write-Host 'and the pane, its link and its "x" read the file through the SAME resolution'
# PaneBpPath is an instance method over _svc/_pending and is not compiled here; what is checked is that it
# is the one thing RemoveBp consults, and that it uses the same two helpers SendBps builds the rows with.
# A second, separately-written resolution is how the link and the "x" come to disagree about a row.
$removeBp = Get-Method 'private void RemoveBp(string data)' $web
Check 'RemoveBp passes a resolved file to the gutter rather than only module:line' `
  ($removeBp -match 'RemoveByModuleLine\(module, line, PaneBpPath\(module, line\)\)') ''
$paneBpPath = Get-Method 'private string PaneBpPath(string module, int line)' $web
Check 'PaneBpPath resolves through the same map SendBps builds its rows from' `
  (($paneBpPath -match 'GutterPathsByModuleLine\(\)') -and ($paneBpPath -match 'GutterPathFor\(')) ''
$sendBps = Get-Method 'private void SendBps()' $web
Check 'and SendBps builds the rows through those same two, with no map of its own' `
  (($sendBps -match 'GutterPathsByModuleLine\(\)') -and ($sendBps -match 'GutterPathFor\(') -and ($sendBps -notmatch 'new Dictionary<string, string>')) ''
# The old one-line overwrite must be gone, not merely bypassed: it is three characters from coming back.
Check 'the silent last-writer-wins assignment is gone from the pad' `
  ($web -notmatch 'paths\[g\.Module \+ "\|" \+ g\.Line\] = g\.Path') ''
# The 2-argument overload is kept for callers with nothing better to offer, and must route to the same body
# rather than keep the old first-match loop alive beside it.
$legacyOverload = Get-Method 'public bool RemoveByModuleLine(string module, int line)' $edt
Check 'the 2-argument overload delegates instead of keeping a second matcher' `
  ($legacyOverload -match 'RemoveByModuleLine\(module, line, null\)') ''

Write-Host ''
if ($script:failures) { Write-Host "$($script:failures) FAILURE(S)"; exit 1 }
Write-Host 'ALL CHECKS PASSED'
exit 0
