# Build the CA Debugger installer.
#
# Stages a separately-built addin DLL for each Clarion version (the addin links
# against version-specific IDE assemblies, so one build per version is required),
# stages the version-independent ClarionDbg engine once, then compiles the Inno
# Setup script into installer\output\.
#
# Usage: .\build-installer.ps1 [-Versions 12,11,10] [-Sign]
#
#   -Versions   Which Clarion versions to include (default: all that are installed).
#   -Sign       Authenticode-sign the staged binaries and the finished installer
#               with the Sectigo EV cert (Kennewick Computer Company). Requires the
#               EV dongle plugged in.
#
# Requires: Visual Studio 2022 / MSBuild, Inno Setup 6, and the Clarion install
# root for every version being built (its \bin\ICSharpCode.*.dll are referenced
# at compile time). For -Sign: Windows SDK signtool + the EV dongle.

# There is deliberately no -NoBuild / -SkipBuild switch. The addin is built once per Clarion
# version into the SAME bin\Debug and staged after each pass, so skipping the builds staged
# whichever single DLL happened to be there into all three folders — C10 and C11 would ship a
# C12-linked DLL. Nothing could catch it: every gate here compares VERSIONS, and all three copies
# carried the correct version; only the linked IDE assembly references differed, and versions,
# sizes and hashes are all blind to binding. Re-adding the switch re-opens that hole.
#
# [CmdletBinding()] is load-bearing here, not decoration. Without it PowerShell does not bind
# strictly: an unknown named argument is silently collected into $args and ignored. Someone typing
# -NoBuild out of muscle memory would get no complaint and would reasonably believe the builds had
# been skipped. With it, the flag is a hard error that names itself.
[CmdletBinding()]
param(
    [int[]]$Versions,
    [switch]$Sign
)

# Sectigo EV cert: "Kennewick Computer Company". Target it explicitly by SHA1
# thumbprint — `signtool /a` can silently fall back to another cert (e.g. an
# expired self-signed one) if the EV dongle is unplugged, producing an
# "Unknown Publisher" build. If the cert is reissued, look up the new thumbprint:
#   Get-ChildItem Cert:\CurrentUser\My | Where Subject -like '*Kennewick*' | Select Thumbprint
$SignThumbprint = '85C3D22C215029A9F59EFF775720446F3B12FE3A'
$SignSubject    = 'Kennewick Computer Company'
$TimestampUrl   = 'http://timestamp.sectigo.com'

$ErrorActionPreference = "Stop"
$InstallerDir = $PSScriptRoot
$RepoRoot     = Split-Path -Parent $InstallerDir
$AddinProj    = Join-Path $RepoRoot "src\ClarionDebugger.Addin\ClarionDebugger.Addin.csproj"
$AddinOut     = Join-Path $RepoRoot "src\ClarionDebugger.Addin\bin\Debug"
$EngineProj   = Join-Path $RepoRoot "src\ClarionDbg.Cli\ClarionDbg.Cli.csproj"
$EngineOut    = Join-Path $RepoRoot "src\ClarionDbg.Cli\bin\Debug\net48"
$StageDir     = Join-Path $InstallerDir "staging"
$OutputDir    = Join-Path $InstallerDir "output"
$IssFile      = Join-Path $InstallerDir "CA-Debugger.iss"

# --- The one place the shipped version comes from ---
# CA-Debugger.iss holds no version literal; it is passed to ISCC below as /DMyAppVersion. The
# single source of truth is <Version> in the addin csproj, which the csproj's own
# CheckAddinVersion target already forces to equal ClarionDebugger.addin's <Identity version>.
# That matters because AddinFinder compares the installed manifest's <Identity version> against
# the GitHub release tag minus 'v' — so the csproj version, the manifest, the installer filename
# and the git tag all have to be the same number.
function Get-ProductVersion {
    [xml]$proj = Get-Content $AddinProj -Raw
    $v = @($proj.Project.PropertyGroup.Version) | Where-Object { $_ } | Select-Object -First 1
    if (-not $v) { throw "Could not read <Version> from $AddinProj — the installer has no version to stamp." }
    return "$v".Trim()
}
$ProductVersion = Get-ProductVersion

# Clarion install roots per version (first existing root wins) — mirrors deploy-addin.ps1.
$VersionRoots = @{
    12 = @("C:\Clarion12", "C:\Clarion12d")
    11 = @("D:\Clarion11.1EE", "C:\Clarion11-13372", "C:\Clarion11")
    10 = @("C:\Clarion10", "C:\Clarion10v8")
}

function Resolve-MSBuild {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -requires Microsoft.Component.MSBuild `
                            -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($found -and (Test-Path $found)) { return $found }
    }
    throw "MSBuild.exe not found. Install Visual Studio 2022 with the MSBuild component."
}

function Resolve-ISCC {
    foreach ($p in @("C:\Program Files (x86)\Inno Setup 6\ISCC.exe", "C:\Program Files\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $p) { return $p }
    }
    throw "Inno Setup 6 (ISCC.exe) not found. Install from https://jrsoftware.org/isdl.php"
}

function Get-VersionRoot([int]$ver) {
    return @($VersionRoots[$ver]) | Where-Object { Test-Path (Join-Path $_ "bin\ICSharpCode.Core.dll") } | Select-Object -First 1
}

function Resolve-SignTool {
    $found = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter 'signtool.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*x64*' } |
        Sort-Object { $_.Directory.Parent.Name } -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $found) { throw "signtool.exe not found. Install the Windows 10/11 SDK." }
    return $found
}

# Sign one file with the EV cert. Retries with backoff — the Sectigo timestamp
# server intermittently rejects rapid successive requests, which is transient.
function Sign-File([string]$signtool, [string]$path, [string]$desc) {
    Write-Host "  signing $([IO.Path]::GetFileName($path))..." -ForegroundColor DarkCyan
    $maxAttempts = 5
    for ($i = 1; $i -le $maxAttempts; $i++) {
        $out = & $signtool sign /sha1 $SignThumbprint /fd sha256 /tr $TimestampUrl /td sha256 /d $desc $path 2>&1
        if ($LASTEXITCODE -eq 0) { return }
        if ($i -lt $maxAttempts) {
            Write-Host "    attempt $i failed (likely timestamp rate-limit); retrying..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds (2 * $i)
        } else {
            Write-Host ($out | Out-String) -ForegroundColor Red
            throw "signtool failed for $path after $maxAttempts attempts"
        }
    }
}

$MSBuild = Resolve-MSBuild
$ISCC    = Resolve-ISCC
$SignTool = if ($Sign) { Resolve-SignTool } else { $null }

# Decide which versions to build: requested, or every one with an install root present.
if (-not $Versions) { $Versions = @(12, 11, 10) }
$Build = @()
foreach ($v in $Versions) {
    $root = Get-VersionRoot $v
    if ($root) { $Build += [pscustomobject]@{ Ver = $v; Root = $root } }
    else { Write-Host "SKIP Clarion $v — no install root with IDE assemblies found." -ForegroundColor DarkYellow }
}
if (-not $Build) { throw "No Clarion versions available to build. Need at least one install root." }

Write-Host "=== CA Debugger Installer Build ===" -ForegroundColor Cyan
Write-Host "MSBuild:    $MSBuild"
Write-Host "Inno Setup: $ISCC"
Write-Host "Versions:   $(( $Build | ForEach-Object { $_.Ver }) -join ', ')"
Write-Host "Product:    $ProductVersion (from csproj <Version>; tag the release v$ProductVersion)"
Write-Host ""

# Clean staging.
if (Test-Path $StageDir) { Remove-Item $StageDir -Recurse -Force }
New-Item -ItemType Directory -Path $StageDir | Out-Null

# --- Engine (version-independent) ---
Write-Host "Building ClarionDbg engine..." -ForegroundColor Yellow
& $MSBuild $EngineProj /t:Build /restore /p:Configuration=Debug /v:minimal /nologo
if ($LASTEXITCODE -ne 0) { throw "Engine build failed." }
$EngineStage = Join-Path $StageDir "engine"
New-Item -ItemType Directory -Path $EngineStage | Out-Null
# Iced.dll is the x86 disassembler the engine hard-references for the disassembly view — stage it
# alongside the engine or a deployed `disasm` throws FileNotFoundException and detaches the debuggee.
foreach ($e in @("ClarionDbg.exe", "ClarionDbg.pdb", "ClarionDbg.Core.dll", "ClarionDbg.Core.pdb", "Iced.dll")) {
    Copy-Item (Join-Path $EngineOut $e) (Join-Path $EngineStage $e) -Force
}
Write-Host "  staged engine ($EngineStage)" -ForegroundColor Green

# --- Addin, once per version ---
function Stage-Addin([string]$dest) {
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    foreach ($f in @(
        "ClarionDebugger.dll", "ClarionDebugger.pdb", "ClarionDebugger.addin",
        "Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll", "Microsoft.Web.WebView2.Wpf.dll"
    )) {
        Copy-Item (Join-Path $AddinOut $f) (Join-Path $dest $f) -Force
    }
    # WebView2 native loader: at the addin root and under runtimes\win-x86\native (mirrors deploy-addin.ps1).
    $loader = Join-Path $AddinOut "runtimes\win-x86\native\WebView2Loader.dll"
    Copy-Item $loader (Join-Path $dest "WebView2Loader.dll") -Force
    $nativeDir = Join-Path $dest "runtimes\win-x86\native"
    New-Item -ItemType Directory -Path $nativeDir -Force | Out-Null
    Copy-Item $loader (Join-Path $nativeDir "WebView2Loader.dll") -Force
    # Debugger pad HTML.
    $termDir = Join-Path $dest "Terminal"
    New-Item -ItemType Directory -Path $termDir -Force | Out-Null
    Copy-Item (Join-Path $AddinOut "Terminal\debugger.html") (Join-Path $termDir "debugger.html") -Force
}

foreach ($b in $Build) {
    Write-Host "Building addin for Clarion $($b.Ver) ($($b.Root))..." -ForegroundColor Yellow
    & $MSBuild $AddinProj /t:Rebuild /restore /p:Configuration=Debug /p:ClarionRoot=$($b.Root) /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { throw "Addin build failed for Clarion $($b.Ver)." }
    $dest = Join-Path $StageDir "C$($b.Ver)"
    Stage-Addin $dest
    Write-Host "  staged Clarion $($b.Ver) addin ($dest)" -ForegroundColor Green
}

# --- Staged-manifest version gate ---
# Check the ARTIFACT, not the source. The csproj guard proves csproj-vs-manifest agree in the
# tree; this proves the manifest that actually reached staging — and therefore the installer —
# declares the version we are about to tag.
#
# This is the gate v1.1.0 did not have. That release shipped with staging carrying a manifest
# still declaring 1.0.0 while the .iss said 1.1.0, so every v1.1.0 install reads "Update
# available" in AddinFinder forever and reinstalling cannot clear it. A stale staged copy is
# invisible in the build log without a check like this one.
Write-Host "`nVerifying staged manifests declare $ProductVersion..." -ForegroundColor Yellow
foreach ($b in $Build) {
    $manifest = Join-Path (Join-Path $StageDir "C$($b.Ver)") "ClarionDebugger.addin"
    if (-not (Test-Path $manifest)) { throw "Staged manifest missing for Clarion $($b.Ver): $manifest" }
    [xml]$mx = Get-Content $manifest -Raw
    $staged = "$($mx.AddIn.Manifest.Identity.version)".Trim()
    if ($staged -ne $ProductVersion) {
        throw ("Staged Clarion $($b.Ver) manifest declares <Identity version=`"$staged`"> but this build is $ProductVersion. " +
               "Shipping this would leave every install stuck on 'Update available' in AddinFinder. " +
               "Rebuild so the manifest is re-copied from source.")
    }
    # The pad caption is stamped separately from <Identity version> and carries the build number,
    # so it can drift on its own axis: a skipped restamp ships a caption a build behind the DLL.
    # That actually happened during development (FileVersion 1.1.1.132 vs caption v1.1.1.131), and
    # nothing else would have caught it — Identity was correct the whole time.
    $padTitle = "$($mx.AddIn.Path | Where-Object { $_.name -eq '/SharpDevelop/Workbench/Pads' } |
                   ForEach-Object { $_.Pad.title })".Trim()
    $dll = Join-Path (Join-Path $StageDir "C$($b.Ver)") "ClarionDebugger.dll"
    $fileVer = (Get-Item $dll).VersionInfo.FileVersion.Trim()
    $expectedTitle = "CA Debugger v$fileVer"
    if ($padTitle -ne $expectedTitle) {
        throw ("Staged Clarion $($b.Ver) pad caption is '$padTitle' but the staged DLL is FileVersion " +
               "$fileVer (expected caption '$expectedTitle'). The manifest was not restamped for this " +
               "build — the shipped caption would show the wrong build number.")
    }
    Write-Host "  C$($b.Ver): identity $staged, caption '$padTitle' OK" -ForegroundColor Green
}

# --- Sign staged binaries (before they are compressed into the installer) ---
if ($Sign) {
    Write-Host "`nSigning staged binaries..." -ForegroundColor Yellow
    Sign-File $SignTool (Join-Path $EngineStage "ClarionDbg.exe") "CA Debugger Engine"
    Sign-File $SignTool (Join-Path $EngineStage "ClarionDbg.Core.dll") "CA Debugger Engine"
    foreach ($b in $Build) {
        Sign-File $SignTool (Join-Path (Join-Path $StageDir "C$($b.Ver)") "ClarionDebugger.dll") "CA Debugger Addin"
    }
}

# --- Compile installer ---
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
Write-Host "`nCompiling installer..." -ForegroundColor Yellow
& $ISCC "/DMyAppVersion=$ProductVersion" $IssFile
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }

$exe = Get-ChildItem $OutputDir -Filter "*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# --- Sign the installer itself, then verify the signer is the expected cert ---
if ($Sign -and $exe) {
    Write-Host "`nSigning installer..." -ForegroundColor Yellow
    Sign-File $SignTool $exe.FullName "CA Debugger Installer"

    # Confirm the signature came from the EV cert (not a stale fallback). Don't use
    # `signtool verify /pa` — its machine root store can lack the chain and report
    # false negatives. Check the signer subject instead.
    $sig = Get-AuthenticodeSignature $exe.FullName
    if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -like "*$SignSubject*") {
        Write-Host "  OK (signed by $($sig.SignerCertificate.Subject.Split(',')[0]))" -ForegroundColor Green
    } else {
        $actual = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(no signer cert)' }
        throw "Installer signed with WRONG certificate: $actual. Expected '$SignSubject'. Plug in the Sectigo EV dongle and rebuild."
    }
}

Write-Host "`n=== Build Complete ===" -ForegroundColor Green
if ($exe) {
    Write-Host "Installer: $($exe.FullName)"
    Write-Host "Size: $([math]::Round($exe.Length / 1MB, 2)) MB"
    if ($Sign) { Write-Host "Signed:    yes (Kennewick Computer Company)" -ForegroundColor Green }
}
