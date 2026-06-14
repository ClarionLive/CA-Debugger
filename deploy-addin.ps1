# Clarion Debugger (standalone addin) — build & deploy.
# Builds the ClarionDbg engine + the IDE addin, then deploys both into
# <ClarionRoot>\accessory\addins\ClarionDebugger\ for each requested version.
#
# Usage: .\deploy-addin.ps1 [-Version 10|11|12|all] [-NoBuild] [-Kill]
#
# Independent of ClarionAssistant — this addin ships its own WebView2 stack, debugger.html,
# and the ClarionDbg engine exe. (Task 74c792f8: debugger extracted from ClarionAssistant.)

param(
    [ValidateSet("10","11","12","all")]
    [string]$Version = "12",
    [switch]$NoBuild,
    [switch]$Kill
)

$ErrorActionPreference = "Stop"
$RepoRoot   = $PSScriptRoot
$AddinProj  = Join-Path $RepoRoot "src\ClarionDebugger.Addin\ClarionDebugger.Addin.csproj"
$AddinOut   = Join-Path $RepoRoot "src\ClarionDebugger.Addin\bin\Debug"
$EngineProj = Join-Path $RepoRoot "src\ClarionDbg.Cli\ClarionDbg.Cli.csproj"
$EngineOut  = Join-Path $RepoRoot "src\ClarionDbg.Cli\bin\Debug\net48"

function Resolve-MSBuild {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -requires Microsoft.Component.MSBuild `
                            -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($found -and (Test-Path $found)) { return $found }
    }
    throw "MSBuild.exe not found. Install Visual Studio with the MSBuild component."
}
$MSBuild = Resolve-MSBuild

# Clarion install roots per version (first existing root wins).
$Versions = @{
    "12" = @("C:\Clarion12")
    "11" = @("d:\Clarion11.1EE", "C:\Clarion11-13372")
    "10" = @("C:\Clarion10", "C:\Clarion10v8")
}
$TargetVersions = if ($Version -eq "all") { @("12","11","10") } else { @($Version) }

if ($Kill) {
    $proc = Get-Process -Name "Clarion" -ErrorAction SilentlyContinue
    if ($proc) { Write-Host "Stopping Clarion IDE..." -ForegroundColor Yellow; $proc | Stop-Process -Force; Start-Sleep -Seconds 2 }
}

# --- Build engine once (version-independent net48/x86) ---
if (-not $NoBuild) {
    Write-Host "Building ClarionDbg engine..." -ForegroundColor Cyan
    & $MSBuild $EngineProj /t:Build /restore /p:Configuration=Debug /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { Write-Host "Engine build failed." -ForegroundColor Red; exit 1 }
}

foreach ($ver in $TargetVersions) {
    $root = @($Versions[$ver]) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $root) { Write-Host "SKIP Clarion $ver (no install root found)" -ForegroundColor DarkGray; continue }

    if (-not $NoBuild) {
        Write-Host ""
        Write-Host "Building addin for Clarion $ver ($root)..." -ForegroundColor Cyan
        & $MSBuild $AddinProj /t:Build /restore /p:Configuration=Debug /p:ClarionRoot=$root /v:minimal /nologo
        if ($LASTEXITCODE -ne 0) { Write-Host "Addin build failed for Clarion $ver." -ForegroundColor Red; exit 1 }
    }

    $DeployDir = Join-Path $root "accessory\addins\ClarionDebugger"
    Write-Host "=== Deploy Clarion $ver -> $DeployDir ===" -ForegroundColor Magenta
    if (-not (Test-Path $DeployDir)) { New-Item -ItemType Directory -Path $DeployDir | Out-Null }

    # Addin payload (dll, manifest, WebView2 managed dlls, runtimes, debugger.html)
    $items = @(
        "ClarionDebugger.dll", "ClarionDebugger.pdb", "ClarionDebugger.addin",
        "Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll", "Microsoft.Web.WebView2.Wpf.dll",
        "runtimes", "Terminal"
    )
    foreach ($item in $items) {
        $s = Join-Path $AddinOut $item
        $d = Join-Path $DeployDir $item
        if (-not (Test-Path $s)) { Write-Host "  SKIP  $item (not in build output)" -ForegroundColor DarkGray; continue }
        if (Test-Path $s -PathType Container) {
            if (Test-Path $d) { Remove-Item $d -Recurse -Force }
            Copy-Item $s $d -Recurse -Force
        } else { Copy-Item $s $d -Force }
        Write-Host "  OK    $item" -ForegroundColor Green
    }

    # WebView2 native loader also at the addin root (mirrors the working ClarionAssistant layout).
    $loader = Join-Path $AddinOut "runtimes\win-x86\native\WebView2Loader.dll"
    if (Test-Path $loader) { Copy-Item $loader (Join-Path $DeployDir "WebView2Loader.dll") -Force; Write-Host "  OK    WebView2Loader.dll (root)" -ForegroundColor Green }

    # ClarionDbg engine (launched as a child process by the pad). Iced.dll is the x86 disassembler
    # the engine hard-references for the disassembly view — ship it or `disasm` throws FileNotFound.
    foreach ($e in @("ClarionDbg.exe", "ClarionDbg.pdb", "ClarionDbg.Core.dll", "ClarionDbg.Core.pdb", "Iced.dll")) {
        $s = Join-Path $EngineOut $e
        if (-not (Test-Path $s)) { Write-Host "  SKIP  $e (not in engine output)" -ForegroundColor DarkGray; continue }
        Copy-Item $s (Join-Path $DeployDir $e) -Force
        Write-Host "  OK    $e (engine)" -ForegroundColor Green
    }

    Write-Host "  Clarion $ver deploy complete." -ForegroundColor Green
}

Write-Host ""
Write-Host "All done." -ForegroundColor Green
