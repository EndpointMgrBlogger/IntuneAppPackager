#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Win32 App Packaging Script

.DESCRIPTION
    Default (no parameters)
        Packages all apps found in <PackagingRoot>\apps and outputs
        .intunewin files to <PackagingRoot>\output.
        Defaults to C:\packaging if -PackagingRoot is not specified.

    -Setup
        First-time setup only. Creates the folder structure and
        downloads IntuneWinAppUtil.exe to <PackagingRoot>.
        Run this once before placing your app folders and packaging.

    -PackagingRoot
        Optional. Override the root packaging folder.
        Defaults to C:\packaging. Works with both -Setup and default mode.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Setup
    First-time setup using the default C:\packaging root.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Setup -PackagingRoot "D:\packaging"
    First-time setup using a custom root folder.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1
    Package all apps in C:\packaging\apps.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -PackagingRoot "D:\packaging\Contoso"
    Package all apps using a custom root folder.

.NOTES
    Run as Administrator.
    Place each app's files in its own subfolder under <PackagingRoot>\apps.
    e.g.  C:\packaging\apps\7-Zip\7z2301-x64.msi
          C:\packaging\apps\VLC\vlc-3.0.18-win64.exe
#>

[CmdletBinding(DefaultParameterSetName = 'Package')]
param (
    [Parameter(ParameterSetName = 'Setup')]
    [switch]$Setup,

    [Parameter(ParameterSetName = 'Setup')]
    [Parameter(ParameterSetName = 'Package')]
    [string]$PackagingRoot = "C:\packaging"
)

# ============================================================
#  Shared config
# ============================================================
$AppsFolder = Join-Path $PackagingRoot "apps"
$OutputFolder = Join-Path $PackagingRoot "output"
$WrapperPath  = Join-Path $PackagingRoot "IntuneWinAppUtil.exe"

# Direct download URL for the tool (raw binary from GitHub)
$WrapperUrl     = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"

# Supported setup-file extensions (evaluated in priority order)
$SetupExtensions = @("*.bat", "*.ps1", "*.exe", "*.msi")

# ============================================================
#  Helper functions
# ============================================================
function Write-Header {
    param([string]$Text)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line            -ForegroundColor Cyan
    Write-Host "  $Text"        -ForegroundColor Cyan
    Write-Host $line            -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "  >> $Text" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Text)
    Write-Host "  [OK] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  [!!] $Text" -ForegroundColor Magenta
}

function Write-Fail {
    param([string]$Text)
    Write-Host "  [XX] $Text" -ForegroundColor Red
}

function Test-AdminRights {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Select-SetupFile {
    # Resolution order per extension:
    #   1. Known PSADT entry points (Invoke-AppDeployToolkit.ps1 / Deploy-Application.ps1)
    #   2. Exact folder-name match       (e.g. folder = "VLC", file = "VLC.exe")
    #   3. Name contains folder name     (e.g. Install-VLC.ps1)
    #   4. Name contains "install"       — uninstall files already stripped
    #   5. Name contains "setup"         (e.g. setup.msi)
    #   6. Only one file remains
    # Uninstall/remove/cleanup/uninst files are always excluded first.

    param([System.IO.FileInfo[]]$Candidates, [string]$AppName, [string]$AppNameNorm)

    # Strip any uninstall files first
    $filtered = $Candidates | Where-Object {
        $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst'
    }

    if (-not $filtered) { return $null }

    # Priority 1 — known PSADT entry points (v4 and v3)
    $psadt = $filtered | Where-Object {
        $_.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$'
    }
    if (@($psadt).Count -eq 1) { return $psadt[0] }

    # Priority 2 — filename (without extension) matches folder name exactly (case-insensitive)
    $exact = $filtered | Where-Object {
        ($_.BaseName -replace '[\s\-_]', '') -eq $AppNameNorm
    }
    if (@($exact).Count -eq 1) { return $exact[0] }

    # Priority 3 — filename contains the folder name as a substring
    $nameMatch = $filtered | Where-Object {
        ($_.BaseName -replace '[\s\-_]', '') -match "(?i)$([regex]::Escape($AppNameNorm))"
    }
    if (@($nameMatch).Count -eq 1) { return $nameMatch[0] }

    # Priority 4 — filename contains "install" (uninstall already filtered above)
    $installMatch = $filtered | Where-Object { $_.BaseName -match '(?i)install' }
    if (@($installMatch).Count -eq 1) { return $installMatch[0] }

    # Priority 5 — filename contains "setup"
    $setupMatch = $filtered | Where-Object { $_.BaseName -match '(?i)setup' }
    if (@($setupMatch).Count -eq 1) { return $setupMatch[0] }

    # Priority 6 — only one file remains after stripping uninstallers
    if (@($filtered).Count -eq 1) { return $filtered[0] }

    # More than one candidate and no clear winner
    return $null
}

# ============================================================
#  Admin rights check (applies to both modes)
# ============================================================
if (-not (Test-AdminRights)) {
    Write-Warn "Script is not running elevated. Some paths may fail."
    }

# ============================================================
#  SETUP — Folder structure + tool download  (-Setup)
# ============================================================
if ($Setup) {

    Write-Header "SETUP — Folder Setup & Tool Download"

    # --- Create folders ---
    foreach ($folder in @($PackagingRoot, $AppsFolder, $OutputFolder)) {
        if (Test-Path $folder) {
            Write-OK "Already exists: $folder"
        } else {
            Write-Step "Creating $folder"
            try {
                New-Item -ItemType Directory -Path $folder -Force | Out-Null
                Write-OK "Created: $folder"
            } catch {
                Write-Fail "Could not create $folder — $_"
                exit 1
            }
        }
    }

    # --- Download IntuneWinAppUtil.exe ---
    if (Test-Path $WrapperPath) {
        Write-OK "IntuneWinAppUtil.exe already present at $WrapperPath"
    } else {
        Write-Step "Downloading IntuneWinAppUtil.exe from GitHub..."
        try {
            # Use TLS 1.2 (required by GitHub)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $WrapperUrl -OutFile $WrapperPath -UseBasicParsing
            if (Test-Path $WrapperPath) {
                Write-OK "Downloaded successfully to $WrapperPath"
            } else {
                Write-Fail "Download appeared to succeed but file not found."
                exit 1
            }
        } catch {
            Write-Fail "Download failed — $_"
            exit 1
        }
    }

    Write-Host ""
    Write-Host "  Setup complete." -ForegroundColor Cyan
    Write-Host "  Place each app's files in its own subfolder under:" -ForegroundColor White
    Write-Host "    $AppsFolder" -ForegroundColor White
    Write-Host "  Then run .\Invoke-IntunePackaging.ps1 to package them." -ForegroundColor White
    Write-Host ""
    exit 0
}

# ============================================================
#  PACKAGING — Package each app with IntuneWinAppUtil.exe  (default)
# ============================================================

    Write-Header "Packaging Apps"

    # Validate tool exists
    if (-not (Test-Path $WrapperPath)) {
        Write-Fail "IntuneWinAppUtil.exe not found at $WrapperPath"
        Write-Fail "Run setup first:  .\Invoke-IntunePackaging.ps1 -Setup"
        exit 1
    }

    # Validate apps folder exists
    if (-not (Test-Path $AppsFolder)) {
        Write-Fail "Apps folder not found: $AppsFolder"
        exit 1
    }

    # Get all immediate subfolders of the apps folder (one per app).
    $appFolders = Get-ChildItem -Path $AppsFolder -Directory

    if (@($appFolders).Count -eq 0) {
        Write-Warn "No app subfolders found in $AppsFolder"
        Write-Warn "Create one subfolder per app and place the installer inside it."
        exit 0
    }

    Write-Step "Found $($appFolders.Count) app folder(s) to process."

    $packaged = [System.Collections.Generic.List[PSCustomObject]]::new()
    $skipped    = [System.Collections.Generic.List[string]]::new()
    $failed     = [System.Collections.Generic.List[string]]::new()

    foreach ($appFolder in $appFolders) {

        $appName = $appFolder.Name
        Write-Host ""
        Write-Host "  Processing: $appName" -ForegroundColor White

        # --- Detect setup file ---
        $appNameNorm  = $appName -replace '[\s\-_]', ''   # normalise for loose name matching
        $setupFile    = $null
        $ambiguous    = $false

        foreach ($ext in $SetupExtensions) {
            $candidates = Get-ChildItem -Path $appFolder.FullName -Filter $ext -File -ErrorAction SilentlyContinue

            if (-not $candidates) { continue }

            $resolved = Select-SetupFile -Candidates $candidates -AppName $appName -AppNameNorm $appNameNorm

            if ($resolved) {
                $setupFile = $resolved
                break
            } else {
                # Candidates existed but none could be resolved unambiguously
                $ambiguous = $true
                $allNames  = ($candidates | Where-Object {
                    $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst'
                }).Name -join ', '
                Write-Warn "$appName — ambiguous $ext files (none matched name/install/setup keywords)."
                Write-Warn "Candidates after excluding uninstallers: $allNames"
                Write-Warn "Rename the intended setup file to include 'install', 'setup', or '$appName'."
                break
            }
        }

        if (-not $setupFile) {
            if (-not $ambiguous) {
                Write-Warn "$appName — no .exe/.msi/.bat/.ps1 file found. Skipping."
            }
            $skipped.Add($appName)
            continue
        }

        Write-Step "Setup file detected: $($setupFile.Name)"

        # --- Run IntuneWinAppUtil ---
        # Syntax: IntuneWinAppUtil.exe -c <SourceFolder> -s <SetupFile> -o <OutputFolder> -q
        $arguments = @(
            "-c", "`"$($appFolder.FullName)`"",
            "-s", "`"$($setupFile.Name)`"",
            "-o", "`"$OutputFolder`"",
            "-q"          # quiet / non-interactive mode
        )

        try {
            Write-Step "Running IntuneWinAppUtil..."

            # Snapshot existing .intunewin files before packaging
            $beforeFiles = Get-ChildItem -Path $OutputFolder -Filter "*.intunewin" -File |
                           Select-Object -ExpandProperty FullName

            $proc = Start-Process -FilePath $WrapperPath `
                                  -ArgumentList $arguments `
                                  -Wait `
                                  -PassThru `
                                  -NoNewWindow

            if ($proc.ExitCode -eq 0) {
                # Check for the expected output file by name first
                $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($setupFile.Name)
                $intuneWin = Join-Path $OutputFolder "$baseName.intunewin"

                if (Test-Path $intuneWin) {
                    Write-OK "$appName — packaged successfully => $($baseName).intunewin"
                    $packaged.Add([PSCustomObject]@{
                        AppName   = $appName
                        SetupFile = $setupFile.Name
                        Output = "$($baseName).intunewin"
                    })
                } else {
                    # Fall back: find any .intunewin that wasn't there before packaging
                    $newFile = Get-ChildItem -Path $OutputFolder -Filter "*.intunewin" -File |
                               Where-Object { $beforeFiles -notcontains $_.FullName } |
                               Select-Object -First 1

                    if ($newFile) {
                        Write-OK "$appName — packaged successfully => $($newFile.Name)"
                        $packaged.Add([PSCustomObject]@{
                        AppName   = $appName
                        SetupFile = $setupFile.Name
                        Output = $newFile.Name 
                        })
                    } else {
                        Write-Warn "$appName — tool exited 0 but no new .intunewin found in output."
                        $failed.Add($appName)
                    }
                }
            } else {
                Write-Fail "$appName — IntuneWinAppUtil exited with code $($proc.ExitCode)"
                $failed.Add($appName)
            }
        } catch {
            Write-Fail "$appName — exception while running tool: $_"
            $failed.Add($appName)
        }
    }

    # --------------------------------------------------------
    #  Summary
    # --------------------------------------------------------
    clear-host
    Write-Header "PACKAGING SUMMARY"

    if ($packaged.Count -gt 0) {
        Write-Host "  Successfully packaged ($($packaged.Count)):" -ForegroundColor Green
        foreach ($a in $packaged) {
            Write-Host "    + $($a.AppName)" -ForegroundColor White
            Write-Host "        Setup : $($a.SetupFile)" -ForegroundColor DarkGreen
            Write-Host "        Output: $($a.Output)" -ForegroundColor DarkGreen
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "  Skipped — no unique setup file ($($skipped.Count)):" -ForegroundColor Magenta
        foreach ($a in $skipped) { Write-Host "    ~ $a" -ForegroundColor White }
    }

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed ($($failed.Count)):" -ForegroundColor Red
        foreach ($a in $failed) { Write-Host "    x $a" -ForegroundColor Red }
    }

    Write-Host ""
    Write-Host "  Output folder: $OutputFolder" -ForegroundColor Cyan
    Write-Host ""
