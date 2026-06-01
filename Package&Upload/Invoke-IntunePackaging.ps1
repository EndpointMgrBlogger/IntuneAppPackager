#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Win32 App Packaging and Upload Script

.DESCRIPTION
    -Setup
        First-time setup. Creates the folder structure and downloads
        IntuneWinAppUtil.exe to <PackagingRoot>.
        Run once before placing app folders and packaging.

    -Package
        Packages all apps found in <PackagingRoot>\apps.
        Before packaging each app, generates a details.json if one does
        not already exist:
            MSI         — detection auto-populated from MSI database, no prep needed.
            PSADT + MSI — detection auto-populated from MSI database.
            PSADT only  — detection template written, fill in before uploading.
            Script      — detection template written, fill in before uploading.
            EXE         — full template written, fill in before uploading.
        Use -Force with -Package to regenerate existing details.json files.
        Output .intunewin files are written to <PackagingRoot>\output.

    -Upload
        Uploads packaged .intunewin files to Intune using the IntuneWin32App
        module. Requires -TenantID and -ClientID.
        Apps with unfilled details.json (REQUIRED placeholder values) are
        skipped with a warning. Apps already in Intune at the same version
        are skipped.

.PARAMETER Setup
    Run first-time folder and tool setup.

.PARAMETER Package
    Package all apps in <PackagingRoot>\apps.

.PARAMETER Upload
    Upload packaged apps to Intune. Requires -TenantID and -ClientID.

.PARAMETER Force
    Used with -Package. Regenerates existing details.json files.

.PARAMETER PackagingRoot
    Root packaging folder. Defaults to C:\packaging.

.PARAMETER TenantID
    Entra ID tenant ID or domain. Required for -Upload.

.PARAMETER ClientID
    Entra app registration client ID. Required for -Upload.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Setup
    First-time setup using the default C:\packaging root.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Setup -PackagingRoot "D:\packaging\Contoso"
    First-time setup with a custom root.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Package
    Package all apps. Generates details.json files where missing.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Package -Force
    Package all apps. Regenerates all details.json files.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Package -PackagingRoot "D:\packaging\Contoso"
    Package using a custom root.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Upload -TenantID "contoso.onmicrosoft.com" -ClientID "your-client-id"
    Upload all packaged apps to Intune.

.EXAMPLE
    .\Invoke-IntunePackaging.ps1 -Upload -TenantID "contoso.onmicrosoft.com" -ClientID "your-client-id" -PackagingRoot "D:\packaging\Contoso"
    Upload using a custom root.

.NOTES
    Run as Administrator.
    Place each app's files in its own subfolder under <PackagingRoot>\apps.
    Recommended order: -Setup  then  -Package  then  review details.json  then  -Upload
#>

[CmdletBinding()]
param (
    [switch]$Setup,
    [switch]$Package,
    [switch]$Upload,
    [switch]$Detect,
    [switch]$Force,

    [string]$PackagingRoot = "C:\packaging",
    [string]$TenantID,
    [string]$ClientID
)

# ============================================================
#  Shared config
# ============================================================
$AppsFolder           = Join-Path $PackagingRoot "apps"
$OutputFolder         = Join-Path $PackagingRoot "output"
$WrapperPath          = Join-Path $PackagingRoot "IntuneWinAppUtil.exe"
$WrapperUrl           = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"
$SetupExtensions      = @("*.bat", "*.ps1", "*.exe", "*.msi")
$DefaultPublisher     = "Endpointmgt"
$DefaultScriptVersion = "1.0"

# ============================================================
#  Helper functions
# ============================================================
function Write-Header {
    param([string]$Text)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line         -ForegroundColor Cyan
    Write-Host "  $Text"     -ForegroundColor Cyan
    Write-Host $line         -ForegroundColor Cyan
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

# ============================================================
#  Packaging functions
# ============================================================
function Select-SetupFile {
    # Resolution order per extension:
    #   1. Known PSADT entry points (Invoke-AppDeployToolkit.ps1 / Deploy-Application.ps1)
    #   2. Exact folder-name match       (e.g. folder = "VLC", file = "VLC.exe")
    #   3. Name contains folder name     (e.g. Install-VLC.ps1)
    #   4. Name contains "install"       - uninstall files already stripped
    #   5. Name contains "setup"         (e.g. setup.msi)
    #   6. Only one file remains
    # Uninstall/remove/cleanup/uninst files are always excluded first.

    param([System.IO.FileInfo[]]$Candidates, [string]$AppName, [string]$AppNameNorm)

    $filtered = $Candidates | Where-Object {
        $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst'
    }

    if (-not $filtered) { return $null }

    $psadt = $filtered | Where-Object {
        $_.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$'
    }
    if (@($psadt).Count -eq 1) { return $psadt[0] }

    $exact = $filtered | Where-Object {
        ($_.BaseName -replace '[\s\-_]', '') -eq $AppNameNorm
    }
    if (@($exact).Count -eq 1) { return $exact[0] }

    $nameMatch = $filtered | Where-Object {
        ($_.BaseName -replace '[\s\-_]', '') -match "(?i)$([regex]::Escape($AppNameNorm))"
    }
    if (@($nameMatch).Count -eq 1) { return $nameMatch[0] }

    $installMatch = $filtered | Where-Object { $_.BaseName -match '(?i)install' }
    if (@($installMatch).Count -eq 1) { return $installMatch[0] }

    $setupMatch = $filtered | Where-Object { $_.BaseName -match '(?i)setup' }
    if (@($setupMatch).Count -eq 1) { return $setupMatch[0] }

    if (@($filtered).Count -eq 1) { return $filtered[0] }

    return $null
}

# ============================================================
#  App type and metadata functions
# ============================================================
function Get-AppType {
    <#
    .SYNOPSIS
        Determines the app type from the folder contents.
    .OUTPUTS
        String: 'PSADT', 'MSI', 'Script', 'JSON', or 'Unknown'
    #>
    param([System.IO.DirectoryInfo]$AppFolder)

    $psadtFile = Get-ChildItem -Path $AppFolder.FullName -Filter "*.ps1" -File |
                 Where-Object { $_.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$' } |
                 Select-Object -First 1
    if ($psadtFile) { return 'PSADT' }

    $msiFile = Get-ChildItem -Path $AppFolder.FullName -Filter "*.msi" -File |
               Select-Object -First 1
    if ($msiFile) { return 'MSI' }

    $scriptFile = Get-ChildItem -Path $AppFolder.FullName -File |
                  Where-Object { $_.Extension -in @('.ps1', '.bat') } |
                  Where-Object { $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst' } |
                  Select-Object -First 1
    if ($scriptFile) { return 'Script' }

    $jsonPath = Join-Path $AppFolder.FullName "details.json"
    if (Test-Path $jsonPath) { return 'JSON' }

    return 'Unknown'
}

function Find-MSIInAppFolder {
    <#
    .SYNOPSIS
        Searches for an MSI file, checking Files\ subfolder first (PSADT standard)
        then the full folder tree.
    #>
    param([System.IO.DirectoryInfo]$AppFolder)

    $filesPath = Join-Path $AppFolder.FullName "Files"
    if (Test-Path $filesPath) {
        $msi = Get-ChildItem -Path $filesPath -Filter "*.msi" -File -Recurse |
               Select-Object -First 1
        if ($msi) { return $msi }
    }

    return Get-ChildItem -Path $AppFolder.FullName -Filter "*.msi" -File -Recurse |
           Select-Object -First 1
}

function Get-MSIMetadata {
    <#
    .SYNOPSIS
        Extracts app metadata from an MSI file via the Windows Installer COM object.
    #>
    param([string]$MsiPath)

    $installer = $null
    $database  = $null

    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database  = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($MsiPath, 0)
        )

        function Read-MSIProperty {
            param([string]$Property)
            $view = $database.GetType().InvokeMember(
                'OpenView', 'InvokeMethod', $null, $database,
                @("SELECT Value FROM Property WHERE Property = '$Property'")
            )
            $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($record) {
                return $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
            }
            return $null
        }

        $productName    = ([string](Read-MSIProperty 'ProductName')).Trim()
        $manufacturer   = ([string](Read-MSIProperty 'Manufacturer')).Trim()
        $productVersion = ([string](Read-MSIProperty 'ProductVersion')).Trim()
        $productCode    = ([string](Read-MSIProperty 'ProductCode')).Trim()
        $msiFileName    = [IO.Path]::GetFileName($MsiPath)

        return [PSCustomObject]@{
            DisplayName       = $productName
            Publisher         = $manufacturer
            Version           = $productVersion
            Description       = "$productName $productVersion"
            InstallCommand    = "msiexec /i `"$msiFileName`" /qn /norestart"
            UninstallCommand  = "msiexec /x `"$productCode`" /qn /norestart"
            InstallExperience = 'system'
            DetectionType     = 'msi'
            DetectionValue    = $productCode
            DetectionVersion  = $productVersion
            Source            = 'MSI'
        }
    } catch {
        Write-Warn "Failed to read MSI metadata from $MsiPath -- $_"
        return $null
    } finally {
        if ($database)  { [Runtime.InteropServices.Marshal]::ReleaseComObject($database)  | Out-Null }
        if ($installer) { [Runtime.InteropServices.Marshal]::ReleaseComObject($installer) | Out-Null }
    }
}

function Get-PSADTMetadata {
    <#
    .SYNOPSIS
        Extracts metadata from a PSADT entry point script.
        Supports both v3 ($appName style) and v4 (AppName hashtable style).
        Detection rule is read from details.json.
    #>
    param([System.IO.DirectoryInfo]$AppFolder)

    $psadtFile = Get-ChildItem -Path $AppFolder.FullName -Filter "*.ps1" -File |
                 Where-Object { $_.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$' } |
                 Select-Object -First 1

    if (-not $psadtFile) {
        Write-Warn "$($AppFolder.Name) -- PSADT entry point not found."
        return $null
    }

    $content = Get-Content -Path $psadtFile.FullName -Raw

    function Read-PSADTVariable {
        param([string]$VariableName)
        # v3 style: [string]$appName = 'value'
        if ($content -match "(?m)^\s*(?:\[string\])?\`$$VariableName\s*=\s*['""](.+?)['""]") {
            return $Matches[1]
        }
        # v4 style: AppName = 'value' (PascalCase hashtable key, no $ prefix)
        $v4Name = $VariableName.Substring(0,1).ToUpper() + $VariableName.Substring(1)
        if ($content -match "(?m)^\s*$v4Name\s*=\s*['""](.+?)['""]") {
            return $Matches[1]
        }
        return $null
    }

    $appName    = Read-PSADTVariable 'appName'
    $appVendor  = Read-PSADTVariable 'appVendor'
    $appVersion = Read-PSADTVariable 'appVersion'

    if (-not $appName) {
        Write-Warn "$($AppFolder.Name) -- could not parse appName from $($psadtFile.Name)."
        return $null
    }

    $entryPoint       = $psadtFile.Name
    $installCommand   = ".\Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode NonInteractive"
    $uninstallCommand = ".\Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode NonInteractive"

    $detectionType    = $null
    $detectionValue   = $null
    $detectionVersion = $null
    $detectionKey     = $null

    $jsonPath = Join-Path $AppFolder.FullName "details.json"
    if (Test-Path $jsonPath) {
        try {
            $json = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
            $detectionType    = $json.detectionType
            $detectionValue   = $json.detectionValue
            $detectionVersion = $json.detectionVersion
            $detectionKey     = $json.detectionKey
        } catch {
            Write-Warn "$($AppFolder.Name) -- failed to read details.json -- $_"
        }
    } else {
        Write-Warn "$($AppFolder.Name) -- no details.json found. Detection rule cannot be built."
        Write-Warn "  Run -Package to generate a template."
    }

    return [PSCustomObject]@{
        DisplayName       = if ($appName) { $appName } else { $AppFolder.Name }
        Publisher         = $appVendor
        Version           = $appVersion
        Description       = if ($appVersion) { "$appName $appVersion" } else { $appName }
        InstallCommand    = $installCommand
        UninstallCommand  = $uninstallCommand
        InstallExperience = 'system'
        DetectionType     = $detectionType
        DetectionValue    = $detectionValue
        DetectionVersion  = $detectionVersion
        DetectionKey      = $detectionKey
        Source            = 'PSADT'
    }
}

function Get-ScriptMetadata {
    <#
    .SYNOPSIS
        Builds metadata for a plain PS1 or BAT app (non-PSADT).
        Display name = folder name. Version = default. Publisher = DefaultPublisher.
        Install command auto-built from script filename.
        Uninstall command looks for an uninstall script; falls back to a no-op.
        Detection rule read from details.json.
    #>
    param([System.IO.DirectoryInfo]$AppFolder)

    $installScript = Get-ChildItem -Path $AppFolder.FullName -File |
                     Where-Object { $_.Extension -in @('.ps1', '.bat') } |
                     Where-Object { $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst' } |
                     Select-Object -First 1

    if (-not $installScript) {
        Write-Warn "$($AppFolder.Name) -- no PS1 or BAT install script found."
        return $null
    }

    if ($installScript.Extension -eq '.ps1') {
        $installCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `".\$($installScript.Name)`""
    } else {
        $installCommand = "cmd.exe /c `".\$($installScript.Name)`""
    }

    $uninstallScript = Get-ChildItem -Path $AppFolder.FullName -File |
                       Where-Object { $_.Extension -in @('.ps1', '.bat') } |
                       Where-Object { $_.BaseName -match '(?i)uninstall|remove' } |
                       Select-Object -First 1

    if ($uninstallScript) {
        if ($uninstallScript.Extension -eq '.ps1') {
            $uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `".\$($uninstallScript.Name)`""
        } else {
            $uninstallCommand = "cmd.exe /c `".\$($uninstallScript.Name)`""
        }
        Write-Step "Uninstall script found: $($uninstallScript.Name)"
    } else {
        $uninstallCommand = "cmd.exe /c echo No uninstall configured"
        Write-Warn "$($AppFolder.Name) -- no uninstall script found. Using placeholder uninstall command."
    }

    $detectionType    = $null
    $detectionKey     = $null
    $detectionValue   = $null
    $detectionVersion = $null

    $jsonPath = Join-Path $AppFolder.FullName "details.json"
    if (Test-Path $jsonPath) {
        try {
            $json = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
            $detectionType    = $json.detectionType
            $detectionKey     = $json.detectionKey
            $detectionValue   = $json.detectionValue
            $detectionVersion = $json.detectionVersion
        } catch {
            Write-Warn "$($AppFolder.Name) -- failed to read details.json -- $_"
        }
    } else {
        Write-Warn "$($AppFolder.Name) -- no details.json found. Detection rule cannot be built."
        Write-Warn "  Run -Package to generate a template."
    }

    return [PSCustomObject]@{
        DisplayName       = $AppFolder.Name
        Publisher         = $DefaultPublisher
        Version           = $DefaultScriptVersion
        Description       = $AppFolder.Name
        InstallCommand    = $installCommand
        UninstallCommand  = $uninstallCommand
        InstallExperience = 'system'
        DetectionType     = $detectionType
        DetectionKey      = $detectionKey
        DetectionValue    = $detectionValue
        DetectionVersion  = $detectionVersion
        Source            = 'Script'
    }
}

function Get-JSONMetadata {
    <#
    .SYNOPSIS
        Reads metadata from a details.json sidecar file.
        Used for EXE and other apps without a native metadata source.
        Display name is always the folder name.
    #>
    param([System.IO.DirectoryInfo]$AppFolder)

    $jsonPath = Join-Path $AppFolder.FullName "details.json"

    if (-not (Test-Path $jsonPath)) {
        Write-Warn "$($AppFolder.Name) -- no details.json found. Cannot determine metadata."
        return $null
    }

    try {
        $json = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
    } catch {
        Write-Warn "$($AppFolder.Name) -- failed to parse details.json -- $_"
        Write-Warn "  Tip: backslashes in paths need \\ not \ in JSON."
        return $null
    }

    # Normalise backslashes in path fields so single \ works as well as \\
    foreach ($field in @('detectionKey', 'detectionValue', 'installCommand', 'uninstallCommand')) {
        if ($json.$field -and $json.$field -notmatch '^REQUIRED') {
            $json.$field = $json.$field -replace '(?<!\\)\\(?!\\)', '\\'
        }
    }

    $required = @('version', 'installCommand', 'uninstallCommand')
    $missing  = $required | Where-Object { -not $json.$_ -or $json.$_ -match '^REQUIRED' }
    if ($missing) {
        Write-Warn "$($AppFolder.Name) -- details.json is missing required fields: $($missing -join ', ')"
        return $null
    }

    return [PSCustomObject]@{
        DisplayName       = $AppFolder.Name
        Publisher         = if ($json.publisher -and $json.publisher -notmatch '^OPTIONAL') { $json.publisher } else { $DefaultPublisher }
        Version           = $json.version
        Description       = if ($json.description -and $json.description -notmatch '^OPTIONAL') { $json.description } else { "$($AppFolder.Name) $($json.version)" }
        InstallCommand    = $json.installCommand
        UninstallCommand  = $json.uninstallCommand
        InstallExperience = if ($json.installExperience) { $json.installExperience } else { 'system' }
        DetectionType     = $json.detectionType
        DetectionValue    = $json.detectionValue
        DetectionVersion  = $json.detectionVersion
        DetectionKey      = $json.detectionKey
        Source            = 'JSON'
    }
}

function Get-AppMetadata {
    <#
    .SYNOPSIS
        Orchestrator -- calls the correct metadata function based on app type.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [string]$AppType
    )

    switch ($AppType) {
        'MSI'    {
            $msiFile = Get-ChildItem -Path $AppFolder.FullName -Filter "*.msi" -File |
                       Select-Object -First 1
            return Get-MSIMetadata -MsiPath $msiFile.FullName
        }
        'PSADT'  { return Get-PSADTMetadata  -AppFolder $AppFolder }
        'Script' { return Get-ScriptMetadata -AppFolder $AppFolder }
        'JSON'   { return Get-JSONMetadata   -AppFolder $AppFolder }
        default {
            Write-Warn "$($AppFolder.Name) -- unknown app type. Cannot extract metadata."
            return $null
        }
    }
}

# ============================================================
#  JSON generation function
# ============================================================
function New-AppDetailsJson {
    <#
    .SYNOPSIS
        Generates a details.json file for an app folder.
        Called during -Package for each app folder before packaging.
        MSI and PSADT+MSI have detection auto-populated from the MSI database.
        All other types get a template with clearly labelled placeholder values.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [switch]$Force
    )

    $appName  = $AppFolder.Name
    $jsonPath = Join-Path $AppFolder.FullName "details.json"

    if ((Test-Path $jsonPath) -and -not $Force) {
        Write-OK "$appName -- details.json already exists."
        return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'Already exists' }
    }

    $appType = Get-AppType -AppFolder $AppFolder
    $json    = $null

    switch ($appType) {

        'MSI' {
            Write-OK "$appName -- plain MSI, no details.json needed (fully automatic)."
            return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'Plain MSI -- no JSON needed' }
        }

        'PSADT' {
            $msiFile = Find-MSIInAppFolder -AppFolder $AppFolder

            if ($msiFile) {
                $relativePath = $msiFile.FullName.Replace($AppFolder.FullName, '').TrimStart('\')
                Write-Step "$appName -- reading MSI at $relativePath..."
                $msiData = Get-MSIMetadata -MsiPath $msiFile.FullName

                if ($msiData) {
                    $json = [ordered]@{
                        '_note'           = "Auto-generated. Detection read from MSI. Name/version/publisher read from Invoke-AppDeployToolkit.ps1."
                        'detectionType'   = 'msi'
                        'detectionValue'  = $msiData.DetectionValue
                        'detectionVersion'= $msiData.DetectionVersion
                    }
                    Write-OK "$appName -- detection auto-generated (product code: $($msiData.DetectionValue))."
                } else {
                    Write-Warn "$appName -- MSI found but could not be read. Generating detection template."
                    $json = [ordered]@{
                        '_note'           = "PSADT app. MSI found but unreadable. Fill in detection fields below."
                        'detectionType'   = 'msi'
                        'detectionValue'  = 'REQUIRED: MSI product code e.g. {00000000-0000-0000-0000-000000000000}'
                        'detectionVersion'= 'REQUIRED: version number e.g. 1.0.0'
                    }
                }
            } else {
                Write-Warn "$appName -- PSADT, no MSI found. Generating detection template."
                $json = [ordered]@{
                    '_note'           = "PSADT app. Name/version/publisher read from Invoke-AppDeployToolkit.ps1. Fill in detection fields below."
                    'detectionType'   = 'REQUIRED: registry, msi or file'
                    'detectionKey'    = 'REQUIRED (registry or file): e.g. HKLM:\\SOFTWARE\\Publisher\\AppName'
                    'detectionValue'  = 'REQUIRED: registry value name, MSI product code, or filename'
                    'detectionVersion'= 'REQUIRED: version number e.g. 1.0.0'
                }
            }
        }

        default {
            $scriptFile = Get-ChildItem -Path $AppFolder.FullName -File |
                          Where-Object { $_.Extension -in @('.ps1', '.bat') } |
                          Where-Object { $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst' } |
                          Select-Object -First 1

            $exeFile = Get-ChildItem -Path $AppFolder.FullName -Filter "*.exe" -File |
                       Where-Object { $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst' } |
                       Select-Object -First 1

            if ($scriptFile) {
                Write-Warn "$appName -- PS1/BAT app. Generating detection-only template."
                $json = [ordered]@{
                    '_note'           = "Script app. Display name, version, publisher and install command are auto-generated. Fill in detection fields only."
                    'detectionType'   = 'REQUIRED: registry, msi or file'
                    'detectionKey'    = 'REQUIRED (registry or file): e.g. HKLM:\\SOFTWARE\\Publisher\\AppName'
                    'detectionValue'  = 'REQUIRED: registry value name or filename'
                    'detectionVersion'= 'REQUIRED: version number e.g. 1.0.0'
                }
            } elseif ($exeFile) {
                Write-Warn "$appName -- EXE app. Generating template. Fill in all REQUIRED fields."
                $json = [ordered]@{
                    '_note'            = "EXE app. Display name is the folder name. Fill in all REQUIRED fields before uploading."
                    'publisher'        = "OPTIONAL: defaults to $DefaultPublisher if left blank"
                    'version'          = 'REQUIRED: version number e.g. 1.0.0'
                    'description'      = 'OPTIONAL: description shown in Company Portal'
                    'installCommand'   = "REQUIRED: e.g. $($exeFile.Name) /silent"
                    'uninstallCommand' = 'REQUIRED: e.g. uninstall.exe /silent'
                    'installExperience'= 'system'
                    'detectionType'    = 'REQUIRED: registry, msi or file'
                    'detectionKey'     = 'REQUIRED (registry or file): e.g. HKLM:\\SOFTWARE\\Publisher\\AppName'
                    'detectionValue'   = 'REQUIRED: registry value name or filename'
                    'detectionVersion' = 'REQUIRED: version number e.g. 1.0.0'
                }
            } else {
                Write-Warn "$appName -- unknown app type. Generating full template."
                $json = [ordered]@{
                    '_note'            = "Fill in all REQUIRED fields before uploading."
                    'publisher'        = "OPTIONAL: defaults to $DefaultPublisher if left blank"
                    'version'          = 'REQUIRED: version number e.g. 1.0.0'
                    'description'      = 'OPTIONAL: description shown in Company Portal'
                    'installCommand'   = 'REQUIRED: e.g. setup.exe /silent'
                    'uninstallCommand' = 'REQUIRED: e.g. uninstall.exe /silent'
                    'installExperience'= 'system'
                    'detectionType'    = 'REQUIRED: registry, msi or file'
                    'detectionKey'     = 'REQUIRED (registry or file): e.g. HKLM:\\SOFTWARE\\Publisher\\AppName'
                    'detectionValue'   = 'REQUIRED: registry value name or filename'
                    'detectionVersion' = 'REQUIRED: version number e.g. 1.0.0'
                }
            }
        }
    }

    if ($json) {
        try {
            $json | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath -Encoding UTF8
            Write-OK "$appName -- details.json written."
            return [PSCustomObject]@{ AppName = $appName; Status = 'Generated'; Reason = $appType }
        } catch {
            Write-Fail "$appName -- failed to write details.json -- $_"
            return [PSCustomObject]@{ AppName = $appName; Status = 'Failed'; Reason = $_.Exception.Message }
        }
    }
}

# ============================================================
#  Upload functions
# ============================================================
function Get-AppIcon {
    <#
    .SYNOPSIS
        Searches for an app icon PNG in the following order:
          1. icon.png in the app folder root
          2. {foldername}.png in the app folder root
        Returns the local path to the icon file, or $null if nothing is found.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [string]$DisplayName
    )

    $folderName = $AppFolder.Name

    # 1. icon.png in app folder root
    $iconPath = Join-Path $AppFolder.FullName "icon.png"
    if (Test-Path $iconPath) {
        Write-Step "Icon found locally: icon.png"
        return $iconPath
    }

    # 2. {foldername}.png in app folder root
    $iconPath = Join-Path $AppFolder.FullName "$folderName.png"
    if (Test-Path $iconPath) {
        Write-Step "Icon found locally: $folderName.png"
        return $iconPath
    }
    return $null
}

function Install-UploadPrerequisites {
    <#
    .SYNOPSIS
        Ensures the IntuneWin32App module is installed and imported.
    #>
    Write-Step "Checking IntuneWin32App module..."

    if (-not (Get-Module -ListAvailable -Name IntuneWin32App)) {
        Write-Step "IntuneWin32App not found -- installing from PSGallery..."
        try {
            Install-Module -Name IntuneWin32App -Scope CurrentUser -Force -AllowClobber
            Write-OK "IntuneWin32App installed successfully."
        } catch {
            Write-Fail "Failed to install IntuneWin32App -- $_"
            return $false
        }
    } else {
        Write-OK "IntuneWin32App module found."
    }

    try {
        Import-Module IntuneWin32App -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Fail "Failed to import IntuneWin32App -- $_"
        return $false
    }
}

function Connect-IntuneGraph {
    <#
    .SYNOPSIS
        Authenticates to the IntuneWin32App module via Connect-MSIntuneGraph.
        Opens an interactive browser login using the provided TenantID and ClientID.
    #>
    param(
        [string]$TenantID,
        [string]$ClientID
    )

    Write-Step "Connecting to Microsoft Graph..."
    try {
        Connect-MSIntuneGraph -TenantID $TenantID -ClientID $ClientID -ErrorAction Stop
        Write-OK "Connected to Microsoft Graph."
        return $true
    } catch {
        Write-Fail "Authentication failed -- $_"
        return $false
    }
}

function Get-IntuneWinPath {
    <#
    .SYNOPSIS
        Locates the .intunewin file in the output folder for an app folder.
        PSADT apps are named after the folder; others after the setup file.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [string]$AppType,
        [string]$OutputFolder
    )

    if ($AppType -eq 'PSADT') {
        $path = Join-Path $OutputFolder "$($AppFolder.Name).intunewin"
        if (Test-Path $path) { return $path }
    } else {
        $installers = Get-ChildItem -Path $AppFolder.FullName -File |
                      Where-Object { $_.Extension -in @('.msi', '.exe', '.bat', '.ps1') }
        foreach ($file in $installers) {
            $baseName = [IO.Path]::GetFileNameWithoutExtension($file.Name)
            $path     = Join-Path $OutputFolder "$baseName.intunewin"
            if (Test-Path $path) { return $path }
        }
    }

    return $null
}

function Test-IntuneAppExists {
    <#
    .SYNOPSIS
        Checks whether an app with the same display name and version already
        exists in the pre-fetched list of Intune apps.
        The list is fetched once before the upload loop and passed in here,
        avoiding a separate API call per app.
    #>
    param(
        [string]$DisplayName,
        [string]$Version,
        [array]$ExistingApps
    )

    return $ExistingApps | Where-Object {
        $_.displayName    -eq $DisplayName -and
        $_.displayVersion -eq $Version
    } | Select-Object -First 1
}

function New-IntuneDetectionRule {
    <#
    .SYNOPSIS
        Builds a detection rule object for Add-IntuneWin32App.
        Supports: msi, registry, file.
    #>
    param([PSCustomObject]$Metadata)

    try {
        switch ($Metadata.DetectionType) {
            'msi' {
                return New-IntuneWin32AppDetectionRuleMSI `
                    -ProductCode    ([string]$Metadata.DetectionValue).Trim() `
                    -ProductVersion ([string]$Metadata.DetectionVersion).Trim()
            }
            'registry' {
                if (([string]$Metadata.DetectionVersion) -match '^\d+[\.\d]*$') {
                    return New-IntuneWin32AppDetectionRuleRegistry `
                        -KeyPath                   ([string]$Metadata.DetectionKey) `
                        -ValueName                 ([string]$Metadata.DetectionValue) `
                        -Check32BitOn64System      $false `
                        -VersionComparison `
                        -VersionComparisonOperator 'greaterThanOrEqual' `
                        -VersionComparisonValue    ([string]$Metadata.DetectionVersion)
                } else {
                    return New-IntuneWin32AppDetectionRuleRegistry `
                        -KeyPath                  ([string]$Metadata.DetectionKey) `
                        -ValueName                ([string]$Metadata.DetectionValue) `
                        -Check32BitOn64System     $false `
                        -StringComparison `
                        -StringComparisonOperator 'equal' `
                        -StringComparisonValue    ([string]$Metadata.DetectionVersion)
                }
            }
            'file' {
                return New-IntuneWin32AppDetectionRuleFile `
                    -Path                 ([string]$Metadata.DetectionKey) `
                    -FileOrFolderName     ([string]$Metadata.DetectionValue) `
                    -Check32BitOn64System $false `
                    -DetectionType        'version' `
                    -VersionValue         ([string]$Metadata.DetectionVersion) `
                    -VersionOperator      'greaterThanOrEqual'
            }
            default {
                Write-Warn "Unsupported detection type: '$($Metadata.DetectionType)'. Supported: msi, registry, file."
                return $null
            }
        }
    } catch {
        Write-Warn "Failed to build detection rule -- $_"
        return $null
    }
}

function Invoke-AppUpload {
    <#
    .SYNOPSIS
        Orchestrates the full upload of a single app to Intune.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [string]$OutputFolder,
        [array]$ExistingApps
    )

    $appName = $AppFolder.Name

    $appType = Get-AppType -AppFolder $AppFolder
    if ($appType -eq 'Unknown') {
        Write-Warn "$appName -- could not determine app type."
        return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'Unknown app type' }
    }
    Write-Step "App type: $appType"

    $intuneWinPath = Get-IntuneWinPath -AppFolder $AppFolder -AppType $appType -OutputFolder $OutputFolder
    if (-not $intuneWinPath) {
        Write-Warn "$appName -- no .intunewin file found. Run -Package first."
        return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'No .intunewin file found' }
    }
    Write-Step ".intunewin: $(Split-Path $intuneWinPath -Leaf)"

    $metadata = Get-AppMetadata -AppFolder $AppFolder -AppType $appType
    if (-not $metadata) {
        return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'Metadata extraction failed' }
    }
    if (-not $metadata.DetectionType -or $metadata.DetectionType -match '^REQUIRED') {
        Write-Warn "$appName -- no detection rule defined. Fill in details.json and re-run."
        return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'No detection rule' }
    }
    Write-Step "Display name : $($metadata.DisplayName)"
    Write-Step "Version      : $($metadata.Version)"
    Write-Step "Publisher    : $($metadata.Publisher)"
    Write-Step "Detection    : $($metadata.DetectionType)"

    Write-Step "Checking for existing app in Intune..."
    $existing = Test-IntuneAppExists -DisplayName $metadata.DisplayName -Version $metadata.Version -ExistingApps $ExistingApps
    if ($existing) {
        Write-Warn "$appName -- '$($metadata.DisplayName)' v$($metadata.Version) already exists in Intune. Skipping."
        return [PSCustomObject]@{ AppName = $appName; Status = 'Skipped'; Reason = 'Already exists in Intune' }
    }
    Write-OK "No duplicate found -- proceeding with upload."

    $detectionRule = New-IntuneDetectionRule -Metadata $metadata
    if (-not $detectionRule) {
        return [PSCustomObject]@{ AppName = $appName; Status = 'Failed'; Reason = 'Detection rule build failed' }
    }

    Write-Step "Uploading to Intune..."

    # --- Icon ---
    $iconObject = $null
    $iconPath   = Get-AppIcon -AppFolder $AppFolder -DisplayName $metadata.DisplayName
    if ($iconPath) {
        try {
            $iconObject = New-IntuneWin32AppIcon -FilePath $iconPath
        } catch {
            Write-Warn "$appName -- icon found but could not be loaded -- $_"
        }
    }

    try {
        $uploadParams = @{
            FilePath             = $intuneWinPath
            DisplayName          = $metadata.DisplayName
            Description          = $metadata.Description
            Publisher            = $metadata.Publisher
            AppVersion           = $metadata.Version
            InstallCommandLine   = $metadata.InstallCommand
            UninstallCommandLine = $metadata.UninstallCommand
            InstallExperience    = $metadata.InstallExperience
            RestartBehavior      = 'suppress'
            DetectionRule        = $detectionRule
        }
        if ($iconObject) { $uploadParams['Icon'] = $iconObject }

        $app = Add-IntuneWin32App @uploadParams

        if ($app.id) {
            Write-OK "$appName -- uploaded successfully. App ID: $($app.id)"
            return [PSCustomObject]@{
                AppName     = $appName
                Status      = 'Uploaded'
                DisplayName = $metadata.DisplayName
                Version     = $metadata.Version
                AppID       = $app.id
                Source      = $metadata.Source
                Icon        = if ($iconObject) { Split-Path $iconPath -Leaf } else { 'none' }
            }
        } else {
            Write-Fail "$appName -- upload returned no app ID."
            return [PSCustomObject]@{ AppName = $appName; Status = 'Failed'; Reason = 'No app ID returned' }
        }
    } catch {
        Write-Fail "$appName -- upload failed -- $_"
        return [PSCustomObject]@{ AppName = $appName; Status = 'Failed'; Reason = $_.Exception.Message }
    }
}

# ============================================================
#  Detect functions
# ============================================================
function Get-InstalledAppsFromRegistry {
    <#
    .SYNOPSIS
        Scans the standard uninstall registry hives and the PhoenixSoftware
        hive for script apps. Returns a normalised list of installed apps.
    #>
    $apps = [System.Collections.Generic.List[PSCustomObject]]::new()

    $hives = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';              Source = 'Uninstall64' },
        @{ Path = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall';  Source = 'Uninstall32' }
    )

    foreach ($hive in $hives) {
        if (-not (Test-Path $hive.Path)) { continue }
        Get-ChildItem -Path $hive.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            if (-not $props.DisplayName) { return }
            $isGuid = $_.PSChildName -match '^\{[0-9A-Fa-f\-]{36}\}$'
            $apps.Add([PSCustomObject]@{
                DisplayName   = $props.DisplayName
                Version       = $props.DisplayVersion
                Publisher     = $props.Publisher
                KeyName       = $_.PSChildName
                RegistryPath  = "HKLM:\$($_.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\', '')"
                IsProductCode = $isGuid
                Source        = $hive.Source
            })
        }
    }

    # PhoenixSoftware hive — script apps
    # Structure: HKLM:\SOFTWARE\PhoenixSoftware\<AppName>
    #   Values:  AppName, AppVersion
    $phoenixPath = 'HKLM:\SOFTWARE\PhoenixSoftware'
    if (Test-Path $phoenixPath) {
        Get-ChildItem -Path $phoenixPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            $apps.Add([PSCustomObject]@{
                DisplayName   = if ($props.AppName) { $props.AppName } else { $_.PSChildName }
                Version       = $props.AppVersion
                Publisher     = $DefaultPublisher
                KeyName       = $_.PSChildName
                RegistryPath  = "HKLM:\SOFTWARE\PhoenixSoftware\$($_.PSChildName)"
                IsProductCode = $false
                Source        = 'PhoenixSoftware'
            })
        }
    }

    return $apps
}

function Find-RegistryMatchForApp {
    <#
    .SYNOPSIS
        Fuzzy matches an app folder name against the scanned registry results.
        Script apps check PhoenixSoftware first, then standard hives as fallback.
        MSI and PSADT+MSI are never passed to this function.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [string]$AppType,
        [System.Collections.Generic.List[PSCustomObject]]$InstalledApps
    )

    $folderNorm = $AppFolder.Name -replace '[\s\-_]', ''

    # Script apps — check PhoenixSoftware hive first
    if ($AppType -eq 'Script') {
        $phoenix = $InstalledApps | Where-Object {
            $_.Source -eq 'PhoenixSoftware' -and
            ($_.KeyName -replace '[\s\-_]', '') -eq $folderNorm
        } | Select-Object -First 1
        if ($phoenix) { return $phoenix }
    }

    # Standard uninstall hives — folder name contained in DisplayName
    $match = $InstalledApps | Where-Object {
        $_.Source -ne 'PhoenixSoftware' -and
        ($_.DisplayName -replace '[\s\-_]', '') -match "(?i)$([regex]::Escape($folderNorm))"
    } | Select-Object -First 1
    if ($match) { return $match }

    # Reverse — DisplayName contained in folder name
    $match = $InstalledApps | Where-Object {
        $_.Source -ne 'PhoenixSoftware' -and
        $folderNorm -match "(?i)$([regex]::Escape(($_.DisplayName -replace '[\s\-_]', '')))"
    } | Select-Object -First 1

    return $match
}

function Update-DetailsJsonWithDetection {
    <#
    .SYNOPSIS
        Writes detection fields into an app's details.json based on a
        registry match. Only updates fields that contain REQUIRED placeholders
        unless -Force is passed.
        MSI and PSADT+MSI apps are never passed to this function.
    #>
    param(
        [System.IO.DirectoryInfo]$AppFolder,
        [PSCustomObject]$RegistryMatch,
        [switch]$Force
    )

    $appName  = $AppFolder.Name
    $jsonPath = Join-Path $AppFolder.FullName "details.json"

    # Build the detection fields from the registry match
    if ($RegistryMatch.Source -eq 'PhoenixSoftware') {
        $newDetectionType    = 'registry'
        $newDetectionKey     = $RegistryMatch.RegistryPath
        $newDetectionValue   = 'AppVersion'
        $newDetectionVersion = $RegistryMatch.Version
    } elseif ($RegistryMatch.IsProductCode) {
        # MSI product code key — use MSI detection
        $newDetectionType    = 'msi'
        $newDetectionKey     = $null
        $newDetectionValue   = $RegistryMatch.KeyName
        $newDetectionVersion = $RegistryMatch.Version
    } else {
        # Standard registry key — use registry detection pointing at uninstall key
        $newDetectionType    = 'registry'
        $newDetectionKey     = $RegistryMatch.RegistryPath
        $newDetectionValue   = 'DisplayVersion'
        $newDetectionVersion = $RegistryMatch.Version
    }

    # Read or create the JSON
    if (Test-Path $jsonPath) {
        try {
            $json = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        } catch {
            Write-Warn "$appName -- failed to read details.json -- $_"
            return $false
        }

        # Check if detection is already filled — skip unless -Force
        $alreadyFilled = $json.detectionType -and
                         $json.detectionType -notmatch '^REQUIRED'
        if ($alreadyFilled -and -not $Force) {
            Write-OK "$appName -- detection already set ('$($json.detectionType)'). Use -Force to overwrite."
            return $false
        }
    } else {
        # No details.json — create a minimal one
        $json = [PSCustomObject]@{}
    }

    # Apply detection fields
    $json | Add-Member -MemberType NoteProperty -Name 'detectionType'    -Value $newDetectionType    -Force
    $json | Add-Member -MemberType NoteProperty -Name 'detectionKey'     -Value $newDetectionKey     -Force
    $json | Add-Member -MemberType NoteProperty -Name 'detectionValue'   -Value $newDetectionValue   -Force
    $json | Add-Member -MemberType NoteProperty -Name 'detectionVersion' -Value $newDetectionVersion -Force

    try {
        $json | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath -Encoding UTF8
        return $true
    } catch {
        Write-Warn "$appName -- failed to write details.json -- $_"
        return $false
    }
}

# ============================================================
#  Admin rights check
# ============================================================
if (-not (Test-AdminRights)) {
    Write-Warn "Script is not running elevated. Some operations may fail."
}

# ============================================================
#  Usage -- no mode specified
# ============================================================
if (-not $Setup -and -not $Package -and -not $Upload -and -not $Detect) {
    Write-Host ""
    Write-Host "  Intune Win32 App Packaging Script" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Usage:" -ForegroundColor White
    Write-Host "    .\Invoke-IntunePackaging.ps1 -Setup" -ForegroundColor Yellow
    Write-Host "    .\Invoke-IntunePackaging.ps1 -Package [-Force] [-PackagingRoot <path>]" -ForegroundColor Yellow
    Write-Host "    .\Invoke-IntunePackaging.ps1 -Detect  [-Force] [-PackagingRoot <path>]" -ForegroundColor Yellow
    Write-Host "    .\Invoke-IntunePackaging.ps1 -Upload  -TenantID <id> -ClientID <id> [-PackagingRoot <path>]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Recommended order: -Setup  -Package  -Detect  review details.json  -Upload" -ForegroundColor White
    Write-Host ""
    exit 0
}

# ============================================================
#  SETUP  (-Setup)
# ============================================================
if ($Setup) {

    Write-Header "SETUP -- Folder Setup and Tool Download"

    foreach ($folder in @($PackagingRoot, $AppsFolder, $OutputFolder)) {
        if (Test-Path $folder) {
            Write-OK "Already exists: $folder"
        } else {
            Write-Step "Creating $folder"
            try {
                New-Item -ItemType Directory -Path $folder -Force | Out-Null
                Write-OK "Created: $folder"
            } catch {
                Write-Fail "Could not create $folder -- $_"
                exit 1
            }
        }
    }

    if (Test-Path $WrapperPath) {
        Write-OK "IntuneWinAppUtil.exe already present at $WrapperPath"
    } else {
        Write-Step "Downloading IntuneWinAppUtil.exe from GitHub..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $WrapperUrl -OutFile $WrapperPath -UseBasicParsing
            if (Test-Path $WrapperPath) {
                Write-OK "Downloaded successfully to $WrapperPath"
            } else {
                Write-Fail "Download appeared to succeed but file not found."
                exit 1
            }
        } catch {
            Write-Fail "Download failed -- $_"
            exit 1
        }
    }

    Write-Host ""
    Write-Host "  Setup complete." -ForegroundColor Cyan
    Write-Host "  Place each app's files in its own subfolder under:" -ForegroundColor White
    Write-Host "    $AppsFolder" -ForegroundColor White
    Write-Host "  Then run .\Invoke-IntunePackaging.ps1 -Package" -ForegroundColor White
    Write-Host ""
    exit 0
}

# ============================================================
#  Shared pre-flight checks  (Package, Detect and Upload)
# ============================================================
if (-not (Test-Path $AppsFolder)) {
    Write-Fail "Apps folder not found: $AppsFolder"
    Write-Fail "Run -Setup first or check -PackagingRoot."
    exit 1
}

$appFolders = Get-ChildItem -Path $AppsFolder -Directory
if (@($appFolders).Count -eq 0) {
    Write-Warn "No app subfolders found in $AppsFolder"
    exit 0
}

# ============================================================
#  PACKAGE  (-Package)
# ============================================================
if ($Package) {

    Write-Header "Packaging Apps"

    if (-not (Test-Path $WrapperPath)) {
        Write-Fail "IntuneWinAppUtil.exe not found at $WrapperPath"
        Write-Fail "Run -Setup first."
        exit 1
    }

    Write-Step "Found $($appFolders.Count) app folder(s) to process."

    $packaged = [System.Collections.Generic.List[PSCustomObject]]::new()
    $skipped  = [System.Collections.Generic.List[string]]::new()
    $failed   = [System.Collections.Generic.List[string]]::new()

    foreach ($appFolder in $appFolders) {

        $appName = $appFolder.Name
        Write-Host ""
        Write-Host "  Processing: $appName" -ForegroundColor White

        # --- Generate details.json if missing (warn and continue if template needed) ---
        New-AppDetailsJson -AppFolder $appFolder -Force:$Force | Out-Null

        # --- Detect setup file ---
        $appNameNorm = $appName -replace '[\s\-_]', ''
        $setupFile   = $null
        $ambiguous   = $false

        foreach ($ext in $SetupExtensions) {
            $candidates = Get-ChildItem -Path $appFolder.FullName -Filter $ext -File -ErrorAction SilentlyContinue

            if (-not $candidates) { continue }

            $resolved = Select-SetupFile -Candidates $candidates -AppName $appName -AppNameNorm $appNameNorm

            if ($resolved) {
                $setupFile = $resolved
                break
            } else {
                $ambiguous = $true
                $allNames  = ($candidates | Where-Object {
                    $_.BaseName -notmatch '(?i)uninstall|remove|cleanup|uninst'
                }).Name -join ', '
                Write-Warn "$appName -- ambiguous $ext files (none matched name/install/setup keywords)."
                Write-Warn "Candidates after excluding uninstallers: $allNames"
                Write-Warn "Rename the intended setup file to include 'install', 'setup', or '$appName'."
                break
            }
        }

        if (-not $setupFile) {
            if (-not $ambiguous) {
                Write-Warn "$appName -- no .exe/.msi/.bat/.ps1 file found. Skipping."
            }
            $skipped.Add($appName)
            continue
        }

        Write-Step "Setup file detected: $($setupFile.Name)"

        # --- Check if .intunewin already exists ---
        $isPsadt = $setupFile.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$'
        $expectedBaseName = if ($isPsadt) { $appName } else {
            [System.IO.Path]::GetFileNameWithoutExtension($setupFile.Name)
        }
        $expectedOutput = Join-Path $OutputFolder "$expectedBaseName.intunewin"

        if ((Test-Path $expectedOutput) -and -not $Force) {
            Write-Warn "$appName -- $expectedBaseName.intunewin already exists in output."
            $response = Read-Host "  Replace it? (Y/N)"
            if ($response -notmatch '^[Yy]$') {
                Write-Warn "$appName -- skipped. Existing .intunewin kept."
                $skipped.Add($appName)
                continue
            }
            Remove-Item -Path $expectedOutput -Force
        }
        $arguments = @(
            "-c", "`"$($appFolder.FullName)`"",
            "-s", "`"$($setupFile.Name)`"",
            "-o", "`"$OutputFolder`"",
            "-q"
        )

        try {
            Write-Step "Running IntuneWinAppUtil..."

            $beforeFiles = Get-ChildItem -Path $OutputFolder -Filter "*.intunewin" -File |
                           Select-Object -ExpandProperty FullName

            $proc = Start-Process -FilePath $WrapperPath `
                                  -ArgumentList $arguments `
                                  -Wait `
                                  -PassThru `
                                  -NoNewWindow

            if ($proc.ExitCode -eq 0) {
                $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($setupFile.Name)
                $intuneWin = Join-Path $OutputFolder "$baseName.intunewin"

                if (Test-Path $intuneWin) {
                    if ($setupFile.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$') {
                        Rename-Item -Path $intuneWin -NewName "$appName.intunewin" -Force
                        $outputName = "$appName.intunewin"
                    } else {
                        $outputName = "$($baseName).intunewin"
                    }
                    Write-OK "$appName -- packaged successfully => $outputName"
                    $packaged.Add([PSCustomObject]@{
                        AppName   = $appName
                        SetupFile = $setupFile.Name
                        Output    = $outputName
                    })
                } else {
                    $newFile = Get-ChildItem -Path $OutputFolder -Filter "*.intunewin" -File |
                               Where-Object { $beforeFiles -notcontains $_.FullName } |
                               Select-Object -First 1

                    if ($newFile) {
                        if ($setupFile.Name -match '(?i)^(Invoke-AppDeployToolkit|Deploy-Application)\.ps1$') {
                            Rename-Item -Path $newFile.FullName -NewName "$appName.intunewin" -Force
                            $outputName = "$appName.intunewin"
                        } else {
                            $outputName = $newFile.Name
                        }
                        Write-OK "$appName -- packaged successfully => $outputName"
                        $packaged.Add([PSCustomObject]@{
                            AppName   = $appName
                            SetupFile = $setupFile.Name
                            Output    = $outputName
                        })
                    } else {
                        Write-Warn "$appName -- tool exited 0 but no new .intunewin found in output."
                        $failed.Add($appName)
                    }
                }
            } else {
                Write-Fail "$appName -- IntuneWinAppUtil exited with code $($proc.ExitCode)"
                $failed.Add($appName)
            }
        } catch {
            Write-Fail "$appName -- exception while running tool: $_"
            $failed.Add($appName)
        }
    }

    # --- Summary ---
    Clear-Host
    Write-Header "PACKAGING SUMMARY"

    if ($packaged.Count -gt 0) {
        Write-Host "  Successfully packaged ($($packaged.Count)):" -ForegroundColor Green
        foreach ($a in $packaged) {
            Write-Host "    + $($a.AppName)" -ForegroundColor White
            Write-Host "        Setup : $($a.SetupFile)" -ForegroundColor DarkGreen
            Write-Host "        Output: $($a.Output)"    -ForegroundColor DarkGreen
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "  Skipped -- no unique setup file ($($skipped.Count)):" -ForegroundColor Magenta
        foreach ($a in $skipped) { Write-Host "    ~ $a" -ForegroundColor White }
    }

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed ($($failed.Count)):" -ForegroundColor Red
        foreach ($a in $failed) { Write-Host "    x $a" -ForegroundColor Red }
    }

    Write-Host ""
    Write-Host "  Output folder: $OutputFolder" -ForegroundColor Cyan
    Write-Host "  Review any details.json templates before running -Upload." -ForegroundColor White
    Write-Host ""
    exit 0
}

# ============================================================
#  DETECT  (-Detect)
# ============================================================
if ($Detect) {

    Write-Header "Registry Detection Scan"

    Write-Step "Scanning registry for installed applications..."
    $installedApps = Get-InstalledAppsFromRegistry
    Write-OK "Found $($installedApps.Count) installed app entries."

    Write-Step "Found $($appFolders.Count) app folder(s) to process."

    $detected  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $skipped   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $notFound  = [System.Collections.Generic.List[string]]::new()

    foreach ($appFolder in $appFolders) {

        $appName = $appFolder.Name
        Write-Host ""
        Write-Host "  Processing: $appName" -ForegroundColor White

        $appType = Get-AppType -AppFolder $appFolder

        # MSI and PSADT+MSI — skip, detection already handled by -Package
        if ($appType -eq 'MSI') {
            Write-OK "$appName -- plain MSI, detection auto-derived. Skipping."
            $skipped.Add([PSCustomObject]@{ AppName = $appName; Reason = 'Plain MSI -- no registry scan needed' })
            continue
        }

        if ($appType -eq 'PSADT') {
            $msiFile = Find-MSIInAppFolder -AppFolder $appFolder
            if ($msiFile) {
                Write-OK "$appName -- PSADT with MSI, detection auto-derived. Skipping."
                $skipped.Add([PSCustomObject]@{ AppName = $appName; Reason = 'PSADT + MSI -- no registry scan needed' })
                continue
            }
        }

        # All other types -- scan registry
        Write-Step "App type: $appType — scanning registry..."
        $match = Find-RegistryMatchForApp -AppFolder $appFolder -AppType $appType -InstalledApps $installedApps

        if (-not $match) {
            Write-Warn "$appName -- not found in registry. App may not be installed, or name did not match."
            Write-Warn "  Install the app on this machine and re-run, or fill in details.json manually."
            $notFound.Add($appName)
            continue
        }

        Write-OK "$appName -- matched: '$($match.DisplayName)' v$($match.Version) [$($match.Source)]"
        Write-Step "Registry path : $($match.RegistryPath)"
        Write-Step "Version       : $($match.Version)"

        $updated = Update-DetailsJsonWithDetection -AppFolder $appFolder -RegistryMatch $match -Force:$Force

        if ($updated) {
            Write-OK "$appName -- details.json updated with detection."
            $detected.Add([PSCustomObject]@{
                AppName       = $appName
                MatchedName   = $match.DisplayName
                Version       = $match.Version
                DetectionType = if ($match.Source -eq 'PhoenixSoftware') { 'registry (PhoenixSoftware)' } elseif ($match.IsProductCode) { 'msi' } else { 'registry (Uninstall)' }
                Source        = $match.Source
            })
        } else {
            $skipped.Add([PSCustomObject]@{ AppName = $appName; Reason = 'Detection already set — use -Force to overwrite' })
        }
    }

    # --- Summary ---
    Clear-Host
    Write-Header "DETECT SUMMARY"

    if ($detected.Count -gt 0) {
        Write-Host "  Updated ($($detected.Count)):" -ForegroundColor Green
        foreach ($r in $detected) {
            Write-Host "    + $($r.AppName)" -ForegroundColor White
            Write-Host "        Matched : $($r.MatchedName)" -ForegroundColor DarkGreen
            Write-Host "        Version : $($r.Version)"     -ForegroundColor DarkGreen
            Write-Host "        Type    : $($r.DetectionType)" -ForegroundColor DarkGreen
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "  Skipped ($($skipped.Count)):" -ForegroundColor Magenta
        foreach ($r in $skipped) {
            Write-Host "    ~ $($r.AppName)" -ForegroundColor White
            Write-Host "        Reason: $($r.Reason)" -ForegroundColor DarkYellow
        }
    }

    if ($notFound.Count -gt 0) {
        Write-Host ""
        Write-Host "  Not found in registry ($($notFound.Count)):" -ForegroundColor Red
        foreach ($a in $notFound) {
            Write-Host "    x $a" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  For apps not found: install them on this machine and re-run -Detect," -ForegroundColor White
        Write-Host "  or fill in the detection fields in details.json manually." -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  Review details.json files in $AppsFolder before running -Upload." -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ============================================================
#  UPLOAD  (-Upload)
# ============================================================
if ($Upload) {

    Write-Header "Intune Win32 App Upload"

    if (-not $TenantID) {
        Write-Fail "TenantID is required for upload."
        Write-Fail "Usage: .\Invoke-IntunePackaging.ps1 -Upload -TenantID `"contoso.onmicrosoft.com`" -ClientID `"your-client-id`""
        exit 1
    }
    if (-not $ClientID) {
        Write-Fail "ClientID is required for upload."
        Write-Fail "Usage: .\Invoke-IntunePackaging.ps1 -Upload -TenantID `"contoso.onmicrosoft.com`" -ClientID `"your-client-id`""
        exit 1
    }

    if (-not (Test-Path $OutputFolder)) {
        Write-Fail "Output folder not found: $OutputFolder"
        Write-Fail "Run -Package before uploading."
        exit 1
    }

    if (-not (Install-UploadPrerequisites)) { exit 1 }
    if (-not (Connect-IntuneGraph -TenantID $TenantID -ClientID $ClientID)) { exit 1 }

    # IntuneWin32App module uses DateTime.Parse internally which is culture-sensitive.
    # Switch to en-US for the duration of the upload to prevent failures on non-US locales.
    $originalCulture   = [System.Threading.Thread]::CurrentThread.CurrentCulture
    $originalUICulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture   = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')

    Write-Step "Found $($appFolders.Count) app folder(s) to process."

    # Fetch all existing Intune apps once upfront — avoids a separate API call per app
    Write-Step "Fetching existing apps from Intune..."
    try {
        $existingIntuneApps = @(Get-IntuneWin32App)
        Write-OK "Found $($existingIntuneApps.Count) existing app(s) in Intune."
    } catch {
        Write-Warn "Could not fetch existing Intune apps -- $_"
        Write-Warn "Duplicate checking will be skipped."
        $existingIntuneApps = @()
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($appFolder in $appFolders) {
        Write-Host ""
        Write-Host "  Processing: $($appFolder.Name)" -ForegroundColor White
        $result = Invoke-AppUpload -AppFolder $appFolder -OutputFolder $OutputFolder -ExistingApps $existingIntuneApps
        $results.Add($result)
    }

    # --- Summary ---
    Clear-Host
    Write-Header "UPLOAD SUMMARY"

    $uploaded = $results | Where-Object { $_.Status -eq 'Uploaded' }
    $skipped  = $results | Where-Object { $_.Status -eq 'Skipped' }
    $failed   = $results | Where-Object { $_.Status -eq 'Failed' }

    if ($uploaded) {
        Write-Host "  Successfully uploaded ($($uploaded.Count)):" -ForegroundColor Green
        foreach ($r in $uploaded) {
            Write-Host "    + $($r.AppName)" -ForegroundColor White
            Write-Host "        Name   : $($r.DisplayName)" -ForegroundColor DarkGreen
            Write-Host "        Version: $($r.Version)"     -ForegroundColor DarkGreen
            Write-Host "        Source : $($r.Source)"      -ForegroundColor DarkGreen
            Write-Host "        Icon   : $($r.Icon)"        -ForegroundColor DarkGreen
            Write-Host "        App ID : $($r.AppID)"       -ForegroundColor DarkGreen
        }
    }

    if ($skipped) {
        Write-Host ""
        Write-Host "  Skipped ($($skipped.Count)):" -ForegroundColor Magenta
        foreach ($r in $skipped) {
            Write-Host "    ~ $($r.AppName)" -ForegroundColor White
            Write-Host "        Reason: $($r.Reason)" -ForegroundColor DarkYellow
        }
    }

    if ($failed) {
        Write-Host ""
        Write-Host "  Failed ($($failed.Count)):" -ForegroundColor Red
        foreach ($r in $failed) {
            Write-Host "    x $($r.AppName)" -ForegroundColor Red
            Write-Host "        Reason: $($r.Reason)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "  Tenant  : $TenantID" -ForegroundColor Cyan
    Write-Host "  ClientID: $ClientID" -ForegroundColor Cyan
    Write-Host ""

    # Restore original culture
    [System.Threading.Thread]::CurrentThread.CurrentCulture   = $originalCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $originalUICulture
    exit 0
}
