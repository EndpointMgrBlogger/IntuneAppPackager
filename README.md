# Invoke-IntunePackaging

A PowerShell script that automates Intune Win32 app packaging — folder setup, downloading the Content Prep Tool, and wrapping your apps ready to upload.

## Requirements

- PowerShell 5.1 or later
- Run as Administrator

---

## Quick Start

### 1. Run setup (once per machine)

```powershell
.\Invoke-IntunePackaging.ps1 -Setup
```

This creates the folder structure and downloads `IntuneWinAppUtil.exe` to `C:\packaging`.

To use a custom path:

```powershell
.\Invoke-IntunePackaging.ps1 -Setup -PackagingRoot "D:\packaging\Contoso"
```

> **Note:** Whatever path you pass to `-Setup`, use the same path when packaging. If you use the same custom path regularly, update the default in the script to avoid passing it every time.

---

### 2. Add your apps

Create one subfolder per app under `\apps` and place the installer inside it:

```
C:\packaging\
├── IntuneWinAppUtil.exe
├── apps\
│   ├── 7-Zip\
│   │   └── 7z2600-x64.msi
│   ├── Chrome\
│   │   └── googlechrome.msi
│   └── MyApp\
│       └── Install-MyApp.ps1
└── output\
```

---

### 3. Package

```powershell
# Default path
.\Invoke-IntunePackaging.ps1

# Custom path
.\Invoke-IntunePackaging.ps1 -PackagingRoot "D:\packaging\Contoso"
```

`.intunewin` files are written to `\output`.

---

## Setup File Detection

The script picks the installer automatically. Uninstall files (`uninstall`, `remove`, `cleanup`, `uninst`) are always excluded first, then it works through the following in order:

| Priority | Rule | Example |
|----------|------|---------|
| 1 | Filename matches folder name exactly | Folder: `Chrome` → `Chrome.msi` |
| 2 | Filename contains the folder name | `Install-Chrome.ps1` |
| 3 | Filename contains `install` | `Install-App.ps1` |
| 4 | Filename contains `setup` | `setup.exe` |
| 5 | Only one installer file in the folder | any single `.msi` / `.exe` / `.bat` / `.ps1` |

Extension priority order is `.msi` → `.exe` → `.bat` → `.ps1`. To change this, update the following line in the script:

```powershell
$SetupExtensions = @("*.msi", "*.exe", "*.bat", "*.ps1")
```

If the script cannot determine the setup file it will tell you which files it found and what to rename them to.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Script fails immediately | Run PowerShell as Administrator |
| `IntuneWinAppUtil.exe` not found | Run `-Setup` first |
| App skipped — no setup file found | Add an installer to the app subfolder |
| App skipped — ambiguous files | Rename the intended installer to include `install`, `setup`, or the folder name |
| Wrong output path | Ensure `-PackagingRoot` matches the path used during `-Setup` |

