# Intune Scripts

| Script | What it does |
|--------|--------------|
| [`Invoke-IntunePackaging-v0.1.ps1`](#invoke-intunepackaging) | Automates Intune Win32 app packaging |
| [`Sync-IntuneEnrolmentTimeGroups.ps1`](#sync-intuneenrolmenttimegroups) | Audits and fixes enrolment time grouping membership |

---

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

---
---

# Sync-IntuneEnrolmentTimeGroups

Enrolment time grouping (ETG) puts a device into an Entra ID security group the moment it
enrols, so targeted policies and apps land before the user reaches the desktop. When it
misfires — a group added after devices had already enrolled, a transient failure during
provisioning, devices moved between profiles — you get devices running the profile but
missing from its group.

This script finds every enrolment profile that has a group attached, works out which
enrolled devices belong to each one, and reports (or fixes) the devices that are not in
the group.

## Requirements

- PowerShell 5.1 or 7+
- No modules — sign-in uses the OAuth 2.0 device code flow directly
- Delegated permissions:

| Permission | Used for |
|------------|----------|
| `DeviceManagementConfiguration.Read.All` | Enrolment policies and their ETG targets |
| `DeviceManagementServiceConfig.Read.All` | ADE tokens, Apple and Android enrolment profiles |
| `DeviceManagementManagedDevices.Read.All` | Enrolled devices and Autopilot deployment events |
| `Device.Read.All` | Resolving a managed device to its Entra device object |
| `GroupMember.ReadWrite.All` | Reading and writing group membership |

---

## Quick Start

```powershell
# 1. Report only — nothing is changed
.\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com

# 2. Fix, confirming each device before it is added
.\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -Remediate

# 3. Fix everything without prompting, and export the full result set
.\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -Remediate -Force -ReportPath .\etg.csv
```

Sign-in prints a code and a URL — open it, sign in as an admin, and the script continues.

---

## What it covers

| Profile type | Graph source | Where the group comes from |
|--------------|--------------|----------------------------|
| Autopilot device preparation | `deviceManagement/configurationPolicies` | `retrieveEnrollmentTimeDeviceMembershipTarget`, plus the `enrollment_autopilot_dpp_devicegroup` policy setting |
| Apple enrolment policies (new ADE experience) | `deviceManagement/configurationPolicies` | `retrieveEnrollmentTimeDeviceMembershipTarget` |
| Apple ADE profiles (classic) | `deviceManagement/depOnboardingSettings/{id}/enrollmentProfiles` | `enrollmentTimeAzureAdGroupIds` |
| Android Enterprise | `deviceManagement/androidDeviceOwnerEnrollmentProfiles` | `retrieveEnrollmentTimeDeviceMembershipTarget` |

Devices are matched to a profile on `managedDevice.enrollmentProfileName`. Autopilot
device preparation is matched additionally through `deviceManagement/autopilotEvents`
(`windowsAutopilotDeploymentProfileDisplayName`), because device preparation deployments
do not always stamp `enrollmentProfileName` onto the managed device.

Membership is added with `POST /groups/{id}/members/$ref`, using the device's Entra
directory object ID resolved from `managedDevice.azureADDeviceId`.

---

## Parameters

| Parameter | Purpose |
|-----------|---------|
| `-TenantId` | Tenant GUID or domain. Required unless `-AccessToken` is used |
| `-ClientId` | Public client app for sign-in. Defaults to Microsoft Graph Command Line Tools |
| `-AccessToken` | Use a token you already hold and skip the device code prompt |
| `-ProfileType` | `All` (default), `AutopilotDevicePreparation`, `AppleEnrolment`, `AndroidEnterprise` |
| `-ProfileName` | Wildcard filter on the profile name, e.g. `"UK-*"` |
| `-Remediate` | Add the missing devices. Without it the script only reports |
| `-Force` | Skip the per-device confirmation prompt |
| `-ReportPath` | Export the full result set to CSV |
| `-SkipAutopilotEvents` | Skip the Autopilot events query |
| `-WhatIf` | Show what would be added without adding it |

The script also returns the result objects to the pipeline, so you can filter them
yourself:

```powershell
$r = .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com
$r | Where-Object Status -eq 'Missing' | Group-Object GroupName
```

---

## Result statuses

| Status | Meaning |
|--------|---------|
| `Compliant` | Device is already in the group |
| `Missing` | Device should be in the group and can be added |
| `Added` | Device was added during remediation |
| `Skipped` | Add was declined at the confirmation prompt, or `-WhatIf` was used |
| `Failed` | The add call was rejected — see `Detail` |
| `MissingDynamicGroup` | Device is missing, but the group is dynamic so the rule owns membership |
| `NoEntraDevice` | No Entra device object for the managed device, so it cannot be added |

---

## Notes

- Enrolment time groups must be **assigned (static) security groups**. Dynamic groups are
  reported but never modified — fix the membership rule instead.
- A group whose membership cannot be read is skipped with a warning rather than having
  every device reported as missing.
- The Intune `/beta` endpoints are used where the enrolment time grouping APIs only exist
  in beta. Microsoft can change those without notice.
- Throttling (HTTP 429) and transient 5xx responses are retried with `Retry-After`.

