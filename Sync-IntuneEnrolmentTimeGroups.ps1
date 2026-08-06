#Requires -Version 5.1
<#
.SYNOPSIS
    Audits and remediates Intune enrolment time grouping (ETG) membership.

.DESCRIPTION
    Finds every enrolment profile/policy in Intune that has enrolment time grouping
    configured, captures the Entra ID security groups attached to each one, finds the
    enrolled devices that carry that profile name, and reports any device that is not
    a member of the group it should be in. Optionally adds the missing devices.

    Profile types covered:

      Autopilot device preparation   deviceManagement/configurationPolicies
                                     (templateFamily = enrollmentConfiguration, Windows)
                                     Group read from retrieveEnrollmentTimeDeviceMembershipTarget
                                     and from the enrollment_autopilot_dpp_devicegroup setting.

      Apple enrolment (ADE)          deviceManagement/depOnboardingSettings/{id}/enrollmentProfiles
                                     Group read from enrollmentTimeAzureAdGroupIds.
                                     Plus the newer Apple "enrolment policies" which are
                                     settings catalog objects under configurationPolicies.

      Android Enterprise             deviceManagement/androidDeviceOwnerEnrollmentProfiles
                                     Group read from retrieveEnrollmentTimeDeviceMembershipTarget.

    Device matching:

      Apple / Android profiles use managedDevice.enrollmentProfileName.
      Autopilot device preparation additionally uses deviceManagement/autopilotEvents,
      matching windowsAutopilotDeploymentProfileDisplayName, because device preparation
      deployments do not always stamp enrollmentProfileName on the managed device.

    Runs on Windows PowerShell 5.1 and PowerShell 7+. No modules required — delegated
    authentication uses the OAuth 2.0 device code flow directly against Microsoft Entra ID.

.PARAMETER TenantId
    Tenant GUID or domain name (e.g. contoso.onmicrosoft.com). Required unless -AccessToken
    is supplied.

.PARAMETER ClientId
    Application (client) ID of the public client app used for the device code sign-in.
    Defaults to the well-known "Microsoft Graph Command Line Tools" app.
    Supply your own app registration if that app is blocked in your tenant.

.PARAMETER AccessToken
    Use an access token you already hold instead of signing in (e.g. from
    (Get-MgContext) based tooling). Skips the device code prompt. Note that a token
    supplied this way is not refreshed, so long runs may expire.

.PARAMETER ProfileType
    Which enrolment profile types to process. One or more of:
    All, AutopilotDevicePreparation, AppleEnrolment, AndroidEnterprise.
    Defaults to All.

.PARAMETER ProfileName
    Optional wildcard filter on the profile/policy display name, e.g. "UK-*".

.PARAMETER Remediate
    Add the missing devices to their enrolment time groups. Without this switch the
    script only reports. Each add is confirmed before it happens unless -Force is used.

.PARAMETER Force
    Suppress the per-device confirmation prompt when remediating.

.PARAMETER ReportPath
    Optional path to a .csv file. The full result set (compliant and non-compliant) is
    exported there.

.PARAMETER SkipAutopilotEvents
    Do not query deviceManagement/autopilotEvents. Autopilot device preparation devices
    will then only be matched on managedDevice.enrollmentProfileName.

.PARAMETER Diagnose
    Print what every enrolment time grouping call actually returned, including the calls
    that are otherwise swallowed. Use this when profiles are found but no groups are.

.PARAMETER GroupMap
    Map profile names to enrolment time group object IDs by hand, for when the group is
    set in the portal but Graph will not return it. Keys are matched with -like, so
    exact names and wildcards both work. Mapped groups are merged with any the script
    discovered on its own.

        -GroupMap @{ 'DP_Cope' = 'aaaa-...'; 'IOS_*' = @('bbbb-...','cccc-...') }

.PARAMETER GraphScopes
    Override the delegated permission scopes requested at sign-in.

.EXAMPLE
    .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com
    Report only. Shows every enrolment profile with a group and every device missing from it.

.EXAMPLE
    .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -Remediate
    Report, then prompt for each missing device before adding it to the group.

.EXAMPLE
    .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -Remediate -Force -ReportPath .\etg.csv
    Add all missing devices without prompting and export the full result set.

.EXAMPLE
    .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -ProfileType AppleEnrolment -WhatIf
    Apple enrolment profiles only, showing what would be changed.

.EXAMPLE
    .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -Remediate ``
        -GroupMap @{ 'DP_Cope' = '11111111-2222-3333-4444-555555555555' }
    Supply the group by hand when the tenant will not return it, then remediate normally.

.EXAMPLE
    .\Sync-IntuneEnrolmentTimeGroups.ps1 -TenantId contoso.onmicrosoft.com -Diagnose
    Show the raw result of every enrolment time grouping call. Use this when you know a
    profile has a group but the script reports none.

.NOTES
    Delegated permissions required:
        DeviceManagementConfiguration.Read.All     enrolment policies + ETG targets
        DeviceManagementServiceConfig.Read.All     DEP tokens and Apple/Android profiles
        DeviceManagementManagedDevices.Read.All    enrolled devices and Autopilot events
        Device.Read.All                            resolve managed device -> Entra device object
        GroupMember.ReadWrite.All                  read and write group membership

    Enrolment time groups must be assigned (static) security groups. Dynamic groups are
    reported and skipped — membership there is owned by the membership rule.

    The Intune /beta endpoints are used where the enrolment time grouping APIs only exist
    in beta. Microsoft may change those without notice.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e',   # Microsoft Graph Command Line Tools

    [Parameter()]
    [string]$AccessToken,

    [Parameter()]
    [ValidateSet('All', 'AutopilotDevicePreparation', 'AppleEnrolment', 'AndroidEnterprise')]
    [string[]]$ProfileType = @('All'),

    [Parameter()]
    [string]$ProfileName = '*',

    [Parameter()]
    [switch]$Remediate,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [switch]$SkipAutopilotEvents,

    [Parameter()]
    [switch]$Diagnose,

    [Parameter()]
    [hashtable]$GroupMap,

    [Parameter()]
    [string[]]$GraphScopes = @(
        'https://graph.microsoft.com/DeviceManagementConfiguration.Read.All'
        'https://graph.microsoft.com/DeviceManagementServiceConfig.Read.All'
        'https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All'
        'https://graph.microsoft.com/Device.Read.All'
        'https://graph.microsoft.com/GroupMember.ReadWrite.All'
        'offline_access'
    )
)

# ============================================================
#  Shared config
# ============================================================
$ScriptVersion = '1.3.0'

$GraphBeta   = 'https://graph.microsoft.com/beta'
$GraphV1     = 'https://graph.microsoft.com/v1.0'
$Authority   = 'https://login.microsoftonline.com'

# Windows PowerShell 5.1 still defaults to TLS 1.0/1.1 on some hosts, which Entra ID
# and Graph both reject. PowerShell 7 negotiates this itself.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# Setting definition IDs that hold an enrolment time group inside a settings catalog
# enrolment policy. Matched loosely so new/renamed variants are still picked up.
$DeviceGroupSettingPattern = '(?i)(devicegroup|device_group|devicemembership)'

# Caches — populated on demand, keyed lookups only.
# The Cache suffix matters: PowerShell variable names are case-insensitive, so a bare
# $script:EntraDevice would be the same variable as a local $entraDevice in the main body.
$script:TokenCache       = $null
$script:LastGraphError   = $null   # last error swallowed by a -Quiet Graph call
$script:EntraDeviceCache = @{}   # Entra deviceId (GUID) -> Entra device object
$script:GroupInfoCache   = @{}   # group object id       -> group object
$script:GroupMemberCache = @{}   # group object id       -> hashtable of member deviceId -> object id
$script:EtgEndpointCache = @{}   # collection name       -> the ETG endpoint variant that answered

# ============================================================
#  Output helpers
# ============================================================
function Write-Header {
    param([string]$Text)
    $line = "=" * 70
    Write-Host ""
    Write-Host $line     -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line     -ForegroundColor Cyan
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

function Write-Info {
    param([string]$Text)
    Write-Host "     $Text" -ForegroundColor DarkGray
}

function Write-Diag {
    # Only speaks under -Diagnose. Used to show exactly what Graph returned for each
    # enrolment time grouping probe, including calls that are otherwise swallowed.
    param([string]$Text)
    if ($Diagnose) { Write-Host "  ?? $Text" -ForegroundColor DarkCyan }
}

# ============================================================
#  Authentication — OAuth 2.0 device code flow (delegated)
# ============================================================
function Get-HttpStatusCode {
    # Status code extraction differs between the PS 5.1 (WebException) and
    # PS 7 (HttpResponseMessage) error records.
    param($ErrorRecord)

    $response = $null
    if ($ErrorRecord.Exception.PSObject.Properties.Name -contains 'Response') {
        $response = $ErrorRecord.Exception.Response
    }
    if (-not $response) { return $null }

    if ($response.StatusCode -is [int]) { return [int]$response.StatusCode }

    try   { return [int]$response.StatusCode }
    catch { return $null }
}

function Get-HttpRetryAfter {
    param($ErrorRecord)

    $response = $null
    if ($ErrorRecord.Exception.PSObject.Properties.Name -contains 'Response') {
        $response = $ErrorRecord.Exception.Response
    }
    if (-not $response) { return $null }

    try {
        # PowerShell 7 / HttpClient
        if ($response.Headers -and $response.Headers.PSObject.Properties.Name -contains 'RetryAfter') {
            if ($response.Headers.RetryAfter -and $response.Headers.RetryAfter.Delta) {
                return [int]$response.Headers.RetryAfter.Delta.TotalSeconds
            }
        }
        # Windows PowerShell 5.1 / WebResponse
        $raw = $response.Headers['Retry-After']
        if ($raw) { return [int]$raw }
    } catch { }

    return $null
}

function Get-ErrorBody {
    param($ErrorRecord)

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        try   { return ($ErrorRecord.ErrorDetails.Message | ConvertFrom-Json) }
        catch { return $ErrorRecord.ErrorDetails.Message }
    }
    return $null
}

function Connect-GraphDelegated {
    <#
        Signs in with the device code flow and caches the resulting tokens in
        $script:TokenCache. Works headless and needs no modules, so it behaves the same
        on Windows PowerShell 5.1 and PowerShell 7.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string[]]$Scopes
    )

    $scopeString = ($Scopes -join ' ')

    Write-Step "Requesting device code for tenant $TenantId"

    $codeRequest = @{
        Uri         = "$Authority/$TenantId/oauth2/v2.0/devicecode"
        Method      = 'POST'
        Body        = @{ client_id = $ClientId; scope = $scopeString }
        ContentType = 'application/x-www-form-urlencoded'
    }

    try {
        $codeResponse = Invoke-RestMethod @codeRequest
    } catch {
        $body = Get-ErrorBody $_
        throw "Device code request failed: $(if ($body.error_description) { $body.error_description } else { $_.Exception.Message })"
    }

    Write-Host ""
    Write-Host "  $($codeResponse.message)" -ForegroundColor White
    Write-Host ""

    $interval = 5
    if ($codeResponse.interval) { $interval = [int]$codeResponse.interval }
    $deadline = (Get-Date).AddSeconds([int]$codeResponse.expires_in)

    $tokenBody = @{
        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
        client_id   = $ClientId
        device_code = $codeResponse.device_code
    }

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $tokenResponse = Invoke-RestMethod -Uri "$Authority/$TenantId/oauth2/v2.0/token" `
                                               -Method POST -Body $tokenBody `
                                               -ContentType 'application/x-www-form-urlencoded'

            $script:TokenCache = [PSCustomObject]@{
                AccessToken  = $tokenResponse.access_token
                RefreshToken = $tokenResponse.refresh_token
                ExpiresOn    = (Get-Date).AddSeconds([int]$tokenResponse.expires_in)
                TenantId     = $TenantId
                ClientId     = $ClientId
                Scopes       = $Scopes
            }

            Write-OK "Signed in successfully."
            return
        } catch {
            # if/elseif rather than switch — break/continue behave differently inside
            # a switch that sits in a loop.
            $body    = Get-ErrorBody $_
            $errCode = [string]$body.error

            if ($errCode -eq 'authorization_pending') {
                continue
            } elseif ($errCode -eq 'slow_down') {
                $interval += 5
                continue
            } elseif ($errCode -eq 'expired_token') {
                throw "Device code expired before sign-in completed."
            } elseif ($errCode -eq 'authorization_declined') {
                throw "Sign-in was declined in the browser."
            } else {
                $msg = if ($body.error_description) { $body.error_description } else { $_.Exception.Message }
                throw "Token request failed: $msg"
            }
        }
    }

    throw "Timed out waiting for device code sign-in."
}

function Get-GraphToken {
    <#
        Returns a valid bearer token, refreshing silently when it is close to expiry.
    #>
    if (-not $script:TokenCache) { throw "Not connected. Call Connect-GraphDelegated first." }

    # A token supplied by the caller has no refresh token — hand it back as-is.
    if (-not $script:TokenCache.RefreshToken) { return $script:TokenCache.AccessToken }

    if ((Get-Date) -lt $script:TokenCache.ExpiresOn.AddMinutes(-5)) {
        return $script:TokenCache.AccessToken
    }

    Write-Info "Access token expiring — refreshing."

    $refreshBody = @{
        grant_type    = 'refresh_token'
        client_id     = $script:TokenCache.ClientId
        refresh_token = $script:TokenCache.RefreshToken
        scope         = ($script:TokenCache.Scopes -join ' ')
    }

    $refreshed = Invoke-RestMethod -Uri "$Authority/$($script:TokenCache.TenantId)/oauth2/v2.0/token" `
                                   -Method POST -Body $refreshBody `
                                   -ContentType 'application/x-www-form-urlencoded'

    $script:TokenCache.AccessToken = $refreshed.access_token
    $script:TokenCache.ExpiresOn   = (Get-Date).AddSeconds([int]$refreshed.expires_in)
    if ($refreshed.refresh_token) { $script:TokenCache.RefreshToken = $refreshed.refresh_token }

    return $script:TokenCache.AccessToken
}

# ============================================================
#  Graph request wrapper
# ============================================================
function Invoke-GraphApi {
    <#
        Single entry point for every Graph call.
          -All          follows @odata.nextLink and returns the flattened .value collection
          -Quiet        returns $null on failure instead of throwing (for optional endpoints)
        Handles 429/503 throttling with Retry-After and retries transient failures.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method = 'GET',
        [object]$Body,
        [switch]$All,
        [switch]$Quiet,
        [int]$MaxRetries = 5
    )

    if ($Uri -notmatch '^https?://') { $Uri = "$GraphBeta/$($Uri.TrimStart('/'))" }

    $results  = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    while ($nextLink) {

        $attempt  = 0
        $response = $null

        while ($true) {
            $attempt++
            try {
                $params = @{
                    Uri         = $nextLink
                    Method      = $Method
                    Headers     = @{
                        Authorization = "Bearer $(Get-GraphToken)"
                        Accept        = 'application/json'
                    }
                    ErrorAction = 'Stop'
                }
                if ($null -ne $Body) {
                    $params.Body        = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
                    $params.ContentType = 'application/json'
                }

                $response = Invoke-RestMethod @params
                break
            } catch {
                $status     = Get-HttpStatusCode $_
                $retryAfter = Get-HttpRetryAfter $_

                if (($status -eq 429 -or $status -ge 500) -and $attempt -le $MaxRetries) {
                    $wait = if ($retryAfter) { $retryAfter } else { [Math]::Min(60, [Math]::Pow(2, $attempt)) }
                    Write-Info "HTTP $status from Graph — retrying in $wait second(s) (attempt $attempt/$MaxRetries)."
                    Start-Sleep -Seconds $wait
                    continue
                }

                $body    = Get-ErrorBody $_
                $message = if ($body.error.message) { $body.error.message } else { $_.Exception.Message }

                # Recorded so -Quiet callers can still explain themselves under -Diagnose
                $script:LastGraphError = [PSCustomObject]@{
                    Method  = $Method
                    Uri     = $nextLink
                    Status  = $status
                    Message = $message
                    Raw     = if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $null }
                }

                if ($Quiet) { return $null }

                throw "Graph $Method $nextLink failed (HTTP $status): $message"
            }
        }

        if (-not $All) { return $response }

        if ($response.value) { foreach ($item in $response.value) { $results.Add($item) } }
        $nextLink = $response.'@odata.nextLink'
    }

    # Comma-wrapped so an empty-but-successful collection stays a collection instead of
    # unrolling to nothing. Callers using -Quiet rely on $null meaning "the call failed".
    return ,$results
}

# ============================================================
#  Enrolment profile discovery
# ============================================================
function Get-TargetIdFromObject {
    <#
        Walks any object graph and returns every GUID held in a property called targetId
        (or groupId / enrollmentTimeAzureAdGroupIds).

        The retrieve action has shipped more than one response shape — the group has
        appeared under enrollmentTimeDeviceMembershipTargetValidationStatuses, under
        enrollmentTimeDeviceMembershipTargets, and sometimes unwrapped. Harvesting by
        property name rather than by path means a shape change does not silently
        produce "no groups".
    #>
    param($Node, [int]$Depth = 0)

    $found = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Node -or $Depth -gt 12) { return $found }

    # Strings are IEnumerable, so they have to be ruled out before the collection branch
    if ($Node -is [string] -or $Node -is [ValueType]) { return $found }

    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($item in $Node) {
            foreach ($v in (Get-TargetIdFromObject -Node $item -Depth ($Depth + 1))) { $found.Add($v) }
        }
        return $found
    }

    foreach ($property in $Node.PSObject.Properties) {
        if ($property.Name -match '(?i)^(targetId|groupId|enrollmentTimeAzureAdGroupIds)$') {
            # Matched on property name, so any non-empty value is taken as-is rather than
            # being held to a GUID shape. A value that is not a real group is caught later
            # by the group lookup, which says so — better than dropping it silently here.
            foreach ($candidate in @($property.Value)) {
                if ($candidate -is [string] -and $candidate.Trim()) { $found.Add($candidate.Trim()) }
            }
        } elseif ($property.Value) {
            foreach ($v in (Get-TargetIdFromObject -Node $property.Value -Depth ($Depth + 1))) { $found.Add($v) }
        }
    }

    return $found
}

function Get-EtgTarget {
    <#
        Returns the enrolment time group object IDs configured against a resource.

        The documented call is
            POST /deviceManagement/configurationPolicies/{id}/retrieveEnrollmentTimeDeviceMembershipTarget
            POST /deviceManagement/androidDeviceOwnerEnrollmentProfiles/{id}/retrieveEnrollmentTimeDeviceMembershipTarget

        but tenants have been seen rejecting it with
            "No OData route exists that match template ~/singleton/navigation/key/action
             with http verb POST"
        which says the action is in the model but no route is registered for that verb
        and shape. Rather than assume one form, the plausible variants are probed in
        order and the first that answers is cached per collection, so the cost is paid
        once and every later profile uses the variant this tenant actually serves.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ResourceUri,
        [Parameter(Mandatory = $true)][string]$CollectionKey,
        [string]$Label = ''
    )

    $groupIds = [System.Collections.Generic.List[string]]::new()

    $candidates = @(
        # GET first. The documented verb is POST, but live tenants serve this over GET and
        # reject POST outright, so trying GET first avoids two doomed calls per collection.
        [PSCustomObject]@{ Method = 'GET';  Segment = 'retrieveEnrollmentTimeDeviceMembershipTarget';                 Body = $null; Expand = $null; RequireHit = $false }
        [PSCustomObject]@{ Method = 'POST'; Segment = 'retrieveEnrollmentTimeDeviceMembershipTarget';                 Body = '{}';  Expand = $null; RequireHit = $false }
        [PSCustomObject]@{ Method = 'POST'; Segment = 'retrieveEnrollmentTimeDeviceMembershipTarget';                 Body = $null; Expand = $null; RequireHit = $false }
        [PSCustomObject]@{ Method = 'POST'; Segment = 'microsoft.graph.retrieveEnrollmentTimeDeviceMembershipTarget'; Body = '{}';  Expand = $null; RequireHit = $false }
        [PSCustomObject]@{ Method = 'GET';  Segment = 'getEnrollmentTimeDeviceMembershipTarget';                      Body = $null; Expand = $null; RequireHit = $false }
        [PSCustomObject]@{ Method = 'POST'; Segment = 'getEnrollmentTimeDeviceMembershipTarget';                      Body = '{}';  Expand = $null; RequireHit = $false }
        [PSCustomObject]@{ Method = 'GET';  Segment = 'enrollmentTimeDeviceMembershipTarget';                         Body = $null; Expand = $null; RequireHit = $false }
        # Last resort. A GET of the resource itself always succeeds, so this variant only
        # counts as the winner if the expand actually produced a group.
        [PSCustomObject]@{ Method = 'GET';  Segment = $null; Expand = 'enrollmentTimeDeviceMembershipTarget';         Body = $null; RequireHit = $true }
    )

    if ($script:EtgEndpointCache.ContainsKey($CollectionKey)) {
        $known = $script:EtgEndpointCache[$CollectionKey]
        if ($null -eq $known) { return $groupIds }   # already established that nothing answers here
        $candidates = @($known)
    }

    foreach ($candidate in $candidates) {

        $uri = if ($candidate.Expand) {
            "$ResourceUri`?`$expand=$($candidate.Expand)"
        } else {
            "$ResourceUri/$($candidate.Segment)"
        }
        $describe = "$($candidate.Method) $(if ($candidate.Expand) { "?`$expand=$($candidate.Expand)" } else { $candidate.Segment })"

        $script:LastGraphError = $null
        $result = Invoke-GraphApi -Uri $uri -Method $candidate.Method -Body $candidate.Body -Quiet

        if ($null -eq $result) {
            Write-Diag "$Label $describe -> HTTP $($script:LastGraphError.Status) $($script:LastGraphError.Message)"
            continue
        }

        $hits = [System.Collections.Generic.List[string]]::new()
        foreach ($id in (Get-TargetIdFromObject -Node $result)) {
            if ($hits -notcontains $id) { $hits.Add($id) }
        }

        if ($candidate.RequireHit -and $hits.Count -eq 0) {
            Write-Diag "$Label $describe -> answered but produced no group, not treating it as the endpoint."
            continue
        }

        Write-Diag "$Label $describe -> $($result | ConvertTo-Json -Depth 10 -Compress)"

        if (-not $script:EtgEndpointCache.ContainsKey($CollectionKey)) {
            $script:EtgEndpointCache[$CollectionKey] = $candidate
            Write-Info "Enrolment time grouping on $CollectionKey is served by: $describe"
        }

        return $hits
    }

    if (-not $script:EtgEndpointCache.ContainsKey($CollectionKey)) {
        $script:EtgEndpointCache[$CollectionKey] = $null
        Write-Warn "No enrolment time grouping endpoint on $CollectionKey answered in this tenant."
        Write-Info "Run with -Diagnose to see each attempt, or supply -GroupMap to map profiles to groups by hand."
    }

    return $groupIds
}

function Get-GuidValueFromSetting {
    <#
        Walks a settings catalog settingInstance tree and returns every GUID held by a
        setting whose definition ID looks like a device group setting — this is where
        Autopilot device preparation keeps its group
        (enrollment_autopilot_dpp_devicegroup).
    #>
    param(
        # Deliberately not mandatory — the walk recurses into branches that may be absent,
        # and @($null) still yields a single $null element to iterate over.
        [Parameter()]$Instance,
        [switch]$InsideDeviceGroup
    )

    $found = [System.Collections.Generic.List[string]]::new()
    if (-not $Instance) { return $found }

    $isDeviceGroup = $InsideDeviceGroup.IsPresent
    if ($Instance.settingDefinitionId -and $Instance.settingDefinitionId -match $DeviceGroupSettingPattern) {
        $isDeviceGroup = $true
    }

    if ($isDeviceGroup) {
        foreach ($value in @($Instance.simpleSettingCollectionValue)) {
            if ($value.value -match '^[0-9a-fA-F-]{36}$') { $found.Add([string]$value.value) }
        }
        if ($Instance.simpleSettingValue -and $Instance.simpleSettingValue.value -match '^[0-9a-fA-F-]{36}$') {
            $found.Add([string]$Instance.simpleSettingValue.value)
        }
    }

    # Recurse through the nested shapes the settings catalog uses
    foreach ($child in @($Instance.choiceSettingValue.children)) {
        foreach ($g in (Get-GuidValueFromSetting -Instance $child)) { $found.Add($g) }
    }
    foreach ($choice in @($Instance.choiceSettingCollectionValue)) {
        foreach ($child in @($choice.children)) {
            foreach ($g in (Get-GuidValueFromSetting -Instance $child)) { $found.Add($g) }
        }
    }
    foreach ($group in @($Instance.groupSettingCollectionValue)) {
        foreach ($child in @($group.children)) {
            foreach ($g in (Get-GuidValueFromSetting -Instance $child -InsideDeviceGroup:$isDeviceGroup) ) { $found.Add($g) }
        }
    }

    return $found
}

function Get-EnrolmentPolicyGroup {
    <#
        Settings catalog enrolment policies — Autopilot device preparation and the newer
        Apple ADE enrolment policies both live here.

        GET  /deviceManagement/configurationPolicies
        GET  /deviceManagement/configurationPolicies('{id}')/settings
    #>

    Write-Step "Reading enrolment policies from deviceManagement/configurationPolicies"

    $policies = Invoke-GraphApi -All -Uri "$GraphBeta/deviceManagement/configurationPolicies?`$select=id,name,description,platforms,technologies,templateReference"

    $enrolmentPolicies = $policies | Where-Object {
        $_.templateReference.templateFamily -eq 'enrollmentConfiguration' -or
        ($_.technologies -and $_.technologies -match 'enrollment')
    }

    Write-Info "$(@($enrolmentPolicies).Count) enrolment policy object(s) found."

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $enrolmentPolicies) {

        $groupIds = [System.Collections.Generic.List[string]]::new()
        $label    = "[policy '$($policy.name)']"

        Write-Diag "$label id=$($policy.id) platforms=$($policy.platforms) technologies=$($policy.technologies) templateFamily=$($policy.templateReference.templateFamily)"

        foreach ($id in (Get-EtgTarget -ResourceUri "$GraphBeta/deviceManagement/configurationPolicies('$($policy.id)')" -CollectionKey 'configurationPolicies' -Label $label)) {
            if ($groupIds -notcontains $id) { $groupIds.Add($id) }
        }

        # Autopilot device preparation stores its group as a policy setting as well
        $settings = Invoke-GraphApi -All -Quiet -Uri "$GraphBeta/deviceManagement/configurationPolicies('$($policy.id)')/settings"
        if ($null -eq $settings) {
            Write-Diag "$label settings could not be read: HTTP $($script:LastGraphError.Status) $($script:LastGraphError.Message)"
        }
        foreach ($setting in @($settings)) {
            # Full JSON, not just the definition ID — a group nested under an unrelated
            # parent setting would otherwise be invisible here.
            Write-Diag "$label setting $($setting.settingInstance.settingDefinitionId) :: $($setting.settingInstance | ConvertTo-Json -Depth 12 -Compress)"
            foreach ($id in (Get-GuidValueFromSetting -Instance $setting.settingInstance)) {
                if ($groupIds -notcontains $id) { $groupIds.Add($id) }
            }
        }

        if ($groupIds.Count -eq 0) { Write-Diag "$label no enrolment time group found." }

        $platform = [string]$policy.platforms
        $type = if ($platform -match '(?i)windows') {
            'AutopilotDevicePreparation'
        } elseif ($platform -match '(?i)ios|macos|apple|visionos|tvos') {
            'AppleEnrolment'
        } elseif ($platform -match '(?i)android') {
            'AndroidEnterprise'
        } else {
            'EnrolmentPolicy'
        }

        $output.Add([PSCustomObject]@{
            ProfileType = $type
            Source      = 'configurationPolicies'
            ProfileId   = $policy.id
            ProfileName = $policy.name
            Platform    = $platform
            GroupIds    = @($groupIds)
        })
    }

    return $output
}

function Get-AndroidEnrolmentProfileGroup {
    <#
        Android Enterprise corporate-owned enrolment profiles.

        GET  /deviceManagement/androidDeviceOwnerEnrollmentProfiles
        POST /deviceManagement/androidDeviceOwnerEnrollmentProfiles/{id}/retrieveEnrollmentTimeDeviceMembershipTarget
    #>

    Write-Step "Reading Android Enterprise enrolment profiles"

    $profiles = Invoke-GraphApi -All -Quiet -Uri "$GraphBeta/deviceManagement/androidDeviceOwnerEnrollmentProfiles?`$select=id,displayName,description,enrollmentMode"

    if ($null -eq $profiles) {
        Write-Warn "Android Enterprise enrolment profiles could not be read (is Android Enterprise connected?)."
        return @()
    }

    Write-Info "$(@($profiles).Count) Android enrolment profile(s) found."

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($enrolProfile in $profiles) {

        $label = "[android '$($enrolProfile.displayName)']"
        Write-Diag "$label id=$($enrolProfile.id) enrollmentMode=$($enrolProfile.enrollmentMode)"

        $groupIds = @(Get-EtgTarget -ResourceUri "$GraphBeta/deviceManagement/androidDeviceOwnerEnrollmentProfiles/$($enrolProfile.id)" -CollectionKey 'androidDeviceOwnerEnrollmentProfiles' -Label $label)

        $output.Add([PSCustomObject]@{
            ProfileType = 'AndroidEnterprise'
            Source      = 'androidDeviceOwnerEnrollmentProfiles'
            ProfileId   = $enrolProfile.id
            ProfileName = $enrolProfile.displayName
            Platform    = "android ($($enrolProfile.enrollmentMode))"
            GroupIds    = @($groupIds)
        })
    }

    return $output
}

function Get-AppleEnrolmentProfileGroup {
    <#
        Apple automated device enrolment profiles held against each ADE/DEP token.

        GET /deviceManagement/depOnboardingSettings
        GET /deviceManagement/depOnboardingSettings/{id}/enrollmentProfiles

        The enrolment time groups are on the derived depEnrollmentBaseProfile type as
        enrollmentTimeAzureAdGroupIds.
    #>

    Write-Step "Reading Apple enrolment (ADE) profiles"

    $tokens = Invoke-GraphApi -All -Quiet -Uri "$GraphBeta/deviceManagement/depOnboardingSettings?`$select=id,tokenName,appleIdentifier"

    if ($null -eq $tokens) {
        Write-Warn "Apple enrolment tokens could not be read (is an ADE token uploaded?)."
        return @()
    }

    Write-Info "$(@($tokens).Count) Apple enrolment token(s) found."

    $output = [System.Collections.Generic.List[object]]::new()

    foreach ($depToken in $tokens) {

        $profileUri = "$GraphBeta/deviceManagement/depOnboardingSettings/$($depToken.id)/enrollmentProfiles"
        $profiles   = Invoke-GraphApi -All -Quiet -Uri $profileUri

        if ($null -eq $profiles) {
            Write-Warn "Enrolment profiles for token '$($depToken.tokenName)' could not be read: HTTP $($script:LastGraphError.Status) $($script:LastGraphError.Message)"
            continue
        }

        Write-Info "$(@($profiles).Count) profile(s) under token '$($depToken.tokenName)'."

        foreach ($enrolProfile in $profiles) {

            $label = "[apple '$($enrolProfile.displayName)']"
            Write-Diag "$label id=$($enrolProfile.id) type=$($enrolProfile.'@odata.type')"
            Write-Diag "  $($enrolProfile | ConvertTo-Json -Depth 6 -Compress)"

            $groupIds = @($enrolProfile.enrollmentTimeAzureAdGroupIds)

            # The collection response can omit derived-type properties — re-read the
            # single profile before deciding there is no group.
            if (-not $groupIds -or $groupIds.Count -eq 0) {
                $full = Invoke-GraphApi -Quiet -Uri "$profileUri/$($enrolProfile.id)"
                if ($full) {
                    Write-Diag "$label single GET: $($full | ConvertTo-Json -Depth 6 -Compress)"
                    $groupIds = @($full.enrollmentTimeAzureAdGroupIds)
                } else {
                    Write-Diag "$label single GET failed: HTTP $($script:LastGraphError.Status) $($script:LastGraphError.Message)"
                }
            }

            # Classic ADE profiles are not documented as supporting the retrieve action,
            # but tenants moved onto the newer enrolment experience do answer it, so it is
            # worth a quiet attempt before giving up on the profile.
            $groupIds = @($groupIds | Where-Object { $_ })
            if ($groupIds.Count -eq 0) {
                $groupIds = @(Get-EtgTarget -ResourceUri "$profileUri/$($enrolProfile.id)" -CollectionKey 'depEnrollmentProfiles' -Label $label)
            }

            $groupIds = @($groupIds | Where-Object { $_ })
            if ($groupIds.Count -eq 0) { Write-Diag "$label no enrolment time group found." }

            $output.Add([PSCustomObject]@{
                ProfileType = 'AppleEnrolment'
                Source      = "depOnboardingSettings/$($depToken.tokenName)"
                ProfileId   = $enrolProfile.id
                ProfileName = $enrolProfile.displayName
                Platform    = 'apple (ADE)'
                GroupIds    = $groupIds
            })
        }
    }

    return $output
}

# ============================================================
#  Device discovery
# ============================================================
function Get-ManagedDeviceIndex {
    <#
        One pass over every enrolled device, indexed by enrolment profile name and by
        Entra device ID.

        GET /deviceManagement/managedDevices
    #>

    Write-Step "Reading enrolled devices from deviceManagement/managedDevices"

    $select = 'id,deviceName,azureADDeviceId,enrollmentProfileName,operatingSystem,managementAgent,deviceEnrollmentType,serialNumber,enrolledDateTime,ownerType'
    $devices = Invoke-GraphApi -All -Uri "$GraphBeta/deviceManagement/managedDevices?`$select=$select&`$top=1000"

    $byProfile = @{}
    $byAadId   = @{}

    foreach ($device in $devices) {
        if ($device.enrollmentProfileName) {
            $key = $device.enrollmentProfileName.ToLowerInvariant()
            if (-not $byProfile.ContainsKey($key)) {
                $byProfile[$key] = [System.Collections.Generic.List[object]]::new()
            }
            $byProfile[$key].Add($device)
        }
        if ($device.azureADDeviceId -and $device.azureADDeviceId -ne '00000000-0000-0000-0000-000000000000') {
            $byAadId[$device.azureADDeviceId.ToLowerInvariant()] = $device
        }
    }

    Write-Info "$(@($devices).Count) enrolled device(s), $($byProfile.Keys.Count) distinct enrolment profile name(s)."

    return [PSCustomObject]@{
        All       = $devices
        ByProfile = $byProfile
        ByAadId   = $byAadId
    }
}

function Get-AutopilotEventIndex {
    <#
        Autopilot deployment events, indexed by the profile name shown in the report.
        This is how Autopilot device preparation deployments are tied back to their
        policy, since managedDevice.enrollmentProfileName is not always populated
        for device preparation.

        GET /deviceManagement/autopilotEvents
    #>

    Write-Step "Reading Autopilot deployment events"

    $select = 'id,deviceId,managedDeviceName,deviceSerialNumber,windowsAutopilotDeploymentProfileDisplayName,enrollmentState,deploymentState,eventDateTime'
    $events = Invoke-GraphApi -All -Quiet -Uri "$GraphBeta/deviceManagement/autopilotEvents?`$select=$select"

    $byProfile = @{}

    if ($null -eq $events) {
        Write-Warn "Autopilot events could not be read — device preparation devices will be matched on enrolment profile name only."
        return $byProfile
    }

    foreach ($apEvent in $events) {
        $name = $apEvent.windowsAutopilotDeploymentProfileDisplayName
        if (-not $name) { continue }
        $key = $name.ToLowerInvariant()
        if (-not $byProfile.ContainsKey($key)) {
            $byProfile[$key] = [System.Collections.Generic.List[object]]::new()
        }
        $byProfile[$key].Add($apEvent)
    }

    Write-Info "$(@($events).Count) Autopilot event(s) across $($byProfile.Keys.Count) profile name(s)."

    return $byProfile
}

function Get-DeviceForProfile {
    <#
        Resolves the enrolled devices that carry a given enrolment profile name.
        Returns managedDevice objects, de-duplicated by managed device ID.
    #>
    param(
        [Parameter(Mandatory = $true)]$EnrolmentProfile,
        [Parameter(Mandatory = $true)]$DeviceIndex,
        [Parameter(Mandatory = $true)][hashtable]$AutopilotIndex
    )

    $matched = @{}
    $key     = $EnrolmentProfile.ProfileName.ToLowerInvariant()

    # Primary match — managedDevice.enrollmentProfileName
    if ($DeviceIndex.ByProfile.ContainsKey($key)) {
        foreach ($device in $DeviceIndex.ByProfile[$key]) { $matched[$device.id] = $device }
    }

    # Autopilot device preparation — match through the deployment event, then map the
    # Entra device ID back to the enrolled device.
    if ($EnrolmentProfile.ProfileType -eq 'AutopilotDevicePreparation' -and $AutopilotIndex.ContainsKey($key)) {
        foreach ($apEvent in $AutopilotIndex[$key]) {
            if (-not $apEvent.deviceId) { continue }
            $aadKey = $apEvent.deviceId.ToLowerInvariant()
            if ($DeviceIndex.ByAadId.ContainsKey($aadKey)) {
                $device = $DeviceIndex.ByAadId[$aadKey]
                $matched[$device.id] = $device
            }
        }
    }

    return $matched.Values
}

function Resolve-EntraDevice {
    <#
        Maps a managed device's Entra device ID (deviceId) to its directory object ID,
        which is what group membership actually uses.

        GET /devices?$filter=deviceId eq '{guid}'
    #>
    param([Parameter(Mandatory = $true)][string]$AzureAdDeviceId)

    $key = $AzureAdDeviceId.ToLowerInvariant()
    if ($script:EntraDeviceCache.ContainsKey($key)) { return $script:EntraDeviceCache[$key] }

    $result = Invoke-GraphApi -Quiet -Uri "$GraphV1/devices?`$filter=deviceId eq '$AzureAdDeviceId'&`$select=id,deviceId,displayName,accountEnabled"
    $device = $null
    if ($result -and $result.value) { $device = $result.value | Select-Object -First 1 }

    $script:EntraDeviceCache[$key] = $device
    return $device
}

# ============================================================
#  Group functions
# ============================================================
function Get-GroupInfo {
    <#
        GET /groups/{id}
    #>
    param([Parameter(Mandatory = $true)][string]$GroupId)

    if ($script:GroupInfoCache.ContainsKey($GroupId)) { return $script:GroupInfoCache[$GroupId] }

    $group = Invoke-GraphApi -Quiet -Uri "$GraphV1/groups/$GroupId`?`$select=id,displayName,groupTypes,securityEnabled,membershipRule,membershipRuleProcessingState"
    if ($group -and -not $group.id) { $group = $null }
    $script:GroupInfoCache[$GroupId] = $group
    return $group
}

function Get-GroupDeviceMember {
    <#
        Device members of a group, indexed by Entra device ID.

        GET /groups/{id}/members/microsoft.graph.device
    #>
    param([Parameter(Mandatory = $true)][string]$GroupId)

    if ($script:GroupMemberCache.ContainsKey($GroupId)) { return $script:GroupMemberCache[$GroupId] }

    $members = Invoke-GraphApi -All -Quiet -Uri "$GraphV1/groups/$GroupId/members/microsoft.graph.device?`$select=id,deviceId,displayName&`$top=999"

    # $null means the read failed. Returning an empty index there would report every
    # device as missing, so the caller is told to skip the group instead.
    if ($null -eq $members) { return $null }

    $index = @{}
    foreach ($member in @($members)) {
        if ($member.deviceId) { $index[$member.deviceId.ToLowerInvariant()] = $member.id }
    }

    $script:GroupMemberCache[$GroupId] = $index
    return $index
}

function Add-DeviceToGroup {
    <#
        POST /groups/{id}/members/$ref
    #>
    param(
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter(Mandatory = $true)][string]$DirectoryObjectId
    )

    $body = @{ '@odata.id' = "$GraphV1/directoryObjects/$DirectoryObjectId" }

    try {
        Invoke-GraphApi -Uri "$GraphV1/groups/$GroupId/members/`$ref" -Method POST -Body $body | Out-Null

        # Keep the cached membership in step so a device shared across profiles is not added twice
        if ($script:GroupMemberCache.ContainsKey($GroupId)) { $script:GroupMemberCache.Remove($GroupId) }
        return [PSCustomObject]@{ Success = $true; Message = 'Added' }
    } catch {
        # Graph returns 400 "already exist" when the object is already a member
        if ($_.Exception.Message -match 'already exist') {
            return [PSCustomObject]@{ Success = $true; Message = 'Already a member' }
        }
        return [PSCustomObject]@{ Success = $false; Message = $_.Exception.Message }
    }
}

# ============================================================
#  Main
# ============================================================
Write-Header "Intune Enrolment Time Grouping — Audit and Sync"
Write-Info "Script version $ScriptVersion on PowerShell $($PSVersionTable.PSVersion)"

# --- Connect ---------------------------------------------------------------
if ($AccessToken) {
    $script:TokenCache = [PSCustomObject]@{
        AccessToken  = $AccessToken
        RefreshToken = $null
        ExpiresOn    = (Get-Date).AddHours(1)
        TenantId     = $TenantId
        ClientId     = $ClientId
        Scopes       = $GraphScopes
    }
    Write-OK "Using the access token supplied by -AccessToken."
} else {
    if (-not $TenantId) {
        Write-Fail "-TenantId is required unless -AccessToken is supplied."
        exit 1
    }
    try {
        Connect-GraphDelegated -TenantId $TenantId -ClientId $ClientId -Scopes $GraphScopes
    } catch {
        Write-Fail "Sign-in failed — $_"
        exit 1
    }
}

# --- Collect the profiles that use enrolment time grouping -----------------
Write-Header "Enrolment profiles using enrolment time grouping"

$wanted = if ($ProfileType -contains 'All') {
    @('AutopilotDevicePreparation', 'AppleEnrolment', 'AndroidEnterprise')
} else {
    $ProfileType
}

$profiles = [System.Collections.Generic.List[object]]::new()

try {
    # configurationPolicies covers Autopilot device preparation and Apple enrolment policies,
    # so it is queried whenever either of those is in scope.
    if ($wanted -contains 'AutopilotDevicePreparation' -or $wanted -contains 'AppleEnrolment') {
        foreach ($p in (Get-EnrolmentPolicyGroup)) { $profiles.Add($p) }
    }
    if ($wanted -contains 'AndroidEnterprise') {
        foreach ($p in (Get-AndroidEnrolmentProfileGroup)) { $profiles.Add($p) }
    }
    if ($wanted -contains 'AppleEnrolment') {
        foreach ($p in (Get-AppleEnrolmentProfileGroup)) { $profiles.Add($p) }
    }
} catch {
    Write-Fail "Could not read enrolment profiles — $_"
    exit 1
}

# Drop anything the caller filtered out by type or name
$profiles = @($profiles | Where-Object {
    ($wanted -contains $_.ProfileType -or $_.ProfileType -eq 'EnrolmentPolicy') -and
    $_.ProfileName -like $ProfileName
})

$discovered = $profiles.Count

# -GroupMap fills in profiles whose group could not be read from Graph. Keys are matched
# with -like, so both exact names and patterns work. Mapped groups are merged with
# anything already discovered rather than replacing it.
if ($GroupMap) {
    foreach ($enrolProfile in $profiles) {
        foreach ($pattern in $GroupMap.Keys) {
            if ($enrolProfile.ProfileName -notlike $pattern) { continue }
            $merged = [System.Collections.Generic.List[string]]::new()
            foreach ($existing in @($enrolProfile.GroupIds)) { if ($existing) { $merged.Add([string]$existing) } }
            foreach ($mapped in @($GroupMap[$pattern])) {
                if ($mapped -and $merged -notcontains $mapped) { $merged.Add([string]$mapped) }
            }
            $enrolProfile.GroupIds = @($merged)
            $enrolProfile.Source   = "$($enrolProfile.Source) + GroupMap"
        }
    }
}

# Only profiles that ended up with at least one group can be checked
$profiles = @($profiles | Where-Object { @($_.GroupIds).Count -gt 0 })

if ($profiles.Count -eq 0) {
    Write-Host ""
    Write-Warn "No enrolment profiles with enrolment time grouping were found for the selected types."
    if ($discovered -gt 0) {
        Write-Info "$discovered profile(s) were found, but none reported a group."
        if (-not $Diagnose) {
            Write-Info "Re-run with -Diagnose to see what each enrolment time grouping call returned."
        }
        Write-Info "If the groups are set in the portal but Graph will not return them, map them by hand:"
        Write-Info "  -GroupMap @{ 'DP_Cope' = '<group object id>'; 'IOS_*' = @('<id1>','<id2>') }"
    }
    Write-Host ""
    exit 0
}

Write-Host ""
foreach ($enrolProfile in $profiles) {
    Write-Host "  $($enrolProfile.ProfileName)" -ForegroundColor White
    Write-Info "Type    : $($enrolProfile.ProfileType)  [$($enrolProfile.Platform)]"
    Write-Info "Source  : $($enrolProfile.Source)"
    foreach ($groupId in $enrolProfile.GroupIds) {
        $group = Get-GroupInfo -GroupId $groupId
        $label = if ($group) { $group.displayName } else { '<group not found>' }
        Write-Info "Group   : $label ($groupId)"
    }
}

# --- Devices ---------------------------------------------------------------
Write-Header "Enrolled devices"

$deviceIndex    = Get-ManagedDeviceIndex
$autopilotIndex = @{}

$needAutopilot = @($profiles | Where-Object { $_.ProfileType -eq 'AutopilotDevicePreparation' }).Count -gt 0
if ($needAutopilot -and -not $SkipAutopilotEvents) {
    $autopilotIndex = Get-AutopilotEventIndex
}

# --- Compare ---------------------------------------------------------------
Write-Header "Membership check"

$results   = [System.Collections.Generic.List[object]]::new()
$toAdd     = [System.Collections.Generic.List[object]]::new()

foreach ($enrolProfile in $profiles) {

    $devices = @(Get-DeviceForProfile -EnrolmentProfile $enrolProfile -DeviceIndex $deviceIndex -AutopilotIndex $autopilotIndex)

    Write-Host ""
    Write-Host "  $($enrolProfile.ProfileName)" -ForegroundColor White
    Write-Info "$($devices.Count) enrolled device(s) matched this profile."

    if ($devices.Count -eq 0) { continue }

    foreach ($groupId in $enrolProfile.GroupIds) {

        $group     = Get-GroupInfo -GroupId $groupId
        $groupName = if ($group) { $group.displayName } else { $groupId }

        if (-not $group) {
            Write-Warn "Group $groupId is referenced by the profile but does not exist — skipping."
            continue
        }

        $isDynamic = @($group.groupTypes) -contains 'DynamicMembership'
        if ($isDynamic) {
            Write-Warn "'$groupName' is a dynamic group — membership is set by its rule, so it is reported but not changed."
        }

        $members = Get-GroupDeviceMember -GroupId $groupId
        if ($null -eq $members) {
            Write-Warn "Membership of '$groupName' could not be read — skipping it rather than reporting every device as missing."
            continue
        }

        $missing = 0

        foreach ($device in $devices) {

            $status    = 'Compliant'
            $detail    = ''
            $objectId  = $null
            $entraId   = $device.azureADDeviceId

            if (-not $entraId -or $entraId -eq '00000000-0000-0000-0000-000000000000') {
                $status = 'NoEntraDevice'
                $detail = 'Managed device has no Entra device ID — cannot be added to a group.'
            }
            elseif ($members.ContainsKey($entraId.ToLowerInvariant())) {
                $objectId = $members[$entraId.ToLowerInvariant()]
            }
            else {
                $entraDevice = Resolve-EntraDevice -AzureAdDeviceId $entraId
                if (-not $entraDevice) {
                    $status = 'NoEntraDevice'
                    $detail = "No Entra device object found for deviceId $entraId."
                } else {
                    $objectId = $entraDevice.id
                    $missing++
                    if ($isDynamic) {
                        $status = 'MissingDynamicGroup'
                        $detail = 'Not a member, but the group is dynamic — fix the membership rule instead.'
                    } else {
                        $status = 'Missing'
                    }
                }
            }

            $record = [PSCustomObject]@{
                ProfileType     = $enrolProfile.ProfileType
                ProfileName     = $enrolProfile.ProfileName
                ProfileId       = $enrolProfile.ProfileId
                Platform        = $enrolProfile.Platform
                GroupName       = $groupName
                GroupId         = $groupId
                DeviceName      = $device.deviceName
                SerialNumber    = $device.serialNumber
                OperatingSystem = $device.operatingSystem
                ManagedDeviceId = $device.id
                EntraDeviceId   = $entraId
                EntraObjectId   = $objectId
                Status          = $status
                Detail          = $detail
            }

            $results.Add($record)
            if ($status -eq 'Missing') { $toAdd.Add($record) }
        }

        if ($missing -eq 0) {
            Write-OK "'$groupName' — all $($devices.Count) device(s) present."
        } else {
            Write-Warn "'$groupName' — $missing device(s) missing."
        }
    }
}

# --- Report ----------------------------------------------------------------
Write-Header "Summary"

$compliant = @($results | Where-Object { $_.Status -eq 'Compliant' }).Count
$noEntra   = @($results | Where-Object { $_.Status -eq 'NoEntraDevice' }).Count
$dynamic   = @($results | Where-Object { $_.Status -eq 'MissingDynamicGroup' }).Count

Write-Host "  Profiles with enrolment time grouping : $($profiles.Count)" -ForegroundColor White
Write-Host "  Device/group pairs checked            : $($results.Count)" -ForegroundColor White
Write-Host "  Already compliant                     : $compliant"        -ForegroundColor Green
Write-Host "  Missing (can be added)                : $($toAdd.Count)"   -ForegroundColor $(if ($toAdd.Count) { 'Magenta' } else { 'Green' })
if ($dynamic) { Write-Host "  Missing from a dynamic group          : $dynamic" -ForegroundColor Magenta }
if ($noEntra) { Write-Host "  No Entra device object                : $noEntra" -ForegroundColor Magenta }

if ($toAdd.Count -gt 0) {
    Write-Host ""
    Write-Host "  Devices missing from their enrolment time group:" -ForegroundColor Magenta
    # Out-String needs an explicit width — hosts without a console (scheduled tasks,
    # redirected output) render an empty table otherwise.
    $toAdd |
        Select-Object ProfileType, ProfileName, DeviceName, SerialNumber, GroupName |
        Format-Table -AutoSize |
        Out-String -Width 200 |
        Write-Host
}

if ($ReportPath) {
    try {
        $results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-OK "Report written to $ReportPath"
    } catch {
        Write-Fail "Could not write the report to $ReportPath — $_"
    }
}

# --- Remediate -------------------------------------------------------------
if (-not $Remediate) {
    if ($toAdd.Count -gt 0) {
        Write-Host ""
        Write-Info "Re-run with -Remediate to add these devices to their groups."
    }
    Write-Host ""
    return $results
}

if ($toAdd.Count -eq 0) {
    Write-Host ""
    Write-OK "Nothing to remediate."
    Write-Host ""
    return $results
}

Write-Header "Remediation"

if ($Force) { $ConfirmPreference = 'None' }

$added   = 0
$skipped = 0
$failed  = 0

foreach ($record in $toAdd) {

    $target = "$($record.DeviceName) ($($record.EntraDeviceId))"
    $action = "Add to enrolment time group '$($record.GroupName)'"

    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
        $record.Status = 'Skipped'
        $record.Detail = 'Not confirmed by the operator.'
        $skipped++
        continue
    }

    $result = Add-DeviceToGroup -GroupId $record.GroupId -DirectoryObjectId $record.EntraObjectId

    if ($result.Success) {
        $record.Status = 'Added'
        $record.Detail = $result.Message
        $added++
        Write-OK "$($record.DeviceName) -> $($record.GroupName)"
    } else {
        $record.Status = 'Failed'
        $record.Detail = $result.Message
        $failed++
        Write-Fail "$($record.DeviceName) -> $($record.GroupName) : $($result.Message)"
    }
}

Write-Host ""
Write-Host "  Added   : $added"   -ForegroundColor Green
if ($skipped) { Write-Host "  Skipped : $skipped" -ForegroundColor Magenta }
if ($failed)  { Write-Host "  Failed  : $failed"  -ForegroundColor Red }
Write-Host ""

if ($ReportPath) {
    try {
        $results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-OK "Report updated at $ReportPath"
    } catch {
        Write-Fail "Could not update the report at $ReportPath — $_"
    }
}

Write-Host ""
return $results
