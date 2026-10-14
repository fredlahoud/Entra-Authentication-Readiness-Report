#requires -Version 5.1

<#
.SYNOPSIS
Creates a Microsoft Entra authentication-method readiness and SMS/voice migration report.

.DESCRIPTION
Uses read-only Microsoft Graph reporting APIs to collect:

- Authentication methods registered for each user.
- Authentication methods observed in sign-in authentication steps.
- Successful and failed SMS/voice usage.
- A prioritized SMS/voice migration action list.

Risk is assigned from observed telephony use, administrator status, and the
registered methods: a user is treated as phishing-resistant only when FIDO2,
a device-bound passkey, or Windows Hello for Business is registered, and as
having a non-phone fallback when any Authenticator, OTP, or phishing-resistant
method is registered.

The script creates CSV files, an HTML summary, and a JSON manifest. Sign-in
queries are split into time windows to reduce Graph timeouts on larger tenants.

The live mode requires the Microsoft.Graph.Authentication and
Microsoft.Graph.Reports modules, the AuditLog.Read.All delegated permission,
and a supported Entra role such as Reports Reader, Security Reader, or Global
Reader.

On first sign-in, Microsoft Graph requests consent for AuditLog.Read.All.
This permission requires administrator consent in the target tenant. If approval
is required, a tenant administrator must approve the Microsoft Graph Command Line
Tools application before a reporting user can export data. Consent does not
create a user or guest account or assign a reader role.

Offline mode reads deterministic JSON data and doesn't connect to Microsoft
Graph. It is intended for testing the reporting pipeline.

.PARAMETER TenantId
Required tenant ID or verified tenant domain used for live Microsoft Graph sign-in.
The domain is resolved to its tenant GUID before checking an existing session.

.PARAMETER LoginHint
Optional account UPN to suggest in the Microsoft Graph sign-in prompt. The
account must already be a member or guest in the target tenant.

.PARAMETER UseDeviceCode
Use device-code sign-in to choose an account explicitly. This does not bypass
the requirement for the chosen account to exist in the target tenant.

.PARAMETER ForceSignIn
Disconnect an existing Microsoft Graph session and start a new sign-in for the
requested tenant. Use this when switching accounts or tenants. New sessions use
process-scoped authentication so they are not persisted across PowerShell sessions.
An existing administrator consent grant is reused; a consent screen only appears
when required by Microsoft Entra.

.PARAMETER LookbackDays
Number of days of sign-in activity to query. The default is 30. Native Entra
sign-in retention is normally 7 days for Free tenants and 30 days for P1/P2.

.PARAMETER WindowHours
Size of each Microsoft Graph sign-in query window. The default is 24 hours.
Reduce this value if a large tenant experiences Graph timeouts.

.PARAMETER OutputPath
Directory in which report files are created. The default is a timestamped
folder under the current directory. The directory must be empty if it exists.

.PARAMETER IncludeEventDetails
Creates Authentication-Usage-Events.csv with one row per recorded authentication
step for every method, user, application, result, and UTC date/time. Enabled by
default. Use -IncludeEventDetails:$false for summary-only exports in busy tenants.
EventDateTimeUtc uses the step time when available, otherwise the sign-in time;
EventTimeSource identifies which was used.

.PARAMETER IncludeMethodDetails
Includes authenticationMethodDetail values in the event-level export. These
values can contain personal information such as a partially displayed phone
number. Requires IncludeEventDetails.

.PARAMETER HtmlActionLimit
Maximum number of prioritized action rows embedded in the HTML report. All
rows are always retained in the CSV action list.

.PARAMETER OfflineDataPath
Runs the script without Microsoft Graph by reading registrationDetails,
signIns, reportEndUtc, and tenantId from a JSON fixture.

.EXAMPLE
.\Get-EntraAuthenticationReadinessReport.ps1 -TenantId YourDomain.onmicrosoft.com

Connects to Microsoft Graph and creates a 30-day readiness report.

.EXAMPLE
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId 00000000-0000-0000-0000-000000000000 `
    -LoginHint analyst@YourDomain.com `
    -ForceSignIn `
    -UseDeviceCode `
    -OutputPath .\Customer-Authentication-Report

Signs in to the target tenant, requests permission consent if needed, and exports
reports to an empty output directory. Approve consent using an authorized account
in that tenant. Device-code sign-in can be blocked by tenant security policy; in
that case omit UseDeviceCode and use the normal interactive sign-in.

.EXAMPLE
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId YourDomain.onmicrosoft.com `
    -LookbackDays 14 `
    -WindowHours 6 `
    -IncludeEventDetails

Queries 14 days in six-hour windows and includes event-level output.

.EXAMPLE
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -OfflineDataPath .\tests\sample-authentication-data.json `
    -OutputPath .\sample-output `
    -IncludeEventDetails

Runs the complete reporting pipeline without accessing a tenant.

.NOTES
The script is read-only. It does not change authentication methods, policies,
users, groups, or Conditional Access configuration.

Registration reporting can be delayed by up to 36 hours and excludes disabled
users. A sign-in whose MFA requirement was satisfied by a previous token claim
does not prove that the user performed a new SMS or voice challenge during that
event.

Live mode reads interactive user sign-ins. SMS and voice challenges occur in
interactive sign-ins, so coverage is complete for this purpose, but the counts
do not include non-interactive or service principal sign-ins. Telephony steps
are recognised by name (SMS, Text message, Voice, Voice call, Phone call); a
warning is written if steps were processed but none matched.
#>

[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Live')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Live')]
    [ValidateNotNullOrEmpty()]
    [string]$LoginHint,

    [Parameter(ParameterSetName = 'Live')]
    [switch]$UseDeviceCode,

    [Parameter(ParameterSetName = 'Live')]
    [switch]$ForceSignIn,

    [ValidateRange(1, 30)]
    [int]$LookbackDays = 30,

    [ValidateRange(1, 168)]
    [int]$WindowHours = 24,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("Entra-Authentication-Readiness-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [switch]$IncludeEventDetails,

    [switch]$IncludeMethodDetails,

    [ValidateRange(1, 1000)]
    [int]$HtmlActionLimit = 200,

    [Parameter(Mandatory, ParameterSetName = 'Offline')]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "Offline data file not found: $_"
        }
        $true
    })]
    [string]$OfflineDataPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $PSBoundParameters.ContainsKey('IncludeEventDetails')) {
    $IncludeEventDetails = [switch]$true
}

function Get-PropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [AllowNull()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function ConvertTo-Boolean {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [bool]) {
        return $Value
    }

    if ($null -eq $Value) {
        return $false
    }

    $parsed = $false
    if ([bool]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed
    }

    return $false
}

function ConvertTo-UtcDateTime {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime
    }

    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime()
    }

    return ([datetimeoffset]::Parse(
        [string]$Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal
    )).UtcDateTime
}

function Format-UtcDateTime {
    param(
        [AllowNull()]
        [object]$Value
    )

    $utcValue = ConvertTo-UtcDateTime -Value $Value
    if ($null -eq $utcValue) {
        return ''
    }

    return $utcValue.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-StringArray {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return
    }

    foreach ($item in @($Value)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            [string]$item
        }
    }
}

function Get-EmptyStringSet {
    return ,([System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    ))
}

function Get-UserKey {
    param(
        [AllowNull()]
        [string]$UserId,

        [AllowNull()]
        [string]$UserPrincipalName
    )

    if (-not [string]::IsNullOrWhiteSpace($UserId)) {
        return "id:$($UserId.Trim().ToLowerInvariant())"
    }

    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        return "upn:$($UserPrincipalName.Trim().ToLowerInvariant())"
    }

    return 'unknown'
}

function Test-PhoneRegistration {
    param(
        [string[]]$MethodsRegistered
    )

    $phoneMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
    foreach ($method in @($MethodsRegistered)) {
        if ($phoneMethods -contains $method) {
            return $true
        }
    }

    return $false
}

function Test-PhishingResistantRegistration {
    param(
        [string[]]$MethodsRegistered
    )

    # Registered methods that are phishing-resistant: FIDO2 security keys,
    # device-bound passkeys, and Windows Hello for Business.
    $phishingResistantMethods = @(
        'fido2SecurityKey'
        'passKeyDeviceBound'
        'passKeyDeviceBoundAuthenticator'
        'passKeyDeviceBoundWindowsHello'
        'windowsHelloForBusiness'
    )
    foreach ($method in @($MethodsRegistered)) {
        if ($phishingResistantMethods -contains $method) {
            return $true
        }
    }

    return $false
}

function Test-StrongNonPhoneRegistration {
    param(
        [string[]]$MethodsRegistered
    )

    # Registered methods that can satisfy MFA without telephony. These are not
    # necessarily phishing-resistant, but they mean the user is not dependent on
    # SMS or voice to sign in.
    $strongMethods = @(
        'fido2SecurityKey'
        'passKeyDeviceBound'
        'passKeyDeviceBoundAuthenticator'
        'passKeyDeviceBoundWindowsHello'
        'windowsHelloForBusiness'
        'microsoftAuthenticatorPush'
        'microsoftAuthenticatorPasswordless'
        'softwareOneTimePasscode'
        'hardwareOneTimePasscode'
    )
    foreach ($method in @($MethodsRegistered)) {
        if ($strongMethods -contains $method) {
            return $true
        }
    }

    return $false
}

function Get-TelephonyMethodType {
    param(
        [AllowNull()]
        [string]$AuthenticationMethod
    )

    # Sign-in log authenticationMethod values vary between Graph versions and
    # tenants ("SMS", "Text message", "Voice", "Voice call", "Phone call",
    # "Mobile phone call", "Office phone call"). Match on substrings so the
    # report doesn't silently miss telephony usage.
    if ([string]::IsNullOrWhiteSpace($AuthenticationMethod)) {
        return $null
    }

    if ($AuthenticationMethod -match '(?i)\bsms\b|text message') {
        return 'Sms'
    }

    if ($AuthenticationMethod -match '(?i)\bvoice\b|phone call') {
        return 'Voice'
    }

    return $null
}

function Test-PhonePreference {
    param(
        [AllowNull()]
        [string]$UserPreferredMethod,

        [string[]]$SystemPreferredMethods
    )

    $phonePreferences = @('sms', 'voiceMobile', 'voiceAlternateMobile', 'voiceOffice')
    if ($phonePreferences -contains $UserPreferredMethod) {
        return $true
    }

    foreach ($method in @($SystemPreferredMethods)) {
        if ($phonePreferences -contains $method) {
            return $true
        }
    }

    return $false
}

function Get-ResultState {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'Unknown'
    }

    $parsed = $false
    if ([bool]::TryParse([string]$Value, [ref]$parsed)) {
        if ($parsed) {
            return 'Succeeded'
        }

        return 'Failed'
    }

    return 'Unknown'
}

function Add-SetValue {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Set,

        [AllowNull()]
        [string]$Value
    )

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        [void]$Set.Add($Value)
    }
}

function Measure-DateRange {
    param(
        [Parameter(Mandatory)]
        [object]$Statistics,

        [AllowNull()]
        [datetime]$EventDate
    )

    if ($null -eq $EventDate) {
        return
    }

    if ($null -eq $Statistics.FirstSeen -or $EventDate -lt $Statistics.FirstSeen) {
        $Statistics.FirstSeen = $EventDate
    }

    if ($null -eq $Statistics.LastSeen -or $EventDate -gt $Statistics.LastSeen) {
        $Statistics.LastSeen = $EventDate
    }
}

function Add-SignInRecord {
    param(
        [Parameter(Mandatory)]
        [object]$SignIn,

        [Parameter(Mandatory)]
        [hashtable]$UserMethodStatistics,

        [Parameter(Mandatory)]
        [hashtable]$MethodStatistics,

        [Parameter(Mandatory)]
        [hashtable]$PhoneStatistics,

        [Parameter(Mandatory)]
        [hashtable]$Counters,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$EventBuffer,

        [switch]$IncludeEvents,

        [switch]$IncludeDetails
    )

    $Counters.SignInsProcessed = [int]$Counters.SignInsProcessed + 1

    $signInDate = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $SignIn -Name 'CreatedDateTime')
    $userId = [string](Get-PropertyValue -InputObject $SignIn -Name 'UserId' -DefaultValue '')
    $upn = [string](Get-PropertyValue -InputObject $SignIn -Name 'UserPrincipalName' -DefaultValue '')
    $displayName = [string](Get-PropertyValue -InputObject $SignIn -Name 'UserDisplayName' -DefaultValue '')
    $application = [string](Get-PropertyValue -InputObject $SignIn -Name 'AppDisplayName' -DefaultValue '')
    $resource = [string](Get-PropertyValue -InputObject $SignIn -Name 'ResourceDisplayName' -DefaultValue '')
    $isInteractive = Get-PropertyValue -InputObject $SignIn -Name 'IsInteractive'
    $userKey = Get-UserKey -UserId $userId -UserPrincipalName $upn
    $authenticationDetails = @(
        Get-PropertyValue -InputObject $SignIn -Name 'AuthenticationDetails' -DefaultValue @()
    )

    if ($authenticationDetails.Count -eq 0) {
        $Counters.SignInsWithoutAuthenticationDetails = [int]$Counters.SignInsWithoutAuthenticationDetails + 1
        return
    }

    foreach ($step in $authenticationDetails) {
        $Counters.AuthenticationStepsProcessed = [int]$Counters.AuthenticationStepsProcessed + 1

        $method = [string](Get-PropertyValue -InputObject $step -Name 'AuthenticationMethod' -DefaultValue 'Unknown')
        if ([string]::IsNullOrWhiteSpace($method)) {
            $method = 'Unknown'
        }
        $method = $method.Trim()

        $stepDate = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $step -Name 'AuthenticationStepDateTime')
        $eventDate = if ($null -ne $stepDate) { $stepDate } else { $signInDate }
        $resultState = Get-ResultState -Value (Get-PropertyValue -InputObject $step -Name 'Succeeded')
        $countProperty = if ($resultState -eq 'Succeeded') { 'Successful' } else { $resultState }
        $methodKey = $method.ToLowerInvariant()
        $userMethodKey = "$userKey|$methodKey"

        if (-not $UserMethodStatistics.ContainsKey($userMethodKey)) {
            $UserMethodStatistics[$userMethodKey] = [pscustomobject]@{
                UserKey          = $userKey
                UserId           = $userId
                UserPrincipalName = $upn
                UserDisplayName  = $displayName
                Method           = $method
                Attempts         = 0
                Successful       = 0
                Failed           = 0
                Unknown          = 0
                FirstSeen        = $null
                LastSeen         = $null
                Applications     = Get-EmptyStringSet
            }
        }

        $userMethod = $UserMethodStatistics[$userMethodKey]
        $userMethod.Attempts = [int]$userMethod.Attempts + 1
        $userMethod.$countProperty = [int]$userMethod.$countProperty + 1
        Measure-DateRange -Statistics $userMethod -EventDate $eventDate
        Add-SetValue -Set $userMethod.Applications -Value $application

        if (-not $MethodStatistics.ContainsKey($methodKey)) {
            $MethodStatistics[$methodKey] = [pscustomobject]@{
                Method       = $method
                Attempts     = 0
                Successful   = 0
                Failed       = 0
                Unknown      = 0
                FirstSeen    = $null
                LastSeen     = $null
                Users        = Get-EmptyStringSet
                Applications = Get-EmptyStringSet
            }
        }

        $methodSummary = $MethodStatistics[$methodKey]
        $methodSummary.Attempts = [int]$methodSummary.Attempts + 1
        $methodSummary.$countProperty = [int]$methodSummary.$countProperty + 1
        Measure-DateRange -Statistics $methodSummary -EventDate $eventDate
        Add-SetValue -Set $methodSummary.Users -Value $userKey
        Add-SetValue -Set $methodSummary.Applications -Value $application

        $telephonyType = Get-TelephonyMethodType -AuthenticationMethod $method
        if ($null -ne $telephonyType) {
            if (-not $PhoneStatistics.ContainsKey($userKey)) {
                $PhoneStatistics[$userKey] = [pscustomobject]@{
                    UserKey          = $userKey
                    UserId           = $userId
                    UserPrincipalName = $upn
                    UserDisplayName  = $displayName
                    SmsAttempts      = 0
                    SmsSuccessful    = 0
                    SmsFailed        = 0
                    SmsUnknown       = 0
                    VoiceAttempts    = 0
                    VoiceSuccessful  = 0
                    VoiceFailed      = 0
                    VoiceUnknown     = 0
                    FirstSeen        = $null
                    LastSeen         = $null
                    Applications     = Get-EmptyStringSet
                }
            }

            $phone = $PhoneStatistics[$userKey]
            $attemptProperty = "${telephonyType}Attempts"
            $resultProperty = "${telephonyType}${countProperty}"
            $phone.$attemptProperty = [int]$phone.$attemptProperty + 1
            $phone.$resultProperty = [int]$phone.$resultProperty + 1
            Measure-DateRange -Statistics $phone -EventDate $eventDate
            Add-SetValue -Set $phone.Applications -Value $application
        }

        if ($IncludeEvents) {
            $methodDetail = ''
            if ($IncludeDetails) {
                $methodDetail = [string](Get-PropertyValue -InputObject $step -Name 'AuthenticationMethodDetail' -DefaultValue '')
            }

            [void]$EventBuffer.Add([pscustomobject]@{
                SignInId                  = [string](Get-PropertyValue -InputObject $SignIn -Name 'Id' -DefaultValue '')
                EventDateTimeUtc          = Format-UtcDateTime -Value $eventDate
                EventTimeSource           = if ($null -ne $stepDate) { 'AuthenticationStep' } elseif ($null -ne $signInDate) { 'SignIn' } else { 'Unavailable' }
                SignInDateTimeUtc         = Format-UtcDateTime -Value $signInDate
                AuthenticationStepTimeUtc = Format-UtcDateTime -Value $stepDate
                UserId                    = $userId
                UserPrincipalName         = $upn
                UserDisplayName           = $displayName
                Application               = $application
                Resource                  = $resource
                IsInteractive             = $isInteractive
                AuthenticationMethod      = $method
                AuthenticationStepCategory = if ($method -in @('Satisfied by token', 'Previously satisfied')) { 'PreviouslySatisfied' } elseif ($method -eq 'Unknown') { 'Unknown' } else { 'RecordedMethod' }
                TelephonyType             = if ($null -ne $telephonyType) { $telephonyType.ToUpperInvariant() } else { '' }
                MethodDetail              = $methodDetail
                Requirement               = [string](Get-PropertyValue -InputObject $step -Name 'AuthenticationStepRequirement' -DefaultValue '')
                ResultState               = $resultState
                ResultDetail              = [string](Get-PropertyValue -InputObject $step -Name 'AuthenticationStepResultDetail' -DefaultValue '')
            })
        }
    }
}

function Write-EventBuffer {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Buffer,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Buffer.Count -eq 0) {
        return
    }

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $Buffer | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8 -Append
    }
    else {
        $Buffer | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
    }

    $Buffer.Clear()
}

function Resolve-EntraTenantId {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantIdentifier
    )

    $tenantGuid = [guid]::Empty
    if ([guid]::TryParse($TenantIdentifier, [ref]$tenantGuid)) {
        return $tenantGuid.ToString()
    }

    $escapedTenant = [uri]::EscapeDataString($TenantIdentifier)
    $metadataUri = "https://login.microsoftonline.com/$escapedTenant/v2.0/.well-known/openid-configuration"
    try {
        $metadata = Invoke-RestMethod -Uri $metadataUri -Method Get -TimeoutSec 15 -ErrorAction Stop
    }
    catch {
        throw "Unable to resolve tenant identifier '$TenantIdentifier' to a Microsoft Entra tenant ID. $($_.Exception.Message)"
    }

    $issuer = [string](Get-PropertyValue -InputObject $metadata -Name 'issuer' -DefaultValue '')
    $match = [regex]::Match(
        $issuer,
        '/(?<tenantId>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/v2\.0/?$'
    )

    if (-not $match.Success) {
        throw "Microsoft Entra OpenID metadata for '$TenantIdentifier' did not contain a tenant GUID issuer."
    }

    return ([guid]$match.Groups['tenantId'].Value).ToString()
}

function Connect-EntraReportGraph {
    param(
        [AllowNull()]
        [string]$RequestedTenantId,

        [AllowNull()]
        [string]$RequestedLoginHint,

        [switch]$UseDeviceCode,

        [switch]$ForceSignIn
    )

    $requiredModules = @(
        'Microsoft.Graph.Authentication'
        'Microsoft.Graph.Reports'
    )

    $missingModules = @(
        $requiredModules | Where-Object {
            -not (Get-Module -ListAvailable -Name $_)
        }
    )

    if ($missingModules.Count -gt 0) {
        throw (
            "Missing required Microsoft Graph modules: {0}. Install them with: " +
            "Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Reports -Scope CurrentUser"
        ) -f ($missingModules -join ', ')
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop

    $expectedTenantId = ''
    if (-not [string]::IsNullOrWhiteSpace($RequestedTenantId)) {
        $expectedTenantId = Resolve-EntraTenantId -TenantIdentifier $RequestedTenantId
    }

    $context = Get-MgContext
    $hasRequiredScope = $false
    $tenantMatches = $true
    $accountMatches = $true

    if ($null -ne $context) {
        $hasRequiredScope = @($context.Scopes) -contains 'AuditLog.Read.All'
        if (-not [string]::IsNullOrWhiteSpace($expectedTenantId)) {
            $tenantMatches = $context.TenantId -ieq $expectedTenantId
        }
        if (-not [string]::IsNullOrWhiteSpace($RequestedLoginHint)) {
            $accountMatches = $context.Account -ieq $RequestedLoginHint
        }
    }

    if ($ForceSignIn -and $null -ne $context) {
        Disconnect-MgGraph -ErrorAction Stop | Out-Null
        $context = $null
    }

    if ($null -eq $context -or -not $hasRequiredScope -or -not $tenantMatches -or -not $accountMatches) {
        $connectParameters = @{
            Scopes    = @('AuditLog.Read.All')
            NoWelcome = $true
            ContextScope = 'Process'
        }

        if (-not [string]::IsNullOrWhiteSpace($RequestedTenantId)) {
            $connectParameters.TenantId = $expectedTenantId
        }
        if (-not [string]::IsNullOrWhiteSpace($RequestedLoginHint)) {
            $connectParameters.LoginHint = $RequestedLoginHint
        }
        if ($UseDeviceCode) {
            $connectParameters.UseDeviceCode = $true
        }

        Write-Information -MessageData (
            "Sign in to tenant '$expectedTenantId' with an account authorized to read reports. " +
            "If prompted, an authorized tenant administrator must consent to AuditLog.Read.All. " +
            "If consent is already granted, no new consent prompt is required."
        ) -InformationAction Continue
        try {
            Connect-MgGraph @connectParameters -ErrorAction Stop | Out-Null
        }
        catch {
            throw (
                "Microsoft Graph sign-in failed. For AADSTS50020, the selected account is not a member or guest " +
                "in the target tenant; use an account that belongs there or have the tenant invite it as a guest. " +
                "For an approval or consent error, ask an authorized target-tenant administrator to grant " +
                "AuditLog.Read.All consent to Microsoft Graph Command Line Tools. " +
                "Original error: $($_.Exception.Message)"
            )
        }
        $context = Get-MgContext
    }

    if ($null -eq $context) {
        throw 'Microsoft Graph authentication did not return a connection context.'
    }

    if (@($context.Scopes) -notcontains 'AuditLog.Read.All') {
        throw 'The Microsoft Graph connection does not include AuditLog.Read.All.'
    }

    if (-not [string]::IsNullOrWhiteSpace($expectedTenantId) -and $context.TenantId -ine $expectedTenantId) {
        throw "Connected tenant '$($context.TenantId)' does not match the requested tenant '$expectedTenantId'. Disconnect and sign in to the intended customer tenant."
    }

    Write-Information -MessageData (
        "Connected account: $($context.Account); tenant: $($context.TenantId). Starting report collection and export."
    ) -InformationAction Continue

    return $context
}

function Get-RiskOrder {
    param(
        [string]$Risk
    )

    switch ($Risk) {
        'Critical' { return 1 }
        'High' { return 2 }
        'Medium' { return 3 }
        'Low' { return 4 }
        default { return 5 }
    }
}

function ConvertTo-MigrationActionRow {
    param(
        [AllowNull()]
        [object]$Registration,

        [AllowNull()]
        [object]$PhoneUsage
    )

    $registrationFound = $null -ne $Registration
    $phoneUsageFound = $null -ne $PhoneUsage

    $userId = if ($registrationFound) { $Registration.UserId } elseif ($phoneUsageFound) { $PhoneUsage.UserId } else { '' }
    $upn = if ($registrationFound) { $Registration.UserPrincipalName } elseif ($phoneUsageFound) { $PhoneUsage.UserPrincipalName } else { '' }
    $displayName = if ($registrationFound) { $Registration.UserDisplayName } elseif ($phoneUsageFound) { $PhoneUsage.UserDisplayName } else { '' }
    $isAdmin = if ($registrationFound) { [bool]$Registration.IsAdmin } else { $false }
    $isPasswordlessCapable = if ($registrationFound) { [bool]$Registration.IsPasswordlessCapable } else { $false }
    $phishingResistantRegistered = if ($registrationFound) { [bool]$Registration.PhishingResistantRegistered } else { $false }
    $strongNonPhoneRegistered = if ($registrationFound) { [bool]$Registration.StrongNonPhoneRegistered } else { $false }
    $phoneRegistered = if ($registrationFound) { [bool]$Registration.PhoneRegistered } else { $false }
    $phonePreferred = if ($registrationFound) { [bool]$Registration.PhonePreferred } else { $false }
    $methodsRegistered = if ($registrationFound) { $Registration.MethodsRegistered -join ';' } else { '' }
    $userPreferred = if ($registrationFound) { $Registration.UserPreferredMethod } else { '' }
    $systemPreferred = if ($registrationFound) { $Registration.SystemPreferredMethods -join ';' } else { '' }
    $smsAttempts = if ($phoneUsageFound) { [int]$PhoneUsage.SmsAttempts } else { 0 }
    $smsSuccessful = if ($phoneUsageFound) { [int]$PhoneUsage.SmsSuccessful } else { 0 }
    $smsFailed = if ($phoneUsageFound) { [int]$PhoneUsage.SmsFailed } else { 0 }
    $voiceAttempts = if ($phoneUsageFound) { [int]$PhoneUsage.VoiceAttempts } else { 0 }
    $voiceSuccessful = if ($phoneUsageFound) { [int]$PhoneUsage.VoiceSuccessful } else { 0 }
    $voiceFailed = if ($phoneUsageFound) { [int]$PhoneUsage.VoiceFailed } else { 0 }
    $successfulPhoneUses = $smsSuccessful + $voiceSuccessful

    # Risk tiers. "Phishing-resistant" is judged from the registered methods
    # (FIDO2, device-bound passkey, Windows Hello for Business), not from the
    # IsPasswordlessCapable flag, because Authenticator phone sign-in is
    # passwordless but not phishing-resistant. "Strong non-phone" means any
    # registered MFA method that does not depend on telephony.
    $phoneInScope = $phoneRegistered -or $phonePreferred
    $risk = 'Low'
    $recommendedAction = 'Monitor usage and remove the registered phone methods when there is no business requirement.'

    if ($isAdmin -and $successfulPhoneUses -gt 0) {
        $risk = 'Critical'
        $recommendedAction = 'Administrator actively using SMS/voice. Enroll and validate two phishing-resistant credentials, then remove the phone methods.'
    }
    elseif ($successfulPhoneUses -gt 0 -and -not $phishingResistantRegistered) {
        $risk = 'Critical'
        $recommendedAction = 'Register and validate a phishing-resistant method, test recovery, then remove SMS/voice dependency.'
    }
    elseif ($isAdmin -and $phoneInScope -and -not $phishingResistantRegistered) {
        $risk = 'High'
        $recommendedAction = 'Administrator with phone methods and no phishing-resistant credential. Enroll FIDO2 or a passkey before removing SMS/voice.'
    }
    elseif ($phoneInScope -and -not $strongNonPhoneRegistered) {
        $risk = 'High'
        $recommendedAction = 'Phone is the only registered MFA method. Enroll a phishing-resistant method and validate the normal and recovery sign-in journeys.'
    }
    elseif ($successfulPhoneUses -gt 0) {
        $risk = 'Medium'
        $recommendedAction = 'Validate the existing phishing-resistant method, then remove SMS/voice as a routine sign-in option.'
    }
    elseif ($phonePreferred -and -not $phishingResistantRegistered) {
        $risk = 'Medium'
        $recommendedAction = 'Phone is the preferred method but a non-phone fallback exists. Change the default to Authenticator or enroll a phishing-resistant method, then remove the phone methods.'
    }

    $dataQualityNote = ''
    if (-not $registrationFound) {
        $dataQualityNote = 'No user registration record was returned. Verify account state and registered methods manually.'
    }

    return [pscustomobject]@{
        UserId                     = $userId
        UserPrincipalName           = $upn
        UserDisplayName             = $displayName
        IsAdmin                     = $isAdmin
        RegistrationRecordFound     = $registrationFound
        PhoneRegistered             = $phoneRegistered
        PhonePreferred              = $phonePreferred
        MethodsRegistered           = $methodsRegistered
        UserPreferredMethod         = $userPreferred
        SystemPreferredMethods      = $systemPreferred
        IsPasswordlessCapable       = $isPasswordlessCapable
        PhishingResistantRegistered = $phishingResistantRegistered
        StrongNonPhoneRegistered    = $strongNonPhoneRegistered
        SmsAttempts                 = $smsAttempts
        SmsSuccessful               = $smsSuccessful
        SmsFailed                   = $smsFailed
        VoiceAttempts               = $voiceAttempts
        VoiceSuccessful             = $voiceSuccessful
        VoiceFailed                 = $voiceFailed
        SuccessfulPhoneUses         = $successfulPhoneUses
        FirstPhoneUseUtc            = if ($phoneUsageFound) { Format-UtcDateTime -Value $PhoneUsage.FirstSeen } else { '' }
        LastPhoneUseUtc             = if ($phoneUsageFound) { Format-UtcDateTime -Value $PhoneUsage.LastSeen } else { '' }
        Applications                = if ($phoneUsageFound) { @($PhoneUsage.Applications | Sort-Object) -join ';' } else { '' }
        Risk                        = $risk
        RecommendedAction           = $recommendedAction
        DataQualityNote             = $dataQualityNote
    }
}

if ($IncludeMethodDetails -and -not $IncludeEventDetails) {
    throw 'IncludeMethodDetails requires IncludeEventDetails.'
}

if (Test-Path -LiteralPath $OutputPath) {
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        throw "OutputPath exists and is not a directory: $OutputPath"
    }

    $existingItems = @(Get-ChildItem -LiteralPath $OutputPath -Force)
    if ($existingItems.Count -gt 0) {
        throw "OutputPath must be empty: $OutputPath"
    }
}
else {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$eventFilePath = Join-Path -Path $resolvedOutputPath -ChildPath 'Authentication-Usage-Events.csv'
$userMethodStatistics = @{}
$methodStatistics = @{}
$phoneStatistics = @{}
$counters = @{
    SignInsProcessed                    = 0
    SignInsWithoutAuthenticationDetails = 0
    AuthenticationStepsProcessed        = 0
}
$registrationSource = @()
$inputMode = 'Live'
$tenantIdentifier = ''
$reportEndUtc = (Get-Date).ToUniversalTime()
$offlineData = $null

if ($PSCmdlet.ParameterSetName -eq 'Offline') {
    $inputMode = 'Offline'
    $offlineJson = Get-Content -LiteralPath $OfflineDataPath -Raw
    $offlineData = $offlineJson | ConvertFrom-Json
    $registrationSource = @(
        Get-PropertyValue -InputObject $offlineData -Name 'registrationDetails' -DefaultValue @()
    )

    $fixtureEnd = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $offlineData -Name 'reportEndUtc')
    if ($null -ne $fixtureEnd) {
        $reportEndUtc = $fixtureEnd
    }

    $tenantIdentifier = [string](Get-PropertyValue -InputObject $offlineData -Name 'tenantId' -DefaultValue 'offline-test-tenant')
}
else {
    Write-Verbose 'Connecting to Microsoft Graph with read-only AuditLog.Read.All permission...'
    $graphContext = Connect-EntraReportGraph `
        -RequestedTenantId $TenantId `
        -RequestedLoginHint $LoginHint `
        -UseDeviceCode:$UseDeviceCode `
        -ForceSignIn:$ForceSignIn
    $tenantIdentifier = [string]$graphContext.TenantId

    Write-Verbose 'Retrieving authentication-method registration details...'
    try {
        $registrationSource = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All)
    }
    catch {
        throw "Failed to retrieve user registration details. $($_.Exception.Message)"
    }
}

$reportStartUtc = $reportEndUtc.AddDays(-$LookbackDays)
$registrationRecords = [System.Collections.Generic.List[object]]::new()

foreach ($registrationItem in $registrationSource) {
    $methodsRegistered = @(
        Get-StringArray -Value (Get-PropertyValue -InputObject $registrationItem -Name 'MethodsRegistered')
    )
    $systemPreferredMethods = @(
        Get-StringArray -Value (Get-PropertyValue -InputObject $registrationItem -Name 'SystemPreferredAuthenticationMethods')
    )
    $userId = [string](Get-PropertyValue -InputObject $registrationItem -Name 'Id' -DefaultValue '')
    $upn = [string](Get-PropertyValue -InputObject $registrationItem -Name 'UserPrincipalName' -DefaultValue '')
    $userPreferredMethod = [string](Get-PropertyValue -InputObject $registrationItem -Name 'UserPreferredMethodForSecondaryAuthentication' -DefaultValue '')
    $phoneRegistered = Test-PhoneRegistration -MethodsRegistered $methodsRegistered
    $phonePreferred = Test-PhonePreference -UserPreferredMethod $userPreferredMethod -SystemPreferredMethods $systemPreferredMethods

    $record = [pscustomobject]@{
        UserKey                     = Get-UserKey -UserId $userId -UserPrincipalName $upn
        UserId                      = $userId
        UserPrincipalName           = $upn
        UserDisplayName             = [string](Get-PropertyValue -InputObject $registrationItem -Name 'UserDisplayName' -DefaultValue '')
        UserType                    = [string](Get-PropertyValue -InputObject $registrationItem -Name 'UserType' -DefaultValue '')
        IsAdmin                     = ConvertTo-Boolean -Value (Get-PropertyValue -InputObject $registrationItem -Name 'IsAdmin')
        IsMfaRegistered             = ConvertTo-Boolean -Value (Get-PropertyValue -InputObject $registrationItem -Name 'IsMfaRegistered')
        IsMfaCapable                = ConvertTo-Boolean -Value (Get-PropertyValue -InputObject $registrationItem -Name 'IsMfaCapable')
        IsPasswordlessCapable       = ConvertTo-Boolean -Value (Get-PropertyValue -InputObject $registrationItem -Name 'IsPasswordlessCapable')
        IsSsprRegistered            = ConvertTo-Boolean -Value (Get-PropertyValue -InputObject $registrationItem -Name 'IsSsprRegistered')
        IsSsprCapable               = ConvertTo-Boolean -Value (Get-PropertyValue -InputObject $registrationItem -Name 'IsSsprCapable')
        MethodsRegistered           = $methodsRegistered
        UserPreferredMethod         = $userPreferredMethod
        SystemPreferredMethods      = $systemPreferredMethods
        PhoneRegistered             = $phoneRegistered
        PhonePreferred              = $phonePreferred
        PhishingResistantRegistered = Test-PhishingResistantRegistration -MethodsRegistered $methodsRegistered
        StrongNonPhoneRegistered    = Test-StrongNonPhoneRegistration -MethodsRegistered $methodsRegistered
        LastUpdatedDateTime         = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $registrationItem -Name 'LastUpdatedDateTime')
    }

    [void]$registrationRecords.Add($record)
}

Write-Verbose ("Processing sign-ins from {0} to {1}..." -f (Format-UtcDateTime $reportStartUtc), (Format-UtcDateTime $reportEndUtc))

if ($inputMode -eq 'Offline') {
    $eventBuffer = [System.Collections.Generic.List[object]]::new()
    $offlineSignIns = @(
        Get-PropertyValue -InputObject $offlineData -Name 'signIns' -DefaultValue @()
    )

    foreach ($signIn in $offlineSignIns) {
        $createdDate = ConvertTo-UtcDateTime -Value (Get-PropertyValue -InputObject $signIn -Name 'CreatedDateTime')
        if ($null -ne $createdDate -and $createdDate -ge $reportStartUtc -and $createdDate -lt $reportEndUtc) {
            Add-SignInRecord `
                -SignIn $signIn `
                -UserMethodStatistics $userMethodStatistics `
                -MethodStatistics $methodStatistics `
                -PhoneStatistics $phoneStatistics `
                -Counters $counters `
                -EventBuffer $eventBuffer `
                -IncludeEvents:$IncludeEventDetails `
                -IncludeDetails:$IncludeMethodDetails
        }
    }

    if ($IncludeEventDetails) {
        Write-EventBuffer -Buffer $eventBuffer -Path $eventFilePath
    }
}
else {
    $windowStart = $reportStartUtc
    $earliestSignInUtc = $null
    while ($windowStart -lt $reportEndUtc) {
        $windowEnd = $windowStart.AddHours($WindowHours)
        if ($windowEnd -gt $reportEndUtc) {
            $windowEnd = $reportEndUtc
        }

        $elapsed = ($windowStart - $reportStartUtc).TotalSeconds
        $duration = ($reportEndUtc - $reportStartUtc).TotalSeconds
        $percentComplete = if ($duration -gt 0) { [int](($elapsed / $duration) * 100) } else { 100 }
        Write-Progress `
            -Activity 'Retrieving Microsoft Entra sign-ins' `
            -Status ("{0} to {1}" -f (Format-UtcDateTime $windowStart), (Format-UtcDateTime $windowEnd)) `
            -PercentComplete $percentComplete

        $filter = "createdDateTime ge $($windowStart.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime lt $($windowEnd.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        try {
            $signInBatch = @(Get-MgAuditLogSignIn -Filter $filter -All)
        }
        catch {
            throw "Failed to retrieve sign-ins for $filter. $($_.Exception.Message)"
        }

        if ($null -eq $earliestSignInUtc -and $signInBatch.Count -gt 0) {
            $earliestSignInUtc = $windowStart
        }

        $eventBuffer = [System.Collections.Generic.List[object]]::new()
        foreach ($signIn in $signInBatch) {
            Add-SignInRecord `
                -SignIn $signIn `
                -UserMethodStatistics $userMethodStatistics `
                -MethodStatistics $methodStatistics `
                -PhoneStatistics $phoneStatistics `
                -Counters $counters `
                -EventBuffer $eventBuffer `
                -IncludeEvents:$IncludeEventDetails `
                -IncludeDetails:$IncludeMethodDetails
        }

        if ($IncludeEventDetails) {
            Write-EventBuffer -Buffer $eventBuffer -Path $eventFilePath
        }

        $windowStart = $windowEnd
    }

    Write-Progress -Activity 'Retrieving Microsoft Entra sign-ins' -Completed

    if ($counters.SignInsProcessed -eq 0) {
        Write-Warning (
            "No sign-ins were returned for the requested period. Confirm the account can read sign-in logs " +
            "and that the tenant retains sign-in data for the requested lookback."
        )
    }
    elseif ($LookbackDays -gt 7 -and $null -ne $earliestSignInUtc -and $earliestSignInUtc -ge $reportEndUtc.AddDays(-7)) {
        Write-Warning (
            "Sign-in data was only returned for the most recent 7 days although {0} days were requested. " +
            "The tenant is likely on Microsoft Entra ID Free (7-day sign-in retention); usage counts cover " +
            "a shorter period than the report period."
        ) -f $LookbackDays
    }

    if ($counters.AuthenticationStepsProcessed -gt 0 -and $phoneStatistics.Count -eq 0) {
        $observedMethods = @($methodStatistics.Values | ForEach-Object { $_.Method } | Sort-Object)
        Write-Warning (
            "No SMS or voice authentication steps were recognised. Observed method names: {0}. " +
            "If any of these are telephony methods, open an issue so the matching can be extended."
        ) -f ($observedMethods -join ', ')
    }
}

$registrationInventory = @(
    $registrationRecords |
        Sort-Object UserPrincipalName |
        ForEach-Object {
            [pscustomobject]@{
                UserId                = $_.UserId
                UserPrincipalName      = $_.UserPrincipalName
                UserDisplayName        = $_.UserDisplayName
                UserType               = $_.UserType
                IsAdmin                = $_.IsAdmin
                IsMfaRegistered        = $_.IsMfaRegistered
                IsMfaCapable           = $_.IsMfaCapable
                IsPasswordlessCapable  = $_.IsPasswordlessCapable
                IsSsprRegistered       = $_.IsSsprRegistered
                IsSsprCapable          = $_.IsSsprCapable
                PhoneRegistered        = $_.PhoneRegistered
                PhonePreferred         = $_.PhonePreferred
                PhishingResistantRegistered = $_.PhishingResistantRegistered
                StrongNonPhoneRegistered    = $_.StrongNonPhoneRegistered
                MethodsRegistered      = $_.MethodsRegistered -join ';'
                UserPreferredMethod    = $_.UserPreferredMethod
                SystemPreferredMethods = $_.SystemPreferredMethods -join ';'
                LastUpdatedDateTimeUtc  = Format-UtcDateTime -Value $_.LastUpdatedDateTime
            }
        }
)

$userMethodRows = @(
    $userMethodStatistics.Values |
        Sort-Object UserPrincipalName, Method |
        ForEach-Object {
            [pscustomobject]@{
                UserId             = $_.UserId
                UserPrincipalName   = $_.UserPrincipalName
                UserDisplayName     = $_.UserDisplayName
                AuthenticationMethod = $_.Method
                Attempts           = $_.Attempts
                Successful         = $_.Successful
                Failed             = $_.Failed
                UnknownResult      = $_.Unknown
                FirstSeenUtc       = Format-UtcDateTime -Value $_.FirstSeen
                LastSeenUtc        = Format-UtcDateTime -Value $_.LastSeen
                Applications       = @($_.Applications | Sort-Object) -join ';'
            }
        }
)

$methodSummaryRows = @(
    $methodStatistics.Values |
        Sort-Object @{ Expression = 'Successful'; Descending = $true }, Method |
        ForEach-Object {
            [pscustomobject]@{
                AuthenticationMethod = $_.Method
                UniqueUsers          = $_.Users.Count
                Attempts             = $_.Attempts
                Successful           = $_.Successful
                Failed               = $_.Failed
                UnknownResult        = $_.Unknown
                FirstSeenUtc         = Format-UtcDateTime -Value $_.FirstSeen
                LastSeenUtc          = Format-UtcDateTime -Value $_.LastSeen
                Applications         = @($_.Applications | Sort-Object) -join ';'
            }
        }
)

$phoneStatisticsByUpn = @{}
foreach ($phoneStat in $phoneStatistics.Values) {
    if (-not [string]::IsNullOrWhiteSpace($phoneStat.UserPrincipalName)) {
        $phoneStatisticsByUpn[$phoneStat.UserPrincipalName] = $phoneStat
    }
}

$consumedPhoneStatistics = Get-EmptyStringSet
$migrationActions = [System.Collections.Generic.List[object]]::new()

foreach ($registration in $registrationRecords) {
    $phoneUsage = $null
    if ($phoneStatistics.ContainsKey($registration.UserKey)) {
        $phoneUsage = $phoneStatistics[$registration.UserKey]
    }
    elseif (-not [string]::IsNullOrWhiteSpace($registration.UserPrincipalName) -and $phoneStatisticsByUpn.ContainsKey($registration.UserPrincipalName)) {
        $phoneUsage = $phoneStatisticsByUpn[$registration.UserPrincipalName]
    }

    if ($null -ne $phoneUsage) {
        [void]$consumedPhoneStatistics.Add($phoneUsage.UserKey)
    }

    if ($registration.PhoneRegistered -or $registration.PhonePreferred -or $null -ne $phoneUsage) {
        [void]$migrationActions.Add(
            (ConvertTo-MigrationActionRow -Registration $registration -PhoneUsage $phoneUsage)
        )
    }
}

foreach ($phoneUsage in $phoneStatistics.Values) {
    if (-not $consumedPhoneStatistics.Contains($phoneUsage.UserKey)) {
        [void]$migrationActions.Add(
            (ConvertTo-MigrationActionRow -Registration $null -PhoneUsage $phoneUsage)
        )
    }
}

$sortedMigrationActions = @(
    $migrationActions |
        Sort-Object `
            @{ Expression = { Get-RiskOrder -Risk $_.Risk }; Ascending = $true }, `
            @{ Expression = 'SuccessfulPhoneUses'; Descending = $true }, `
            UserPrincipalName
)

$criticalCount = @($sortedMigrationActions | Where-Object { $_.Risk -eq 'Critical' }).Count
$highCount = @($sortedMigrationActions | Where-Object { $_.Risk -eq 'High' }).Count
$mediumCount = @($sortedMigrationActions | Where-Object { $_.Risk -eq 'Medium' }).Count
$lowCount = @($sortedMigrationActions | Where-Object { $_.Risk -eq 'Low' }).Count
$successfulSmsUsers = @($phoneStatistics.Values | Where-Object { $_.SmsSuccessful -gt 0 }).Count
$successfulVoiceUsers = @($phoneStatistics.Values | Where-Object { $_.VoiceSuccessful -gt 0 }).Count
$successfulPhoneUsers = @(
    $phoneStatistics.Values |
        Where-Object { ($_.SmsSuccessful + $_.VoiceSuccessful) -gt 0 }
).Count
$activePhoneUsersNoPhishingResistant = @(
    $sortedMigrationActions |
        Where-Object { $_.SuccessfulPhoneUses -gt 0 -and -not $_.PhishingResistantRegistered }
).Count
$adminPhoneUsers = @(
    $sortedMigrationActions |
        Where-Object { $_.IsAdmin -and $_.SuccessfulPhoneUses -gt 0 }
).Count
$missingRegistrationCount = @(
    $sortedMigrationActions |
        Where-Object { -not $_.RegistrationRecordFound }
).Count

$executiveSummary = @(
    [pscustomobject]@{ Metric = 'Report generated (UTC)'; Value = Format-UtcDateTime -Value (Get-Date).ToUniversalTime(); Meaning = 'Time the report files were created.' }
    [pscustomobject]@{ Metric = 'Tenant'; Value = $tenantIdentifier; Meaning = 'Microsoft Entra tenant identifier from the Graph context or offline fixture.' }
    [pscustomobject]@{ Metric = 'Report period'; Value = "{0} to {1}" -f (Format-UtcDateTime $reportStartUtc), (Format-UtcDateTime $reportEndUtc); Meaning = 'Sign-in activity window included in this report.' }
    [pscustomobject]@{ Metric = 'Registration records'; Value = $registrationRecords.Count; Meaning = 'Enabled users returned by the authentication-method registration report.' }
    [pscustomobject]@{ Metric = 'Users with phone registered'; Value = @($registrationRecords | Where-Object { $_.PhoneRegistered }).Count; Meaning = 'Users with mobile, alternate mobile, or office phone registered.' }
    [pscustomobject]@{ Metric = 'Users with successful SMS use'; Value = $successfulSmsUsers; Meaning = 'Users with at least one successful SMS authentication step in the report period.' }
    [pscustomobject]@{ Metric = 'Users with successful voice use'; Value = $successfulVoiceUsers; Meaning = 'Users with at least one successful voice authentication step in the report period.' }
    [pscustomobject]@{ Metric = 'Users with successful SMS or voice use'; Value = $successfulPhoneUsers; Meaning = 'Distinct users with successful observed telephony authentication.' }
    [pscustomobject]@{ Metric = 'Active phone users without a phishing-resistant method'; Value = $activePhoneUsersNoPhishingResistant; Meaning = 'Users with successful SMS or voice use and no FIDO2, passkey, or Windows Hello for Business registration. Highest-priority migration population.' }
    [pscustomobject]@{ Metric = 'Administrators with successful phone use'; Value = $adminPhoneUsers; Meaning = 'Privileged users observed successfully using SMS or voice.' }
    [pscustomobject]@{ Metric = 'Critical migration actions'; Value = $criticalCount; Meaning = 'Administrators with successful phone use, or successful phone use without a phishing-resistant method.' }
    [pscustomobject]@{ Metric = 'High migration actions'; Value = $highCount; Meaning = 'Phone is the only registered MFA method, or an administrator has phone methods and no phishing-resistant credential.' }
    [pscustomobject]@{ Metric = 'Medium migration actions'; Value = $mediumCount; Meaning = 'Successful phone use with a phishing-resistant method registered, or phone preferred with a non-phone fallback.' }
    [pscustomobject]@{ Metric = 'Low migration actions'; Value = $lowCount; Meaning = 'Phone registered but not preferred or used, with a non-phone method available.' }
    [pscustomobject]@{ Metric = 'Action rows missing registration data'; Value = $missingRegistrationCount; Meaning = 'Observed phone users not returned by the registration report; verify manually.' }
    [pscustomobject]@{ Metric = 'Sign-ins processed'; Value = $counters.SignInsProcessed; Meaning = 'Sign-in records read from Graph or the offline fixture.' }
    [pscustomobject]@{ Metric = 'Authentication steps processed'; Value = $counters.AuthenticationStepsProcessed; Meaning = 'Individual authentication steps included in usage aggregation.' }
    [pscustomobject]@{ Metric = 'Sign-ins without authentication details'; Value = $counters.SignInsWithoutAuthenticationDetails; Meaning = 'Sign-ins that could not contribute authentication-method usage.' }
)

$executiveSummaryPath = Join-Path -Path $resolvedOutputPath -ChildPath 'Executive-Summary.csv'
$registrationPath = Join-Path -Path $resolvedOutputPath -ChildPath 'Registration-Inventory.csv'
$userUsagePath = Join-Path -Path $resolvedOutputPath -ChildPath 'Authentication-Usage-By-User.csv'
$methodSummaryPath = Join-Path -Path $resolvedOutputPath -ChildPath 'Authentication-Method-Summary.csv'
$migrationPath = Join-Path -Path $resolvedOutputPath -ChildPath 'SmsVoice-Migration-Actions.csv'
$htmlPath = Join-Path -Path $resolvedOutputPath -ChildPath 'Entra-Authentication-Readiness-Report.html'
$manifestPath = Join-Path -Path $resolvedOutputPath -ChildPath 'Report-Manifest.json'

$executiveSummary | Export-Csv -LiteralPath $executiveSummaryPath -NoTypeInformation -Encoding utf8
$registrationInventory | Export-Csv -LiteralPath $registrationPath -NoTypeInformation -Encoding utf8
$userMethodRows | Export-Csv -LiteralPath $userUsagePath -NoTypeInformation -Encoding utf8
$methodSummaryRows | Export-Csv -LiteralPath $methodSummaryPath -NoTypeInformation -Encoding utf8
$sortedMigrationActions | Export-Csv -LiteralPath $migrationPath -NoTypeInformation -Encoding utf8

$riskSummary = @(
    [pscustomobject]@{ Risk = 'Critical'; Users = $criticalCount }
    [pscustomobject]@{ Risk = 'High'; Users = $highCount }
    [pscustomobject]@{ Risk = 'Medium'; Users = $mediumCount }
    [pscustomobject]@{ Risk = 'Low'; Users = $lowCount }
)

$summaryHtml = $executiveSummary |
    ConvertTo-Html -Fragment -PreContent '<h2>Executive summary</h2>' |
    Out-String
$riskHtml = $riskSummary |
    ConvertTo-Html -Fragment -PreContent '<h2>SMS/voice migration risk</h2>' |
    Out-String
$methodHtml = $methodSummaryRows |
    Select-Object AuthenticationMethod, UniqueUsers, Attempts, Successful, Failed, LastSeenUtc |
    ConvertTo-Html -Fragment -PreContent '<h2>Observed authentication-method usage</h2>' |
    Out-String
$actionRowsForHtml = @($sortedMigrationActions | Select-Object -First $HtmlActionLimit)

if ($actionRowsForHtml.Count -gt 0) {
    $actionHtml = $actionRowsForHtml |
        Select-Object Risk, UserPrincipalName, UserDisplayName, IsAdmin, PhoneRegistered, UserPreferredMethod, SmsSuccessful, VoiceSuccessful, LastPhoneUseUtc, PhishingResistantRegistered, StrongNonPhoneRegistered, RecommendedAction |
        ConvertTo-Html -Fragment -PreContent ("<h2>Prioritized migration actions</h2><p>Showing {0} of {1} rows. See the CSV file for the complete list.</p>" -f $actionRowsForHtml.Count, $sortedMigrationActions.Count) |
        Out-String
}
else {
    $actionHtml = '<h2>Prioritized migration actions</h2><p>No phone registration, preference, or usage was identified in the available data.</p>'
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft Entra Authentication Readiness Report</title>
<style>
body { font-family: "Segoe UI", Arial, sans-serif; margin: 32px; color: #242424; }
h1 { color: #0f6cbd; }
h2 { margin-top: 32px; color: #174a7e; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 24px; font-size: 13px; }
th { background: #0f6cbd; color: white; text-align: left; }
th, td { border: 1px solid #d1d1d1; padding: 7px; vertical-align: top; }
tr:nth-child(even) { background: #f7f7f7; }
.callout { background: #eef6fc; border-left: 5px solid #0f6cbd; padding: 12px 16px; }
.warning { background: #fff4ce; border-left: 5px solid #986f0b; padding: 12px 16px; }
.footer { margin-top: 32px; font-size: 12px; color: #616161; }
</style>
</head>
<body>
<h1>Microsoft Entra Authentication Readiness Report</h1>
<div class="callout">
<strong>Priority population:</strong> $activePhoneUsersNoPhishingResistant users successfully used SMS or voice during the report period and have no phishing-resistant method (FIDO2, passkey, or Windows Hello for Business) registered.
</div>
$summaryHtml
$riskHtml
$methodHtml
$actionHtml
<h2>Interpretation and limitations</h2>
<div class="warning">
<ul>
<li>Policy scope, method registration, and observed use are different measurements.</li>
<li>Registration data can be delayed by up to 36 hours and does not include disabled users.</li>
<li>A previous MFA claim can satisfy a sign-in without a new authentication challenge.</li>
<li>Authentication-Usage-Events.csv contains all recorded methods with user and UTC timestamps. PreviouslySatisfied rows represent token or claim reuse, not a fresh method challenge.</li>
<li>No observed SMS or voice event does not prove the method is never used outside the available retention period.</li>
<li>Only interactive user sign-ins are collected. SMS and voice challenges occur in interactive sign-ins, so telephony coverage is complete, but totals exclude non-interactive sign-ins.</li>
<li>"Phishing-resistant" means FIDO2, a device-bound passkey, or Windows Hello for Business is registered. Authenticator phone sign-in is passwordless but is not treated as phishing-resistant.</li>
<li>Review critical and high rows before changing any policy or deleting registered methods.</li>
</ul>
</div>
<div class="footer">Generated in $inputMode mode at $(Format-UtcDateTime -Value (Get-Date).ToUniversalTime()). This script performs read-only Microsoft Graph operations.</div>
</body>
</html>
"@

Set-Content -LiteralPath $htmlPath -Value $html -Encoding utf8

$outputFiles = [ordered]@{
    ExecutiveSummary            = $executiveSummaryPath
    RegistrationInventory       = $registrationPath
    AuthenticationUsageByUser   = $userUsagePath
    AuthenticationMethodSummary = $methodSummaryPath
    SmsVoiceMigrationActions    = $migrationPath
    HtmlReport                  = $htmlPath
}

if ($IncludeEventDetails -and (Test-Path -LiteralPath $eventFilePath -PathType Leaf)) {
    $outputFiles.AuthenticationUsageEvents = $eventFilePath
}

$manifest = [ordered]@{
    SchemaVersion        = '1.1'
    GeneratedDateTimeUtc = Format-UtcDateTime -Value (Get-Date).ToUniversalTime()
    InputMode            = $inputMode
    TenantId             = $tenantIdentifier
    ReportStartUtc       = Format-UtcDateTime -Value $reportStartUtc
    ReportEndUtc         = Format-UtcDateTime -Value $reportEndUtc
    LookbackDays         = $LookbackDays
    WindowHours          = $WindowHours
    IncludeEventDetails  = [bool]$IncludeEventDetails
    IncludeMethodDetails = [bool]$IncludeMethodDetails
    Counts               = [ordered]@{
        RegistrationRecords                    = $registrationRecords.Count
        PhoneRegisteredUsers                   = @($registrationRecords | Where-Object { $_.PhoneRegistered }).Count
        SuccessfulSmsUsers                     = $successfulSmsUsers
        SuccessfulVoiceUsers                   = $successfulVoiceUsers
        SuccessfulPhoneUsers                   = $successfulPhoneUsers
        ActivePhoneUsersNoPhishingResistant = $activePhoneUsersNoPhishingResistant
        AdministratorPhoneUsers                = $adminPhoneUsers
        Critical                               = $criticalCount
        High                                   = $highCount
        Medium                                 = $mediumCount
        Low                                    = $lowCount
        SignInsProcessed                       = $counters.SignInsProcessed
        AuthenticationStepsProcessed           = $counters.AuthenticationStepsProcessed
    }
    Files                = $outputFiles
}

$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$outputFiles.ReportManifest = $manifestPath

Write-Information -MessageData 'Report completed successfully.' -InformationAction Continue
Write-Information -MessageData "Output directory: $resolvedOutputPath" -InformationAction Continue
Write-Information -MessageData "Critical actions: $criticalCount" -InformationAction Continue
Write-Information -MessageData "High actions: $highCount" -InformationAction Continue
Write-Information -MessageData "Active SMS/voice users without a phishing-resistant method: $activePhoneUsersNoPhishingResistant" -InformationAction Continue

[pscustomobject]@{
    OutputPath                              = $resolvedOutputPath
    TenantId                               = $tenantIdentifier
    InputMode                              = $inputMode
    RegistrationRecords                    = $registrationRecords.Count
    SignInsProcessed                       = $counters.SignInsProcessed
    AuthenticationStepsProcessed           = $counters.AuthenticationStepsProcessed
    ActivePhoneUsersNoPhishingResistant = $activePhoneUsersNoPhishingResistant
    CriticalActions                        = $criticalCount
    HighActions                            = $highCount
    HtmlReport                             = $htmlPath
    Manifest                               = $manifestPath
}
