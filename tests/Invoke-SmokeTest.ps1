#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Expected,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Actual,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if ($Expected -ne $Actual) {
        throw "$Message Expected '$Expected' but found '$Actual'."
    }
}

$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$scriptPath = Join-Path -Path $repositoryRoot -ChildPath 'Get-EntraAuthenticationReadinessReport.ps1'
$fixturePath = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures\sample-authentication-data.json'
$outputPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath (
    'Entra-Authentication-Readiness-SmokeTest-{0}' -f [guid]::NewGuid().ToString('N')
)

try {
    $result = & $scriptPath `
        -OfflineDataPath $fixturePath `
        -OutputPath $outputPath `
        -LookbackDays 30 `
        -IncludeEventDetails `
        -IncludeMethodDetails

    $expectedFiles = @(
        'Executive-Summary.csv'
        'Registration-Inventory.csv'
        'Authentication-Usage-By-User.csv'
        'Authentication-Method-Summary.csv'
        'SmsVoice-Migration-Actions.csv'
        'Authentication-Usage-Events.csv'
        'Entra-Authentication-Readiness-Report.html'
        'Report-Manifest.json'
    )

    foreach ($file in $expectedFiles) {
        $path = Join-Path -Path $outputPath -ChildPath $file
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Expected report file was not created: $file"
        }
    }

    $manifestPath = Join-Path -Path $outputPath -ChildPath 'Report-Manifest.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

    Assert-Equal -Expected 'Offline' -Actual $manifest.InputMode -Message 'Unexpected input mode.'
    Assert-Equal -Expected 'offline-test-tenant' -Actual $manifest.TenantId -Message 'Unexpected tenant identifier.'
    Assert-Equal -Expected 4 -Actual $manifest.Counts.RegistrationRecords -Message 'Unexpected registration count.'
    Assert-Equal -Expected 4 -Actual $manifest.Counts.PhoneRegisteredUsers -Message 'Unexpected phone registration count.'
    Assert-Equal -Expected 2 -Actual $manifest.Counts.SuccessfulSmsUsers -Message 'Unexpected successful SMS user count.'
    Assert-Equal -Expected 1 -Actual $manifest.Counts.SuccessfulVoiceUsers -Message 'Unexpected successful voice user count.'
    Assert-Equal -Expected 3 -Actual $manifest.Counts.SuccessfulPhoneUsers -Message 'Unexpected successful phone user count.'
    Assert-Equal -Expected 1 -Actual $manifest.Counts.ActivePhoneUsersNoPhishingResistant -Message 'Unexpected priority population.'
    Assert-Equal -Expected 1 -Actual $manifest.Counts.AdministratorPhoneUsers -Message 'Unexpected administrator phone user count.'
    Assert-Equal -Expected 2 -Actual $manifest.Counts.Critical -Message 'Unexpected critical action count.'
    Assert-Equal -Expected 0 -Actual $manifest.Counts.High -Message 'Unexpected high action count.'
    Assert-Equal -Expected 1 -Actual $manifest.Counts.Medium -Message 'Unexpected medium action count.'
    Assert-Equal -Expected 2 -Actual $manifest.Counts.Low -Message 'Unexpected low action count.'
    Assert-Equal -Expected 6 -Actual $manifest.Counts.SignInsProcessed -Message 'Unexpected sign-in count.'
    Assert-Equal -Expected 7 -Actual $manifest.Counts.AuthenticationStepsProcessed -Message 'Unexpected authentication-step count.'

    $migrationPath = Join-Path -Path $outputPath -ChildPath 'SmsVoice-Migration-Actions.csv'
    $migrationActions = @(Import-Csv -LiteralPath $migrationPath)
    Assert-Equal -Expected 5 -Actual $migrationActions.Count -Message 'Unexpected migration action row count.'
    Assert-Equal -Expected 2 -Actual @($migrationActions | Where-Object { $_.Risk -eq 'Critical' }).Count -Message 'Unexpected critical CSV rows.'
    Assert-Equal -Expected 0 -Actual @($migrationActions | Where-Object { $_.Risk -eq 'High' }).Count -Message 'Unexpected high CSV rows.'
    Assert-Equal -Expected 1 -Actual @($migrationActions | Where-Object { $_.Risk -eq 'Medium' }).Count -Message 'Unexpected medium CSV rows.'
    Assert-Equal -Expected 2 -Actual @($migrationActions | Where-Object { $_.Risk -eq 'Low' }).Count -Message 'Unexpected low CSV rows.'

    $riskByUpn = @{}
    foreach ($row in $migrationActions) { $riskByUpn[$row.UserPrincipalName] = $row.Risk }
    Assert-Equal -Expected 'Critical' -Actual $riskByUpn['alice@example.com'] -Message 'Alice (SMS use, no phishing-resistant method) should be Critical.'
    Assert-Equal -Expected 'Critical' -Actual $riskByUpn['bob@example.com'] -Message 'Bob (administrator using voice) should be Critical.'
    Assert-Equal -Expected 'Low' -Actual $riskByUpn['carol@example.com'] -Message 'Carol (phone registered, Authenticator preferred, no use) should be Low.'
    Assert-Equal -Expected 'Medium' -Actual $riskByUpn['dana@example.com'] -Message 'Dana (SMS use with Windows Hello registered) should be Medium.'
    Assert-Equal -Expected 'Low' -Actual $riskByUpn['eve@example.com'] -Message 'Eve (failed voice only, no registration) should be Low.'

    $eventPath = Join-Path -Path $outputPath -ChildPath 'Authentication-Usage-Events.csv'
    $events = @(Import-Csv -LiteralPath $eventPath)
    Assert-Equal -Expected 7 -Actual $events.Count -Message 'Unexpected event row count.'
    if (@($events | Where-Object { -not [string]::IsNullOrWhiteSpace($_.MethodDetail) }).Count -eq 0) {
        throw 'Method details were requested but no method detail was exported.'
    }
    Assert-Equal -Expected 3 -Actual @($events | Where-Object { $_.TelephonyType -eq 'SMS' }).Count -Message 'Unexpected SMS event count (Text message and SMS should both match).'
    Assert-Equal -Expected 2 -Actual @($events | Where-Object { $_.TelephonyType -eq 'VOICE' }).Count -Message 'Unexpected voice event count (Voice call and Phone call should both match).'

    $htmlPath = Join-Path -Path $outputPath -ChildPath 'Entra-Authentication-Readiness-Report.html'
    if (-not (Select-String -LiteralPath $htmlPath -SimpleMatch 'Microsoft Entra Authentication Readiness Report' -Quiet)) {
        throw 'The HTML report title was not found.'
    }

    Assert-Equal -Expected 2 -Actual $result.CriticalActions -Message 'Unexpected result critical action count.'
    Assert-Equal -Expected 0 -Actual $result.HighActions -Message 'Unexpected result high action count.'

    Write-Host 'Offline smoke test passed.'
}
finally {
    if (Test-Path -LiteralPath $outputPath) {
        Remove-Item -LiteralPath $outputPath -Recurse -Force
    }
}
