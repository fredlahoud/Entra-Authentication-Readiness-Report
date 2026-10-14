# Microsoft Entra Authentication Readiness Report

[![Validate](https://github.com/fredlahoud/Entra-Authentication-Readiness-Report/actions/workflows/validate.yml/badge.svg)](https://github.com/fredlahoud/Entra-Authentication-Readiness-Report/actions/workflows/validate.yml)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![License:LHIT](https://img.shields.io/badge/License-LHIT-yellow.svg)](LICENSE)

A read-only PowerShell reporting tool that helps Microsoft Entra administrators understand authentication-method readiness and prioritize migration away from SMS and voice authentication.

The script combines authentication-method registration data with observed sign-in authentication steps, then produces CSV reports, an executive HTML summary, and a machine-readable manifest.

> [!IMPORTANT]
> The generated reports contain identity and authentication-usage data. Store them securely, restrict access, and never commit real tenant reports to source control.

## What it does

- Inventories registered authentication methods for enabled users.
- Summarizes authentication methods observed in sign-in records.
- Identifies successful and failed SMS and voice authentication.
- Prioritizes users for migration based on observed usage, administrator status, and passwordless capability.
- Splits sign-in queries into configurable time windows to reduce Microsoft Graph timeouts in larger tenants.
- Supports an offline mode for testing the complete reporting pipeline without connecting to Microsoft Graph.
- Performs read-only Microsoft Graph operations and does not modify users, methods, policies, groups, or Conditional Access.

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7 or later.
- The following Microsoft Graph PowerShell modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Reports`
- Delegated Microsoft Graph permission `AuditLog.Read.All`.
- A supported Microsoft Entra role, such as Reports Reader, Security Reader, or Global Reader.
- Administrator consent for `AuditLog.Read.All` in the target tenant.

Install the required modules for the current user:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Reports -Scope CurrentUser
```

## Quick start

Clone the repository and enter its directory:

```powershell
git clone https://github.com/fredlahoud/Entra-Authentication-Readiness-Report.git
Set-Location .\Entra-Authentication-Readiness-Report
```

Run a 30-day report by using a verified tenant domain:

```powershell
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId YourDomain.onmicrosoft.com `
    -OutputPath .\output
```

The output directory must either not exist or be empty. On first use, Microsoft Graph prompts for sign-in and any required consent.

### Select an account explicitly

```powershell
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId YourDomain.onmicrosoft.com `
    -LoginHint analyst@YourDomain.com `
    -UseDeviceCode `
    -ForceSignIn `
    -OutputPath .\output
```

Device-code sign-in can be blocked by tenant policy. OMIT `-UseDeviceCode` to use the standard interactive sign-in flow.

### Reduce query-window size

For a large tenant, reduce the Graph query window:

```powershell
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId YourDomain.onmicrosoft.com `
    -LookbackDays 14 `
    -WindowHours 6 `
    -OutputPath .\output
```

### Control event-level data

Event-level export is enabled by default. Disable it for a smaller, summary-only report:

```powershell
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId YourDomain.onmicrosoft.com `
    -IncludeEventDetails:$false `
    -OutputPath .\output
```

Authentication method details can contain personal information, such as a partially displayed phone number. Include them only when needed:

```powershell
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -TenantId YourDomain.onmicrosoft.com `
    -IncludeMethodDetails `
    -OutputPath .\output
```

`-IncludeMethodDetails` requires the event-level export.

## Report files

| File | Purpose |
| --- | --- |
| `Executive-Summary.csv` | Key readiness, usage, and migration metrics. |
| `Registration-Inventory.csv` | User authentication registration and capability inventory. |
| `Authentication-Usage-By-User.csv` | Authentication-method attempts and outcomes by user. |
| `Authentication-Method-Summary.csv` | Tenant-wide usage totals by authentication method. |
| `SmsVoice-Migration-Actions.csv` | Prioritized SMS and voice migration actions. |
| `Authentication-Usage-Events.csv` | Optional event-level authentication-step data. |
| `Entra-Authentication-Readiness-Report.html` | Executive summary and prioritized action report. |
| `Report-Manifest.json` | Run settings, counts, report period, and output file paths. |

## Migration priority logic

| Priority | Condition |
| --- | --- |
| Critical | Successful SMS or voice use and the user is not reported as passwordless-capable. |
| High | An administrator successfully used SMS or voice, or a user has phone authentication registered or preferred without passwordless capability. |
| Medium | Successful SMS or voice use and an existing passwordless-capable method is reported. |
| Low | Phone authentication is registered, preferred, or observed without successful phone use during the report period. |

Treat these priorities as investigation guidance rather than automated remediation decisions. Validate each user's sign-in and recovery journeys before changing policy or removing a method.

## Data interpretation and limitations

- Authentication policy scope, method registration, and observed method use are different measurements.
- Registration reporting can be delayed by up to 36 hours and excludes disabled users.
- Microsoft Entra sign-in retention is normally 7 days for Free tenants and 30 days for P1/P2 tenants.
- A previous MFA claim can satisfy a sign-in without a new authentication challenge.
- No observed SMS or voice event does not prove that the method is never used outside the available retention period.
- `PreviouslySatisfied` event rows represent token or claim reuse, not a fresh authentication-method challenge.

See the Microsoft Graph documentation for [authentication-method registration details](https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails) and [sign-in records](https://learn.microsoft.com/graph/api/signin-list).

## Offline example and validation

Run the reporting pipeline with fictional sample data:

```powershell
.\Get-EntraAuthenticationReadinessReport.ps1 `
    -OfflineDataPath .\tests\fixtures\sample-authentication-data.json `
    -OutputPath .\sample-output `
    -IncludeMethodDetails
```

Run the repository smoke test:

```powershell
.\tests\Invoke-SmokeTest.ps1
```

Run static analysis when PSScriptAnalyzer is installed:

```powershell
Invoke-ScriptAnalyzer -Path .\Get-EntraAuthenticationReadinessReport.ps1 -Recurse -Severity Warning,Error
```

## Security and privacy

The `.gitignore` file excludes the report filenames generated by this tool, but source-control exclusions are not a substitute for access controls. Review the output before sharing it, use encrypted storage where appropriate, and follow your organization's retention and data-handling requirements.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

This project is licensed under the [LHIT License](LICENSE).

Microsoft, Microsoft Entra, and Microsoft Graph are trademarks of the Microsoft group of companies. This project is independently maintained and is not an official Microsoft product.
