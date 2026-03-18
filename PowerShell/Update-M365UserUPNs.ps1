###################################################################################
#
# Update-M365UserUPNs.ps1 - Updates licensed M365 users' UPNs to match their
# primary SMTP address. Connects to Microsoft Graph, retrieves all cloud-only
# licensed users, and renames any UPN that doesn't already match their Mail or
# primary SMTP ProxyAddress. Directory-synced (on-prem) accounts are skipped
# automatically since their UPNs must be managed from AD, not the cloud.
#
# Supports -WhatIf for a full dry-run before committing any changes. All
# processed users are written to a timestamped CSV audit log regardless of
# outcome (changed, skipped, error, or dry-run).
#
# Requires: Microsoft.Graph.Authentication + Microsoft.Graph.Users modules
# Requires: User.ReadWrite.All Graph permission at runtime
#
# Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser -Force
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts | v2.1
#
# RUN FOR USAGE: .\Update-M365UserUPNs.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".\UPN_Changes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

============== UPDATE M365 USER UPNs (UberGuidoZ) ==============

DESCRIPTION:
    Updates all licensed M365 users' UPNs to match their primary SMTP
    address. Connects to Microsoft Graph, retrieves all cloud-only licensed
    users, and renames any UPN that doesn't already match their Mail or
    primary SMTP ProxyAddress.
    - Directory-synced (on-prem) accounts are skipped automatically
    - Supports -WhatIf for a full dry-run before committing any changes
    - All processed users are written to a timestamped CSV audit log
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

REQUIREMENTS:
    Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser -Force
    Requires User.ReadWrite.All Graph permission at runtime.

SYNTAX:
    .\Update-M365UserUPNs.ps1 [[-ExportPath] <String>] [-WhatIf] [-h]

PARAMETERS:
    -ExportPath <String>
        Optional. Path where the CSV audit log will be saved.
        Defaults to a timestamped file in the current directory.

    -WhatIf
        Optional. Performs a full dry-run showing what would change
        without making any updates. All results are still logged to CSV.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Run live update with default log path
    .\Update-M365UserUPNs.ps1

    Example 2: Dry-run to preview changes without applying them
    .\Update-M365UserUPNs.ps1 -WhatIf

    Example 3: Run live update and save log to a specific path
    .\Update-M365UserUPNs.ps1 -ExportPath "C:\Logs\UPN_Changes.csv"

    Example 4: Dry-run with a specific log path
    .\Update-M365UserUPNs.ps1 -WhatIf -ExportPath "C:\Logs\UPN_WhatIf.csv"

    Example 5: Export with timestamp in filename
    .\Update-M365UserUPNs.ps1 -ExportPath "C:\Logs\UPN_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Example 6: Show this help
    .\Update-M365UserUPNs.ps1 -h

OUTPUT:
    Displays a per-user status line on screen as each account is processed:
      [+] Name: old@domain.com -> new@domain.com   (updated)
      [?] Name: old@domain.com -> new@domain.com   (dry-run only)
    Skipped and no-change accounts are logged silently (-Verbose to see them).

    CSV audit log columns:
    DisplayName, CurrentUPN, PrimaryEmail, NewUPN, Action, Reason, Success, Timestamp

    Action values: Update, WhatIf, NoChange, Skipped, Error

NOTES:
    - Requires an interactive sign-in to Microsoft Graph at runtime
    - Directory-synced accounts are skipped; manage their UPNs from on-prem AD
    - UPN comparison is case-insensitive
    - The script always disconnects from Graph on exit, even if an error occurs

=================================================================

"@ -ForegroundColor Cyan
    exit 0
}

$ErrorActionPreference = 'Stop'

Write-Host "`n=== M365 UPN Update Tool ===" -ForegroundColor Cyan

# -- Module check (collect all missing before failing) ------------------------
$missing = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users') |
    Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    Write-Error "Missing required module(s): $($missing -join ', '). Install with: Install-Module <n> -Scope CurrentUser"
}

# -- Connect ------------------------------------------------------------------
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome
    $context = Get-MgContext
    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
}

# -- Main block wrapped in try/finally to guarantee disconnect ----------------
try {

    # Retrieve only licensed users via server-side OData filter (avoids pulling
    # the entire tenant client-side just to filter locally)
    Write-Host "Retrieving licensed users from Microsoft Graph..." -ForegroundColor Cyan
    try {
        $users = Get-MgUser -All `
            -Filter "assignedLicenses/`$count ne 0" `
            -ConsistencyLevel eventual `
            -CountVariable userCount `
            -Property Id, UserPrincipalName, Mail, ProxyAddresses, OnPremisesSyncEnabled, DisplayName, AccountEnabled, AssignedLicenses

        Write-Host "Found $($users.Count) licensed user(s)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to retrieve users: $_"
    }

    # -- Process --------------------------------------------------------------
    $results      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $changedCount = 0
    $whatIfCount  = 0
    $skippedCount = 0
    $errorCount   = 0
    $i            = 0

    Write-Host "Processing licensed users..." -ForegroundColor Cyan

    foreach ($user in $users) {
        $i++
        Write-Progress -Activity "Processing users" `
                       -Status "$i of $($users.Count): $($user.DisplayName)" `
                       -PercentComplete (($i / $users.Count) * 100)

        $result = [PSCustomObject]@{
            DisplayName  = $user.DisplayName
            CurrentUPN   = $user.UserPrincipalName
            PrimaryEmail = $null
            NewUPN       = $null
            Action       = 'NoChange'
            Reason       = $null
            Success      = $null          # $null = not attempted; $true/$false = attempted
            Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }

        try {
            # Resolve primary SMTP: prefer Mail, fall back to uppercase SMTP: ProxyAddress
            $primaryEmail = if ($user.Mail) {
                $user.Mail
            } elseif ($user.ProxyAddresses) {
                $smtp = $user.ProxyAddresses | Where-Object { $_ -clike "SMTP:*" } | Select-Object -First 1
                if ($smtp) { $smtp -replace '^SMTP:', '' }
            }

            $result.PrimaryEmail = $primaryEmail

            if (-not $primaryEmail) {
                $result.Action  = 'Skipped'
                $result.Reason  = 'No primary email found'
                $skippedCount++
                $results.Add($result)
                Write-Warning "[$($user.DisplayName)] No primary email — skipping"
                continue
            }

            if ($user.OnPremisesSyncEnabled -eq $true) {
                $result.Action  = 'Skipped'
                $result.Reason  = 'Directory-synced (manage UPN from on-prem AD)'
                $skippedCount++
                $results.Add($result)
                Write-Verbose "[$($user.DisplayName)] On-prem synced — skipping"
                continue
            }

            # -ieq makes case-insensitive intent explicit (UPNs are case-insensitive)
            if ($user.UserPrincipalName -ieq $primaryEmail) {
                $result.Action  = 'NoChange'
                $result.Reason  = 'UPN already matches primary email'
                $result.Success = $true
                $results.Add($result)
                Write-Verbose "[$($user.DisplayName)] Already correct — no change needed"
                continue
            }

            $result.NewUPN = $primaryEmail
            $result.Action = 'Update'

            if ($PSCmdlet.ShouldProcess($user.DisplayName, "Change UPN: $($user.UserPrincipalName) -> $primaryEmail")) {
                Update-MgUser -UserId $user.Id -UserPrincipalName $primaryEmail
                $result.Success = $true
                $result.Reason  = 'Updated successfully'
                $changedCount++
                Write-Host "[+] $($user.DisplayName): $($user.UserPrincipalName) -> $primaryEmail" -ForegroundColor Green
            }
            else {
                $result.Action  = 'WhatIf'
                $result.Reason  = 'Dry-run only — no change applied'
                $result.Success = $null
                $whatIfCount++
                Write-Host "[?] $($user.DisplayName): $($user.UserPrincipalName) -> $primaryEmail" -ForegroundColor Yellow
            }
        }
        catch {
            $result.Action  = 'Error'
            $result.Reason  = $_.Exception.Message
            $result.Success = $false
            $errorCount++
            Write-Error "[-] $($user.DisplayName) failed: $_" -ErrorAction Continue
        }

        $results.Add($result)
    }

    Write-Progress -Activity "Processing users" -Completed

    # -- Export audit log -----------------------------------------------------
    Write-Host "`nExporting audit log to: $ExportPath" -ForegroundColor Cyan
    try {
        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "Audit log saved successfully" -ForegroundColor Green
    }
    catch {
        Write-Warning "Export failed: $_"
    }

    # -- Summary --------------------------------------------------------------
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total processed : $($users.Count)"
    Write-Host "Changed         : $changedCount"  -ForegroundColor Green
    if ($WhatIfPreference) {
        Write-Host "Would change    : $whatIfCount" -ForegroundColor Yellow
    }
    Write-Host "Skipped         : $skippedCount"  -ForegroundColor Yellow
    Write-Host "Errors          : $errorCount"    -ForegroundColor $(if ($errorCount -gt 0) { 'Red' } else { 'White' })

    if ($WhatIfPreference) {
        Write-Host "`nDRY-RUN MODE — No changes were applied" -ForegroundColor Yellow
    }

}
finally {
    # Always disconnect, even if the script errors out mid-run
    Disconnect-MgGraph | Out-Null
    Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Gray
}