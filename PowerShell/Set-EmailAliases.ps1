###################################################################################
#
# Set-EmailAliases.ps1 - Standardizes Office 365 email addresses and aliases
# with configurable domains and naming patterns. Sets primary email and ensures
# required aliases exist. Supports conflict resolution and domain preservation.
#
# Version: 2.4 | Date: 2026-03-14
#
# Requires Exchange Online Management module and admin permissions.
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
#
# RUN FOR USAGE: .\Set-EmailAliases.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$PrimaryDomain,
    
    [Parameter()]
    [string]$AliasDomain,
    
    [Parameter()]
    [string]$PrimaryPattern = "{FirstInitial}{LastName}",
    
    [Parameter()]
    [string[]]$AliasPatterns = @('{FirstName}', '{FirstInitial}{LastName}'),
    
    [Parameter()]
    [string]$ConflictPattern = "{FirstName}{LastInitial}",
    
    [Parameter()]
    [string[]]$PreserveDomains = @(),
    
    [Parameter()]
    [string]$LogPath = ".\EmailAliasUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",

    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

============== SET EMAIL ALIASES (UberGuidoZ) =======================

DESCRIPTION:
    Standardizes Office 365 email addresses and aliases for all user
    mailboxes based on configurable domain names and naming patterns.
    Sets primary email and ensures required aliases exist, with
    conflict resolution and preservation of non-managed domain aliases.
    Uses .NET file operations for log writing to ensure WhatIf immunity.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

    Default behavior:
    - Primary  : FirstInitialLastName@domainOne
    - Aliases  : FirstName@domainOne, FirstName@domainTwo,
                 FirstInitialLastName@domainTwo
    - Conflict : FirstNameLastInitial@Domain

SYNTAX:
    .\Set-EmailAliases.ps1 [[-PrimaryDomain] <String>] [[-AliasDomain] <String>]
        [[-PrimaryPattern] <String>] [[-AliasPatterns] <String[]>]
        [[-ConflictPattern] <String>] [[-PreserveDomains] <String[]>]
        [[-LogPath] <String>] [-WhatIf] [-Confirm] [-h]

PARAMETERS:
    -PrimaryDomain <String>
        Domain for primary email addresses.
        Default: value of `$domainOne set at top of script.

    -AliasDomain <String>
        Domain for alias email addresses.
        Default: value of `$domainTwo set at top of script.

    -PrimaryPattern <String>
        Pattern for primary email address. Default: {FirstInitial}{LastName}
        Tokens: {FirstInitial}, {LastInitial}, {FirstName}, {LastName}

    -AliasPatterns <String[]>
        Array of patterns for alias addresses.
        Default: @('{FirstName}', '{FirstInitial}{LastName}')
        Applied to both PrimaryDomain and AliasDomain.

    -ConflictPattern <String>
        Pattern used when preferred alias is already taken.
        Default: {FirstName}{LastInitial}

    -PreserveDomains <String[]>
        Domains whose existing aliases should never be removed.
        Default: all domains except PrimaryDomain and AliasDomain.

    -LogPath <String>
        Path for the detailed log file.
        Default: .\EmailAliasUpdate_<timestamp>.log

    -WhatIf
        Preview all changes without applying them. Log is still written.

    -Confirm
        Prompt for confirmation before each change.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Dry run with default settings
    .\Set-EmailAliases.ps1 -WhatIf

    Example 2: Run with custom domains
    .\Set-EmailAliases.ps1 -PrimaryDomain "contoso.com" -AliasDomain "contoso.net"

    Example 3: Custom primary pattern and aliases
    .\Set-EmailAliases.ps1 -PrimaryPattern "{FirstName}.{LastName}" -AliasPatterns @('{FirstInitial}{LastName}')

    Example 4: Preserve aliases from additional domains
    .\Set-EmailAliases.ps1 -PreserveDomains @("legacy.com", "old-domain.net")

    Example 5: Full run with custom log path
    .\Set-EmailAliases.ps1 -LogPath "C:\Logs\AliasUpdate.log"

    Example 6: Show this help
    .\Set-EmailAliases.ps1 -h

OUTPUT:
    All actions are logged to console and to a .log file. Log columns:
    - Timestamp   : Date and time of the entry
    - Level       : Info / Warning / Error / Success
    - Message     : Action taken or issue encountered
    A summary at the end shows total Successful, Errors, and Skipped counts.

NOTES:
    - Requires the ExchangeOnlineManagement module (installs automatically if missing)
    - Must be connected to or able to connect to Exchange Online
    - Does NOT require NT AUTHORITY\SYSTEM; runs as the current admin user
    - Log file is always written even in -WhatIf mode (.NET file ops bypass WhatIf)
    - Domains with no changes will still appear in the log for audit purposes

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# ==============================================================================
# DOMAIN CONFIGURATION - Set your domains here before running
# ==============================================================================
#
# Change $domainOne and $domainTwo to your actual domain names.
# These are used as the default values for -PrimaryDomain and -AliasDomain.
# You can also override them at runtime with those parameters.
#
$domainOne = "domain1.com"   # <-- CHANGE THIS: primary email domain
$domainTwo = "domain2.com"   # <-- CHANGE THIS: alias email domain
#
# ==============================================================================

# Validate domains have been configured
if ($domainOne -eq "domain1.com" -or $domainTwo -eq "domain2.com") {
    Write-Error "Domains have not been configured. Open the script and set `$domainOne and `$domainTwo at lines 158/159 before running."
    exit 1
}

# Apply domain defaults if not overridden on the command line
if (-not $PSBoundParameters.ContainsKey('PrimaryDomain')) { $PrimaryDomain = $domainOne }
if (-not $PSBoundParameters.ContainsKey('AliasDomain'))   { $AliasDomain   = $domainTwo }


$ErrorActionPreference = 'Stop'

# Convert relative path to absolute path
$script:LogFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)

#region Helper Functions

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Console output with color
    switch ($Level) {
        'Error'   { Write-Error $Message -ErrorAction Continue }
        'Warning' { Write-Warning $Message }
        'Success' { Write-Host $logEntry -ForegroundColor Green }
        default   { Write-Verbose $logEntry }
    }
    
    # Always write to log file using .NET (immune to WhatIf)
    if ($script:LogFilePath) {
        try {
            [System.IO.File]::AppendAllText($script:LogFilePath, "$logEntry`r`n")
        }
        catch {
            Write-Warning "Failed to write to log file '$($script:LogFilePath)': $($_.Exception.Message)"
        }
    }
}

function Expand-EmailPattern {
    <#
    .SYNOPSIS
        Expands email pattern with user name tokens.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Pattern,
        
        [Parameter(Mandatory)]
        [string]$FirstName,
        
        [Parameter(Mandatory)]
        [string]$LastName,
        
        [Parameter(Mandatory)]
        [string]$Domain
    )
    
    # Sanitize names
    $firstNameClean = ($FirstName -replace '[^a-zA-Z0-9]', '').Trim()
    $lastNameClean = ($LastName -replace '[^a-zA-Z0-9]', '').Trim()
    
    if ([string]::IsNullOrWhiteSpace($firstNameClean) -or [string]::IsNullOrWhiteSpace($lastNameClean)) {
        return $null
    }
    
    $firstInitial = $firstNameClean.Substring(0, 1)
    $lastInitial = $lastNameClean.Substring(0, 1)
    
    # Expand pattern tokens
    $expanded = $Pattern -replace '\{FirstName\}', $firstNameClean `
                         -replace '\{LastName\}', $lastNameClean `
                         -replace '\{FirstInitial\}', $firstInitial `
                         -replace '\{LastInitial\}', $lastInitial
    
    return "$expanded@$Domain".ToLower()
}

function Get-SafeEmailAlias {
    <#
    .SYNOPSIS
        Generates email alias with conflict detection.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PreferredPattern,
        
        [Parameter(Mandatory)]
        [string]$ConflictPattern,
        
        [Parameter(Mandatory)]
        [string]$FirstName,
        
        [Parameter(Mandatory)]
        [string]$LastName,
        
        [Parameter(Mandatory)]
        [string]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$UsedAliases,
        
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )
    
    # Try preferred pattern first
    $preferredAlias = Expand-EmailPattern -Pattern $PreferredPattern -FirstName $FirstName -LastName $LastName -Domain $Domain
    
    if (-not $preferredAlias) {
        Write-Log "Could not generate alias for $UserPrincipalName using pattern '$PreferredPattern'" -Level Warning
        return $null
    }
    
    if (-not $UsedAliases.ContainsKey($preferredAlias)) {
        $UsedAliases[$preferredAlias] = $UserPrincipalName
        return $preferredAlias
    }
    
    # Conflict detected - use conflict pattern
    $conflictAlias = Expand-EmailPattern -Pattern $ConflictPattern -FirstName $FirstName -LastName $LastName -Domain $Domain
    
    if (-not $conflictAlias) {
        Write-Log "Could not generate conflict resolution alias for $UserPrincipalName" -Level Warning
        return $null
    }
    
    # Check if conflict resolution is also taken
    if ($UsedAliases.ContainsKey($conflictAlias)) {
        Write-Log "Conflict resolution failed: $conflictAlias already used by $($UsedAliases[$conflictAlias])" -Level Warning
        return $null
    }
    
    $UsedAliases[$conflictAlias] = $UserPrincipalName
    Write-Log "Conflict on $preferredAlias (used by $($UsedAliases[$preferredAlias])). Using $conflictAlias instead." -Level Warning
    return $conflictAlias
}

#endregion

#region Main Script

try {
    # Initialize log file FIRST using .NET (immune to WhatIf)
    try {
        # Ensure directory exists
        $logDir = Split-Path -Path $script:LogFilePath -Parent
        if ($logDir -and -not [System.IO.Directory]::Exists($logDir)) {
            [System.IO.Directory]::CreateDirectory($logDir) | Out-Null
        }
        
        # Create log file using .NET
        [System.IO.File]::WriteAllText($script:LogFilePath, "")
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Log file created: $script:LogFilePath" -ForegroundColor Cyan
        Write-Host "File exists: $([System.IO.File]::Exists($script:LogFilePath))" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Could not create log file at $script:LogFilePath - logging to console only. Error: $($_.Exception.Message)"
        $script:LogFilePath = $null
    }
    
    Write-Log "========================================" -Level Info
    Write-Log "Email Alias Standardization Script Started" -Level Info
    if ($WhatIfPreference) {
        Write-Log "RUNNING IN WHATIF MODE - No changes will be applied" -Level Info
    }
    Write-Log "========================================" -Level Info
    Write-Log "Configuration:" -Level Info
    Write-Log "  Primary Domain: $PrimaryDomain" -Level Info
    Write-Log "  Alias Domain: $AliasDomain" -Level Info
    Write-Log "  Primary Pattern: $PrimaryPattern" -Level Info
    Write-Log "  Alias Patterns: $($AliasPatterns -join ', ')" -Level Info
    Write-Log "  Conflict Pattern: $ConflictPattern" -Level Info
    if ($PreserveDomains.Count -gt 0) {
        Write-Log "  Preserve Domains: $($PreserveDomains -join ', ')" -Level Info
    }
    Write-Log "========================================" -Level Info
    
    # Check for Exchange Online connection
    Write-Log "Checking Exchange Online connection..." -Level Info
    
    try {
        $null = Get-EXOMailbox -ResultSize 1 -ErrorAction Stop
        Write-Log "Exchange Online connection verified." -Level Success
    }
    catch {
        Write-Log "Not connected to Exchange Online. Attempting to connect..." -Level Warning
        
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            throw "ExchangeOnlineManagement module not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        }
        
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Connected to Exchange Online successfully." -Level Success
    }
    
    # Retrieve all user mailboxes
    Write-Log "Retrieving all user mailboxes..." -Level Info
    $mailboxes = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties DisplayName, EmailAddresses, PrimarySmtpAddress
    
    if (-not $mailboxes) {
        Write-Log "No mailboxes found. Exiting." -Level Warning
        return
    }
    
    Write-Log "Retrieved $($mailboxes.Count) mailboxes. Fetching user details..." -Level Info
    
    # Build user data collection with name information
    $userDataCollection = @()
    $batchSize = 100
    $currentBatch = 0
    
    for ($i = 0; $i -lt $mailboxes.Count; $i += $batchSize) {
        $currentBatch++
        $batch = $mailboxes[$i..[Math]::Min($i + $batchSize - 1, $mailboxes.Count - 1)]
        
        Write-Log "Processing batch $currentBatch of $([Math]::Ceiling($mailboxes.Count / $batchSize))..." -Level Info
        
        foreach ($mailbox in $batch) {
            try {
                # Get user object for FirstName/LastName (not available on EXOMailbox)
                $user = Get-User -Identity $mailbox.UserPrincipalName -ErrorAction Stop
                
                $userDataCollection += [PSCustomObject]@{
                    UserPrincipalName  = $mailbox.UserPrincipalName
                    DisplayName        = $mailbox.DisplayName
                    FirstName          = $user.FirstName
                    LastName           = $user.LastName
                    EmailAddresses     = $mailbox.EmailAddresses
                    PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                }
            }
            catch {
                Write-Log "Failed to retrieve user details for $($mailbox.UserPrincipalName): $($_.Exception.Message)" -Level Warning
            }
        }
    }
    
    Write-Log "Successfully retrieved details for $($userDataCollection.Count) users." -Level Info
    
    # Track used aliases globally to detect conflicts per domain
    $usedAliasesByDomain = @{
        $PrimaryDomain = @{}
        $AliasDomain   = @{}
    }
    
    $successCount = 0
    $errorCount = 0
    $skippedCount = 0
    
    foreach ($userData in $userDataCollection) {
        try {
            Write-Log "----------------------------------------" -Level Info
            Write-Log "Processing: $($userData.DisplayName) ($($userData.UserPrincipalName))" -Level Info
            
            $firstName = $userData.FirstName
            $lastName = $userData.LastName
            
            # Validate name data
            if ([string]::IsNullOrWhiteSpace($firstName) -or [string]::IsNullOrWhiteSpace($lastName)) {
                Write-Log "Skipping $($userData.UserPrincipalName) - missing first or last name (First: '$firstName', Last: '$lastName')." -Level Warning
                $skippedCount++
                continue
            }
            
            # Sanitize for email
            $firstNameClean = ($firstName -replace '[^a-zA-Z0-9]', '').Trim()
            $lastNameClean = ($lastName -replace '[^a-zA-Z0-9]', '').Trim()
            
            if ([string]::IsNullOrWhiteSpace($firstNameClean) -or [string]::IsNullOrWhiteSpace($lastNameClean)) {
                Write-Log "Skipping $($userData.UserPrincipalName) - names contain only special characters." -Level Warning
                $skippedCount++
                continue
            }
            
            # Generate primary email address
            $newPrimary = Expand-EmailPattern -Pattern $PrimaryPattern -FirstName $firstName -LastName $lastName -Domain $PrimaryDomain
            
            if (-not $newPrimary) {
                Write-Log "Skipping $($userData.UserPrincipalName) - could not generate primary email." -Level Warning
                $skippedCount++
                continue
            }
            
            Write-Log "  Current Primary: $($userData.PrimarySmtpAddress)" -Level Info
            Write-Log "  New Primary: $newPrimary" -Level Info
            
            # Collect all required email addresses
            $requiredAddresses = @()
            
            # Add primary
            $requiredAddresses += [PSCustomObject]@{ 
                Address   = $newPrimary
                IsPrimary = $true
            }
            
            # Generate aliases for both domains
            foreach ($domain in @($PrimaryDomain, $AliasDomain)) {
                if (-not $usedAliasesByDomain.ContainsKey($domain)) {
                    $usedAliasesByDomain[$domain] = @{}
                }
                
                foreach ($aliasPattern in $AliasPatterns) {
                    $alias = Get-SafeEmailAlias -PreferredPattern $aliasPattern `
                                                -ConflictPattern $ConflictPattern `
                                                -FirstName $firstName `
                                                -LastName $lastName `
                                                -Domain $domain `
                                                -UsedAliases $usedAliasesByDomain[$domain] `
                                                -UserPrincipalName $userData.UserPrincipalName
                    
                    if ($alias -and $alias -ne $newPrimary) {
                        $requiredAddresses += [PSCustomObject]@{ 
                            Address   = $alias
                            IsPrimary = $false
                        }
                    }
                }
            }
            
            # Build new email addresses list
            $existingAddresses = $userData.EmailAddresses | Where-Object { $_ -match '^smtp:' }
            
            # Determine which domains to preserve
            $managedDomains = @($PrimaryDomain, $AliasDomain) | ForEach-Object { $_.ToLower() }
            
            # Start with preserved addresses from non-managed domains
            $newEmailAddresses = @()
            $preservedCount = 0
            foreach ($addr in $existingAddresses) {
                $cleanAddr = ($addr -replace '^SMTP:', '' -replace '^smtp:', '').ToLower()
                $addrDomain = ($cleanAddr -split '@')[1]
                
                # Preserve if:
                # 1. Not a managed domain, OR
                # 2. Explicitly in PreserveDomains list
                $shouldPreserve = ($addrDomain -notin $managedDomains) -or ($addrDomain -in ($PreserveDomains | ForEach-Object { $_.ToLower() }))
                
                if ($shouldPreserve) {
                    $newEmailAddresses += "smtp:$cleanAddr"
                    $preservedCount++
                }
            }
            
            if ($preservedCount -gt 0) {
                Write-Log "  Preserved $preservedCount existing alias(es)" -Level Info
            }
            
            # Add new primary (SMTP uppercase = primary)
            $newEmailAddresses += "SMTP:$newPrimary"
            
            # Add required aliases (smtp lowercase = alias)
            $addedAliasCount = 0
            foreach ($reqAddr in $requiredAddresses) {
                if (-not $reqAddr.IsPrimary) {
                    $newEmailAddresses += "smtp:$($reqAddr.Address)"
                    $addedAliasCount++
                }
            }
            
            Write-Log "  Adding $addedAliasCount new alias(es)" -Level Info
            
            # Remove duplicates (case-insensitive comparison, preserve SMTP vs smtp)
            $uniqueAddresses = @{}
            $finalEmailAddresses = @()
            
            foreach ($addr in $newEmailAddresses) {
                $key = $addr.ToLower()
                if (-not $uniqueAddresses.ContainsKey($key)) {
                    $uniqueAddresses[$key] = $true
                    $finalEmailAddresses += $addr
                }
            }
            
            Write-Log "  Total addresses: $($finalEmailAddresses.Count)" -Level Info
            Write-Log "  Full list: $($finalEmailAddresses -join ', ')" -Level Info
            
            # Apply changes
            if ($PSCmdlet.ShouldProcess($userData.UserPrincipalName, "Set primary to $newPrimary and update aliases")) {
                Set-Mailbox -Identity $userData.UserPrincipalName -EmailAddresses $finalEmailAddresses -ErrorAction Stop
                Write-Log "Successfully updated $($userData.UserPrincipalName)" -Level Success
                $successCount++
            }
            else {
                Write-Log "WhatIf: Would update $($userData.UserPrincipalName) with primary $newPrimary" -Level Info
            }
            
        }
        catch {
            Write-Log "Error processing $($userData.UserPrincipalName): $($_.Exception.Message)" -Level Error
            Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
            $errorCount++
        }
    }
    
    # Summary
    Write-Log "========================================" -Level Info
    Write-Log "Script Completed" -Level Info
    Write-Log "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info
    Write-Log "Total Users: $($userDataCollection.Count)" -Level Info
    
    if ($successCount -gt 0) {
        Write-Log "Successful: $successCount" -Level Success
    } else {
        Write-Log "Successful: $successCount" -Level Info
    }
    
    if ($errorCount -gt 0) {
        Write-Log "Errors: $errorCount" -Level Error
    } else {
        Write-Log "Errors: $errorCount" -Level Info
    }
    
    if ($skippedCount -gt 0) {
        Write-Log "Skipped: $skippedCount" -Level Warning
    } else {
        Write-Log "Skipped: $skippedCount" -Level Info
    }
    
    Write-Log "========================================" -Level Info
    
}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}
finally {
    if ($script:LogFilePath -and [System.IO.File]::Exists($script:LogFilePath)) {
        $fileInfo = New-Object System.IO.FileInfo($script:LogFilePath)
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Log file saved: $script:LogFilePath" -ForegroundColor Green
        Write-Host "File size: $($fileInfo.Length) bytes" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        if ($WhatIfPreference) {
            Write-Host "[WhatIf Mode] No changes were made. Run without -WhatIf to apply changes." -ForegroundColor Yellow
        }
    }
    else {
        Write-Warning "Log file was not created successfully."
    }
}

#endregion