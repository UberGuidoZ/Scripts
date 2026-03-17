# Script: Get-MappedDrives_CU.ps1
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
# Must be run as NT AUTHORITY\SYSTEM
# Usage: .\Get-MappedDrives_CU.ps1 [-OutputCsv "C:\Path\To\Output.csv"] [-h]

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputCsv,

    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

============= GET CURRENT USER MAPPED DRIVES (UberGuidoZ) ==========

DESCRIPTION:
    Retrieves all mapped network drives for currently logged-in users
    by reading each user's registry hive (HKEY_USERS\<SID>\Network).
    --> Must be run as NT AUTHORITY\SYSTEM. <--
    Works with Local, Domain, and Entra (Azure AD) users.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Get-MappedDrives_CU.ps1 [[-OutputCsv] <String>] [-h]

PARAMETERS:
    -OutputCsv <String>
        Optional. Path where CSV file will be saved.
        If omitted, results are only displayed in console.
    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:
    Example 1: Display results in console only
    .\Get-MappedDrives_CU.ps1
    Example 2: Display results and export to CSV
    .\Get-MappedDrives_CU.ps1 -OutputCsv "C:\Temp\MappedDrives.csv"
    Example 3: Export with timestamp in filename
    .\Get-MappedDrives_CU.ps1 -OutputCsv "C:\Reports\Drives_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    Example 4: Run as SYSTEM using PsExec (display only)
    psexec.exe -s -i powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-MappedDrives_CU.ps1"
    Example 5: Run as SYSTEM with CSV export
    psexec.exe -s -i powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-MappedDrives_CU.ps1" -OutputCsv "C:\Temp\Output.csv"
    Example 6: Show this help
    .\Get-MappedDrives_CU.ps1 -h

OUTPUT:
    The script outputs a table with the following columns:
    - Username    : Logged-in user account name
    - SessionID   : User session ID from 'query user'
    - DriveLetter : Mapped drive letter (e.g., Z:)
    - RemotePath  : UNC path (e.g., \\server\share)

NOTES:
    - Requires NT AUTHORITY\SYSTEM privileges
    - Use PsExec or Task Scheduler to run as SYSTEM
    - Only persistent mapped drives appear (non-persistent drives are not stored in registry)
    - CSV file is only created if -OutputCsv parameter is specified
    - Supports Entra (Azure AD), Domain, and Local user accounts

====================================================================
"@ -ForegroundColor Cyan
    exit 0
}

$results = @()

# Get all logged-in user sessions
$loggedInUsers = query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
    $fields = $_ -split '\s{2,}'
    [PSCustomObject]@{
        Username = ($fields[0] -replace '^>','').Trim()
        SessionName = $fields[1]
        ID = $fields[2]
        State = if ($fields.Count -eq 5) { $fields[3] } else { $fields[2] }
    }
}

foreach ($user in $loggedInUsers) {
    $username = $user.Username
    $sessionID = $user.ID
    
    Write-Host "Processing user: $username (Session ID: $sessionID)" -ForegroundColor Cyan
    
    try {
        # Get user's SID
        $userObj = New-Object System.Security.Principal.NTAccount($username)
        $sid = $userObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        
        # Load user's registry hive if needed
        $regPath = "Registry::HKEY_USERS\$sid\Network"
        
        if (Test-Path $regPath) {
            # Enumerate mapped drives from registry
            Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                $driveLetter = $_.PSChildName + ":"
                $remotePath = (Get-ItemProperty -Path $_.PSPath -Name RemotePath -ErrorAction SilentlyContinue).RemotePath
                
                if ($remotePath) {
                    $results += [PSCustomObject]@{
                        Username = $username
                        SessionID = $sessionID
                        DriveLetter = $driveLetter
                        RemotePath = $remotePath
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to process user $username : $_"
    }
}

# Display results in console table
Write-Host "`n==================== MAPPED DRIVES SUMMARY ====================" -ForegroundColor Green
if ($results.Count -gt 0) {
    $results | Format-Table -AutoSize
    Write-Host "Total mapped drives found: $($results.Count)" -ForegroundColor Green
} else {
    Write-Host "No mapped drives found for logged-in users." -ForegroundColor Yellow
}
Write-Host "===============================================================`n" -ForegroundColor Green

# Export to CSV if path specified
if ($OutputCsv) {
    try {
        $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
        Write-Host "Results exported to: $OutputCsv" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}