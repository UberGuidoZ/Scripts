# Script: Get-MappedDrives.ps1
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
# Must be run as NT AUTHORITY\SYSTEM
# Usage: .\Get-MappedDrives.ps1 [-OutputCsv "C:\Path\To\Output.csv"] [-h]

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

============= GET ALL USER MAPPED DRIVES (UberGuidoZ) ==============

DESCRIPTION:
    Retrieves all mapped network drives for currently logged-in users.
    --> Must be run as NT AUTHORITY\SYSTEM. <--
    Works with Local, Domain, and Entra (Azure AD) users.
	Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Get-MappedDrives.ps1 [[-OutputCsv] <String>] [-h]

PARAMETERS:
    -OutputCsv <String>
        Optional. Path where CSV file will be saved.
        If omitted, results are only displayed in console.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Display results in console only
    .\Get-MappedDrives.ps1

    Example 2: Display results and export to CSV
    .\Get-MappedDrives.ps1 -OutputCsv "C:\Temp\MappedDrives.csv"

    Example 3: Export with timestamp in filename
    .\Get-MappedDrives.ps1 -OutputCsv "C:\Reports\Drives_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Example 4: Run as SYSTEM using PsExec (display only)
    psexec.exe -s -i powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-MappedDrives.ps1"

    Example 5: Run as SYSTEM with CSV export
    psexec.exe -s -i powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-MappedDrives.ps1" -OutputCsv "C:\Temp\Output.csv"

    Example 6: Show this help
    .\Get-MappedDrives.ps1 -h

OUTPUT:
    The script outputs a table with the following columns:
    - Username      : Logged-in user account name
    - Session     : User session ID (or "Unknown" if not matched)
    - Drive   : Mapped drive letter (e.g., Z:)
    - Path    : UNC path (e.g., \\server\share)

NOTES:
    - Requires NT AUTHORITY\SYSTEM privileges
    - Use PsExec or Task Scheduler to run as SYSTEM
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

Write-Host "Found $($loggedInUsers.Count) logged-in user(s)" -ForegroundColor Cyan
Write-Host ""

# Get all loaded user registry hives (exclude system SIDs)
$loadedHives = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { 
    $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$'
}

Write-Host "Found $($loadedHives.Count) user registry hive(s) loaded" -ForegroundColor Cyan
Write-Host ""

foreach ($hive in $loadedHives) {
    $sid = $hive.PSChildName
    $username = $null
    $sessionID = "Unknown"
    
    Write-Host "Processing SID: $sid" -ForegroundColor Cyan
    
    # Try multiple methods to get the username
    
    # Method 1: Volatile Environment USERNAME
    try {
        $username = (Get-ItemProperty -Path "Registry::HKEY_USERS\$sid\Volatile Environment" -Name USERNAME -ErrorAction SilentlyContinue).USERNAME
        if ($username) {
            Write-Host "  Username from Volatile Environment: $username" -ForegroundColor Gray
        }
    } catch { }
    
    # Method 2: Volatile Environment USERDOMAIN and USERNAME combined
    if (-not $username) {
        try {
            $user = (Get-ItemProperty -Path "Registry::HKEY_USERS\$sid\Volatile Environment" -Name USERDOMAIN -ErrorAction SilentlyContinue).USERDOMAIN
            $name = (Get-ItemProperty -Path "Registry::HKEY_USERS\$sid\Volatile Environment" -Name USERNAME -ErrorAction SilentlyContinue).USERNAME
            if ($name) {
                $username = $name
                Write-Host "  Username from Volatile Environment: $username" -ForegroundColor Gray
            }
        } catch { }
    }
    
    # Method 3: Check profile path from HKLM
    if (-not $username) {
        try {
            $profileList = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue
            if ($profileList.ProfileImagePath) {
                $username = Split-Path $profileList.ProfileImagePath -Leaf
                Write-Host "  Username from Profile Path: $username" -ForegroundColor Gray
            }
        } catch { }
    }
    
    # Method 4: Try to match with logged-in users
    if ($username) {
        $matchedUser = $loggedInUsers | Where-Object { $_.Username -eq $username }
        if ($matchedUser) {
            $sessionID = $matchedUser.ID
            Write-Host "  Matched to session ID: $sessionID" -ForegroundColor Green
        }
    }
    
    # If still no username, use SID
    if (-not $username) {
        $username = "SID: $sid"
        Write-Host "  Could not resolve username, using SID" -ForegroundColor Yellow
    }
    
    # Check for mapped drives
    $regPath = "Registry::HKEY_USERS\$sid\Network"
    
    if (Test-Path $regPath) {
        Write-Host "  Checking for mapped drives..." -ForegroundColor Gray
        
        $drivesFound = 0
        Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            $driveLetter = $_.PSChildName + ":"
            $remotePath = (Get-ItemProperty -Path $_.PSPath -Name RemotePath -ErrorAction SilentlyContinue).RemotePath
            
            if ($remotePath) {
                $drivesFound++
                $results += [PSCustomObject]@{
                    Username = $username
                    Session = $sessionID
                    Drive = $driveLetter
                    Path = $remotePath
                }
            }
        }
        
        if ($drivesFound -eq 0) {
            Write-Host "  No mapped drives found" -ForegroundColor Gray
        } else {
            Write-Host "  Found $drivesFound mapped drive(s)" -ForegroundColor Green
        }
    } else {
        Write-Host "  No Network registry key (no mapped drives)" -ForegroundColor Gray
    }
    
    Write-Host ""
}

# Display results in console table
Write-Host "==================== MAPPED DRIVES SUMMARY ====================" -ForegroundColor Green
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