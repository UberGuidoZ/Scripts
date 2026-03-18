###################################################################################
#
# Get-MappedDrives.ps1 - Retrieves mapped network drives for users on this machine.
# Scans registry hives (HKEY_USERS\<SID>\Network) to find persistent drive mappings.
# Works with Local, Domain, and Entra (Azure AD) accounts.
#
# Use -All to scan every loaded user hive - catches users even if session
# detection via 'query user' fails. Resolves usernames via Volatile Environment
# and ProfileList. Best for thorough auditing.
#
# Use -Current to scan only actively logged-in sessions from 'query user'.
# Faster and lower noise, but limited to currently active sessions only.
#
# If just run, it will display on screen. You can also output to CSV if specified.
# --> Must be run as NT AUTHORITY\SYSTEM (e.g. via PsExec or Task Scheduler). <--
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts  |  v2.0
#
# RUN FOR USAGE: .\Get-MappedDrives.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory=$false, ParameterSetName='All')]
    [switch]$All,

    [Parameter(Mandatory=$false, ParameterSetName='Current')]
    [switch]$Current,

    [Parameter(Mandatory=$false)]
    [string]$OutputCsv,

    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

=================== GET MAPPED DRIVES (UberGuidoZ) =================

DESCRIPTION:
    Retrieves mapped network drives for users on this machine.
    --> Must be run as NT AUTHORITY\SYSTEM. <--
    Works with Local, Domain, and Entra (Azure AD) users.
    Updates posted to https://github.com/UberGuidoZ/Scripts repo.

    Use -All to scan every loaded registry hive (catches all users,
    including those whose sessions may not appear in 'query user').

    Use -Current to scan only actively logged-in sessions reported
    by 'query user' (faster, lower noise, session ID always accurate).

SYNTAX:
    .\Get-MappedDrives.ps1 -All     [[-OutputCsv] <String>] [-h]
    .\Get-MappedDrives.ps1 -Current [[-OutputCsv] <String>] [-h]

PARAMETERS:
    -All
        Scans all loaded user registry hives (HKEY_USERS\S-1-5-21-*).
        Resolves usernames via Volatile Environment and ProfileList.
        Requires NT AUTHORITY\SYSTEM.

    -Current
        Scans only users currently listed in 'query user'.
        Translates each username to a SID to locate their hive.
        Requires NT AUTHORITY\SYSTEM.

    -OutputCsv <String>
        Optional. Path where CSV file will be saved.
        If omitted, results are only displayed in the console.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: All-user scan, console output only
    .\Get-MappedDrives.ps1 -All

    Example 2: Current-user scan, console output only
    .\Get-MappedDrives.ps1 -Current

    Example 3: All-user scan with CSV export
    .\Get-MappedDrives.ps1 -All -OutputCsv "C:\Temp\MappedDrives.csv"

    Example 4: Current-user scan with CSV export
    .\Get-MappedDrives.ps1 -Current -OutputCsv "C:\Temp\MappedDrives.csv"

    Example 5: Export with timestamp in filename
    .\Get-MappedDrives.ps1 -All -OutputCsv "C:\Reports\Drives_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Example 6: Run as SYSTEM via PsExec (all-user scan)
    psexec.exe -s -i powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-MappedDrives.ps1" -All

    Example 7: Run as SYSTEM via PsExec (current-user scan) with CSV
    psexec.exe -s -i powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Get-MappedDrives.ps1" -Current -OutputCsv "C:\Temp\Output.csv"

    Example 8: Show this help
    .\Get-MappedDrives.ps1 -h

OUTPUT:
    -All mode columns:
    - Username  : Resolved account name (or "SID: <sid>" if unresolvable)
    - Session   : Session ID matched from 'query user' (or "Unknown")
    - Drive     : Mapped drive letter (e.g., Z:)
    - Path      : UNC path (e.g., \\server\share)

    -Current mode columns:
    - Username    : Logged-in user account name
    - SessionID   : Session ID from 'query user'
    - DriveLetter : Mapped drive letter (e.g., Z:)
    - RemotePath  : UNC path (e.g., \\server\share)

NOTES:
    - Requires NT AUTHORITY\SYSTEM privileges
    - Use PsExec or Task Scheduler to run as SYSTEM
    - Only persistent mapped drives appear (non-persistent drives
      are not stored in the registry)
    - CSV file is only created if -OutputCsv is specified
    - Supports Entra (Azure AD), Domain, and Local user accounts

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# Require at least one mode flag
if (-not $All -and -not $Current) {
    Write-Host ""
    Write-Host "ERROR: Please specify -All or -Current." -ForegroundColor Red
    Write-Host "       Run with -h for full usage information." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

$results = @()

# =====================================================================
# -All mode: enumerate every loaded user hive in HKEY_USERS
# =====================================================================
if ($All) {

    # Get all logged-in user sessions (used for session ID matching)
    $loggedInUsers = query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
        $fields = $_ -split '\s{2,}'
        [PSCustomObject]@{
            Username    = ($fields[0] -replace '^>','').Trim()
            SessionName = $fields[1]
            ID          = $fields[2]
            State       = if ($fields.Count -eq 5) { $fields[3] } else { $fields[2] }
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
        $sid       = $hive.PSChildName
        $username  = $null
        $sessionID = "Unknown"

        Write-Host "Processing SID: $sid" -ForegroundColor Cyan

        # Method 1: Volatile Environment USERNAME
        try {
            $username = (Get-ItemProperty -Path "Registry::HKEY_USERS\$sid\Volatile Environment" -Name USERNAME -ErrorAction SilentlyContinue).USERNAME
            if ($username) {
                Write-Host "  Username from Volatile Environment: $username" -ForegroundColor Gray
            }
        } catch { }

        # Method 2: Volatile Environment USERDOMAIN + USERNAME combined
        if (-not $username) {
            try {
                $name = (Get-ItemProperty -Path "Registry::HKEY_USERS\$sid\Volatile Environment" -Name USERNAME -ErrorAction SilentlyContinue).USERNAME
                if ($name) {
                    $username = $name
                    Write-Host "  Username from Volatile Environment (domain+name): $username" -ForegroundColor Gray
                }
            } catch { }
        }

        # Method 3: Profile path from HKLM ProfileList
        if (-not $username) {
            try {
                $profileList = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue
                if ($profileList.ProfileImagePath) {
                    $username = Split-Path $profileList.ProfileImagePath -Leaf
                    Write-Host "  Username from Profile Path: $username" -ForegroundColor Gray
                }
            } catch { }
        }

        # Method 4: Match resolved username to a logged-in session
        if ($username) {
            $matchedUser = $loggedInUsers | Where-Object { $_.Username -eq $username }
            if ($matchedUser) {
                $sessionID = $matchedUser.ID
                Write-Host "  Matched to session ID: $sessionID" -ForegroundColor Green
            }
        }

        # Fallback: use raw SID as identifier
        if (-not $username) {
            $username = "SID: $sid"
            Write-Host "  Could not resolve username, using SID" -ForegroundColor Yellow
        }

        # Check for mapped drives under HKEY_USERS\<SID>\Network
        $regPath = "Registry::HKEY_USERS\$sid\Network"

        if (Test-Path $regPath) {
            Write-Host "  Checking for mapped drives..." -ForegroundColor Gray

            $drivesFound = 0
            Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                $driveLetter = $_.PSChildName + ":"
                $remotePath  = (Get-ItemProperty -Path $_.PSPath -Name RemotePath -ErrorAction SilentlyContinue).RemotePath

                if ($remotePath) {
                    $drivesFound++
                    $results += [PSCustomObject]@{
                        Username = $username
                        Session  = $sessionID
                        Drive    = $driveLetter
                        Path     = $remotePath
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
}

# =====================================================================
# -Current mode: enumerate only actively logged-in sessions
# =====================================================================
if ($Current) {

    $loggedInUsers = query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
        $fields = $_ -split '\s{2,}'
        [PSCustomObject]@{
            Username    = ($fields[0] -replace '^>','').Trim()
            SessionName = $fields[1]
            ID          = $fields[2]
            State       = if ($fields.Count -eq 5) { $fields[3] } else { $fields[2] }
        }
    }

    Write-Host "Found $($loggedInUsers.Count) logged-in user(s)" -ForegroundColor Cyan
    Write-Host ""

    foreach ($user in $loggedInUsers) {
        $username  = $user.Username
        $sessionID = $user.ID

        Write-Host "Processing user: $username (Session ID: $sessionID)" -ForegroundColor Cyan

        try {
            # Translate username to SID
            $userObj = New-Object System.Security.Principal.NTAccount($username)
            $sid     = $userObj.Translate([System.Security.Principal.SecurityIdentifier]).Value

            $regPath = "Registry::HKEY_USERS\$sid\Network"

            if (Test-Path $regPath) {
                Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $driveLetter = $_.PSChildName + ":"
                    $remotePath  = (Get-ItemProperty -Path $_.PSPath -Name RemotePath -ErrorAction SilentlyContinue).RemotePath

                    if ($remotePath) {
                        $results += [PSCustomObject]@{
                            Username    = $username
                            SessionID   = $sessionID
                            DriveLetter = $driveLetter
                            RemotePath  = $remotePath
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to process user $username : $_"
        }
    }
}

# =====================================================================
# Output
# =====================================================================
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