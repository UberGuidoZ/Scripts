###################################################################################
#
# Set-FolderPermissions.ps1 - Grants permissions on folders where the folder
# name matches a domain or local username. Grants Modify to the matching user
# and Full Control to Domain Admins, Local Admins, and SYSTEM.
#
# Version: 1.5 | Date: 4/28/25
#
# Must be run as Administrator or it will fail.
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
#
# RUN FOR USAGE: .\Set-FolderPermissions.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$RootPath,
    [switch]$VerifyCheck,
    [string]$CsvPath,
    [switch]$NoTable,
    [string]$Domain,
    [int]$Threads = 1,

    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Automatically show help if asked or no parameters are passed
if ($PSBoundParameters.Count -eq 0 -or $ShowHelp) {
    Write-Host @"

============= SET FOLDER PERMISSIONS (UberGuidoZ) ==================

DESCRIPTION:
    Grants permissions on folders where the folder name matches a
    domain or local username. Grants Modify to the matching user and
    Full Control to Domain Admins, Local Admins, and NT AUTHORITY\SYSTEM.
    Supports parallel processing, verification/dry-run mode, and CSV export.
    --> Must be run as Administrator or it will fail. <--
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Set-FolderPermissions.ps1 -RootPath <String> [options]

PARAMETERS:
    -RootPath <String>
        Required. The root folder containing user-named subfolders.

    -VerifyCheck
        Optional. Preview permission changes without applying them.
        Generates a summary table and CSV without modifying any ACLs.

    -CsvPath <String>
        Optional. Path to export the VerifyCheck summary CSV.
        Default: <RootPath>\VerifyCheck_Summary.csv

    -NoTable
        Optional. Suppress the on-screen summary table.
        Implies -VerifyCheck; CSV is still exported.

    -Domain <String>
        Optional. Specify domain name manually.
        Use '.' or 'localhost' for local accounts.
        Default: auto-detected from system.

    -Threads <Int>
        Optional. Number of parallel threads (default: 1).
        Set to 1 to disable parallel processing (PS 5.1 compatible).
        Values greater than 1 require PowerShell 7+.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Apply permissions to all user folders
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders'

    Example 2: Dry run to preview changes
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders' -VerifyCheck

    Example 3: Dry run suppressing the on-screen table
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders' -NoTable

    Example 4: Dry run and export summary to a specific CSV
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders' -VerifyCheck -CsvPath 'C:\Temp\Summary.csv'

    Example 5: Specify domain manually
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders' -Domain 'mydomain.local'

    Example 6: Use local accounts instead of domain
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders' -Domain '.'

    Example 7: Run with parallel processing (PowerShell 7+ only)
    .\Set-FolderPermissions.ps1 -RootPath 'D:\UserFolders' -Threads 5

    Example 8: Show this help
    .\Set-FolderPermissions.ps1 -h

OUTPUT:
    - Log file : SetFolderPermissions_<timestamp>.log in RootPath
    - CSV file : VerifyCheck_Summary.csv in RootPath (if -VerifyCheck or -NoTable)
    - Console  : Per-folder status lines and a final summary

NOTES:
    - Requires Administrator privileges
    - Does not require NT AUTHORITY\SYSTEM; local admin is sufficient
    - Parallel processing (-Threads > 1) requires PowerShell 7+
    - Use -VerifyCheck first to confirm expected changes before applying

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# Define suppression of table
if ($NoTable) {
    $VerifyCheck = $true
}
# RootPath is required
if (-not $RootPath -or !(Test-Path $RootPath)) {
    Write-Error "Root path is missing or does not exist."
    exit 1
}

# Set domain detection and logic
if (-not $Domain) {
    $Domain = (Get-CimInstance Win32_ComputerSystem).Domain
}

if ($Domain -eq "." -or $Domain -eq "localhost") {
    $Domain = "$env:COMPUTERNAME"
}

# Option to disable parallel processing for compatibility
$DisableParallel = $false
if ($Threads -eq 1) {
    $DisableParallel = $true
    Write-Host "Running single-threaded (parallel processing disabled)." -ForegroundColor Yellow
}

# Define admin groups
$adminGroups = @(
    "$Domain\Domain Admins",
    "BUILTIN\Administrators",
    "NT AUTHORITY\SYSTEM"
)

# Setup logging
$summary = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path -Path $RootPath -ChildPath "SetFolderPermissions_$timestamp.log"

# Log the domain being used
Write-Host "Domain being used: $Domain" -ForegroundColor Cyan
Add-Content -Path $logPath -Value "Domain being used: $Domain"

# Time for the magic to happen
$folders = Get-ChildItem -Path $RootPath -Directory
$foldersProcessed = 0

if ($DisableParallel) {
    foreach ($folder in $folders) {
        $foldersProcessed++
        $userName = $folder.Name
        $userIdentity = "$Domain\$userName"
        $acl = Get-Acl $folder.FullName

        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $userIdentity, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($userRule)

        foreach ($admin in $adminGroups) {
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $admin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($adminRule)
        }

        if ($VerifyCheck) {
            $logEntry = "[Verify-Check] Would set permissions on: $($folder.FullName)"
            Write-Host $logEntry -ForegroundColor Yellow
            Add-Content -Path $logPath -Value $logEntry
            $summary.Add([PSCustomObject]@{
                Folder = $folder.FullName
                UserGrantedModify = $userIdentity
                AdminsGrantedFullControl = ($adminGroups -join ", ")
            })
        } else {
            try {
                Set-Acl -Path $folder.FullName -AclObject $acl
                $success = "Successfully set permissions on: $($folder.FullName)"
                Write-Host $success -ForegroundColor Green
                Add-Content -Path $logPath -Value $success
            } catch {
                $error = "Failed to set permissions on: $($folder.FullName) - $_"
                Write-Host $error -ForegroundColor Red
                Add-Content -Path $logPath -Value $error
            }
        }
    }
} else {
    $folders | ForEach-Object -Parallel {
        param($folder)
        $userName = $folder.Name
        $userIdentity = "$using:Domain\$userName"
        $acl = Get-Acl $folder.FullName

        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $userIdentity, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($userRule)

        foreach ($admin in $using:adminGroups) {
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $admin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($adminRule)
        }

        if ($using:VerifyCheck) {
            $logEntry = "[Verify-Check] Would set permissions on: $($folder.FullName)"
            Write-Host $logEntry -ForegroundColor Yellow
            Add-Content -Path $using:logPath -Value $logEntry
            $summary.Add([PSCustomObject]@{
                Folder = $folder.FullName
                UserGrantedModify = $userIdentity
                AdminsGrantedFullControl = ($using:adminGroups -join ", ")
            })
        } else {
            try {
                Set-Acl -Path $folder.FullName -AclObject $acl
                $success = "Successfully set permissions on: $($folder.FullName)"
                Write-Host $success -ForegroundColor Green
                Add-Content -Path $using:logPath -Value $success
            } catch {
                $error = "Failed to set permissions on: $($folder.FullName) - $_"
                Write-Host $error -ForegroundColor Red
                Add-Content -Path $using:logPath -Value $error
            }
        }
    } -ThrottleLimit $Threads
}

# Define display of verification check
if ($VerifyCheck -and $summary.Count -gt 0) {
    if (-not $NoTable) {
		Write-Host " " -ForegroundColor Cyan
        Write-Host "===== VERIFY CHECK SUMMARY =====" -ForegroundColor Cyan
        $summary | Sort-Object Folder | Format-Table -AutoSize
    }
    if (-not $CsvPath) {
        $CsvPath = Join-Path $RootPath "VerifyCheck_Summary.csv"
    }
    $summary | Sort-Object Folder | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Summary exported to: $CsvPath" -ForegroundColor Green
    Add-Content -Path $logPath -Value "Summary exported to: $CsvPath"
}

# Give some quick summary notes
Write-Host "Total folders processed: $foldersProcessed" -ForegroundColor Cyan
Add-Content -Path $logPath -Value "Total folders processed: $foldersProcessed"

Write-Host "Log file created at: $logPath" -ForegroundColor Cyan