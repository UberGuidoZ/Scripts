################################################################################################
#
# Invoke-SystemCleanup.ps1 - Comprehensive disk cleanup for all users and system-wide temp files
# 
# Must be run as NT AUTHORITY\SYSTEM or Administrator
# 
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts | v1.0 (2/11/2026)
#
# RUN FOR USAGE: .\Invoke-SystemCleanup.ps1 [-h] [-help] [-ShowHelp] [-?]
#
# Options include: -IncludeBrowserCache -DisableHibernate -RunDiskCleanup -WhatIf -LogFile
#
###############################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$IncludeBrowserCache,
    
    [Parameter(Mandatory=$false)]
    [switch]$DisableHibernate,
    
    [Parameter(Mandatory=$false)]
    [switch]$RunDiskCleanup,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFile,
    
    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

============== SYSTEM CLEANUP SCRIPT (UberGuidoZ) ==============

DESCRIPTION:
    Comprehensive disk cleanup script that cleans temp files, caches,
    and system files for all users. Optionally disables hibernate and
    runs Windows Disk Cleanup utility.

    WARNING: This script deletes files! Use -WhatIf first to review.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Invoke-SystemCleanup.ps1 [-IncludeBrowserCache] [-DisableHibernate] 
                               [-RunDiskCleanup] [-WhatIf] [[-LogFile] <String>] [-h]

PARAMETERS:
    -IncludeBrowserCache
        Clears browser cache for Chrome, Edge, and Firefox.
        Does NOT touch cookies, history, or passwords.

    -DisableHibernate
        Disables Windows hibernation and removes hiberfil.sys.

    -RunDiskCleanup
        Invokes Windows Disk Cleanup (cleanmgr.exe) with all options.

    -WhatIf
        Shows what would be deleted without actually deleting.
        STRONGLY RECOMMENDED to run this first!

    -LogFile <String>
        Path to CSV log file. Logs all deleted items with details.
        Default: CleanupLog_<timestamp>.csv in script directory

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Dry run (see what would be deleted)
    .\Invoke-SystemCleanup.ps1 -WhatIf

    Example 2: Clean temp files only
    .\Invoke-SystemCleanup.ps1

    Example 3: Full cleanup with logging
    .\Invoke-SystemCleanup.ps1 -IncludeBrowserCache -DisableHibernate -LogFile "C:\Logs\Cleanup.csv"

    Example 4: Full cleanup with auto-generated log
    .\Invoke-SystemCleanup.ps1 -IncludeBrowserCache -DisableHibernate -RunDiskCleanup

    Example 5: Dry run with all options
    .\Invoke-SystemCleanup.ps1 -IncludeBrowserCache -DisableHibernate -RunDiskCleanup -WhatIf

WHAT GETS CLEANED:
    Always:
    - Windows Temp folder
    - User temp folders (AppData\Local\Temp)
    - Recycle Bin
    - Windows Update cache
    - Prefetch files
    - Thumbnail cache
    - Windows Error Reporting
    - Delivery Optimization files
    
    With -IncludeBrowserCache:
    - Chrome cache (NOT cookies/history)
    - Edge cache (NOT cookies/history)
    - Firefox cache (NOT cookies/history)
    
    With -DisableHibernate:
    - Disables hibernation
    - Removes hiberfil.sys
    
    With -RunDiskCleanup:
    - Runs Windows Disk Cleanup utility

LOG FILE:
    CSV file contains:
    - Timestamp of deletion
    - Item path
    - Item type (File/Folder/Action)
    - Size in bytes
    - Category
    - Status (Deleted/Failed/WhatIf)
    
    Summary text file includes:
    - Total files, folders, and size
    - List of cleaned categories/directories
    - Duration and status

NOTES:
    - Requires Administrator or SYSTEM privileges
    - Use -WhatIf first to preview deletions
    - Some files may be locked and cannot be deleted
    - Log file is always created (even in WhatIf mode)

==================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator or SYSTEM"
    exit 1
}

# Setup log file
if (-not $LogFile) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogFile = Join-Path $PSScriptRoot "CleanupLog_$timestamp.csv"
}

# Statistics tracking
$script:TotalSize = 0
$script:TotalFiles = 0
$script:TotalFolders = 0
$script:DeletedItems = @()
$script:FailedItems = @()
$script:CategoriesCleaned = @()

# Function to format bytes
function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    else { return "$Bytes Bytes" }
}

# Function to log item
function Add-LogEntry {
    param(
        [string]$Path,
        [string]$Type,
        [long]$Size,
        [string]$Category,
        [string]$Status
    )
    
    $script:DeletedItems += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Path = $Path
        Type = $Type
        SizeBytes = $Size
        SizeFormatted = Format-Bytes $Size
        Category = $Category
        Status = $Status
    }
}

# Function to track cleaned categories
function Add-CategoryCleaned {
    param(
        [string]$Category,
        [string]$Path,
        [int]$Files,
        [int]$Folders,
        [long]$Size
    )
    
    if ($Files -gt 0 -or $Folders -gt 0 -or $Size -gt 0) {
        $script:CategoriesCleaned += [PSCustomObject]@{
            Category = $Category
            Path = $Path
            Files = $Files
            Folders = $Folders
            Size = $Size
            SizeFormatted = Format-Bytes $Size
        }
    }
}

# Function to clean directory
function Remove-DirectoryContents {
    param(
        [string]$Path,
        [string]$Description,
        [switch]$Recurse
    )
    
    if (-not (Test-Path $Path)) {
        Write-Host "  [SKIP] $Description - Path not found" -ForegroundColor Yellow
        Add-LogEntry -Path $Path -Type "Folder" -Size 0 -Category $Description -Status "Skipped-NotFound"
        return
    }
    
    try {
        $items = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue
        if ($Recurse) {
            $items = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        $files = $items | Where-Object { -not $_.PSIsContainer }
        $folders = $items | Where-Object { $_.PSIsContainer }
        
        $fileCount = $files.Count
        $folderCount = $folders.Count
        $size = ($files | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        
        if ($null -eq $size) { $size = 0 }
        
        if ($fileCount -eq 0 -and $folderCount -eq 0) {
            Write-Host "  [EMPTY] $Description" -ForegroundColor Gray
            Add-LogEntry -Path $Path -Type "Folder" -Size 0 -Category $Description -Status "Empty"
            return
        }
        
        if ($WhatIf) {
            Write-Host "  [WHATIF] $Description - Would delete: $fileCount files, $folderCount folders ($(Format-Bytes $size))" -ForegroundColor Cyan
            
            # Log each item
            foreach ($file in $files) {
                Add-LogEntry -Path $file.FullName -Type "File" -Size $file.Length -Category $Description -Status "WhatIf"
            }
            foreach ($folder in $folders) {
                Add-LogEntry -Path $folder.FullName -Type "Folder" -Size 0 -Category $Description -Status "WhatIf"
            }
            
            Add-CategoryCleaned -Category $Description -Path $Path -Files $fileCount -Folders $folderCount -Size $size
            
            $script:TotalSize += $size
            $script:TotalFiles += $fileCount
            $script:TotalFolders += $folderCount
        } else {
            Write-Host "  [CLEAN] $Description - Deleting $fileCount files, $folderCount folders ($(Format-Bytes $size))..." -ForegroundColor Green
            
            $deletedFiles = 0
            $deletedFolders = 0
            $deletedSize = 0
            
            # Delete files
            foreach ($file in $files) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Add-LogEntry -Path $file.FullName -Type "File" -Size $file.Length -Category $Description -Status "Deleted"
                    $script:TotalSize += $file.Length
                    $script:TotalFiles++
                    $deletedFiles++
                    $deletedSize += $file.Length
                } catch {
                    Add-LogEntry -Path $file.FullName -Type "File" -Size $file.Length -Category $Description -Status "Failed-Locked"
                    $script:FailedItems += $file.FullName
                }
            }
            
            # Delete folders
            foreach ($folder in $folders) {
                try {
                    Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                    Add-LogEntry -Path $folder.FullName -Type "Folder" -Size 0 -Category $Description -Status "Deleted"
                    $script:TotalFolders++
                    $deletedFolders++
                } catch {
                    Add-LogEntry -Path $folder.FullName -Type "Folder" -Size 0 -Category $Description -Status "Failed-Locked"
                    $script:FailedItems += $folder.FullName
                }
            }
            
            Add-CategoryCleaned -Category $Description -Path $Path -Files $deletedFiles -Folders $deletedFolders -Size $deletedSize
        }
    }
    catch {
        Write-Host "  [ERROR] $Description - $($_.Exception.Message)" -ForegroundColor Red
        Add-LogEntry -Path $Path -Type "Folder" -Size 0 -Category $Description -Status "Error: $($_.Exception.Message)"
    }
}

# Function to clean specific files by pattern
function Remove-FilesByPattern {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Description
    )
    
    if (-not (Test-Path $Path)) {
        Write-Host "  [SKIP] $Description - Path not found" -ForegroundColor Yellow
        Add-LogEntry -Path $Path -Type "Pattern" -Size 0 -Category $Description -Status "Skipped-NotFound"
        return
    }
    
    try {
        $files = Get-ChildItem -Path $Path -Filter $Pattern -Recurse -Force -ErrorAction SilentlyContinue
        $fileCount = $files.Count
        $size = ($files | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        
        if ($null -eq $size) { $size = 0 }
        
        if ($fileCount -eq 0) {
            Write-Host "  [EMPTY] $Description" -ForegroundColor Gray
            Add-LogEntry -Path "$Path\$Pattern" -Type "Pattern" -Size 0 -Category $Description -Status "Empty"
            return
        }
        
        if ($WhatIf) {
            Write-Host "  [WHATIF] $Description - Would delete: $fileCount files ($(Format-Bytes $size))" -ForegroundColor Cyan
            
            foreach ($file in $files) {
                Add-LogEntry -Path $file.FullName -Type "File" -Size $file.Length -Category $Description -Status "WhatIf"
            }
            
            Add-CategoryCleaned -Category $Description -Path $Path -Files $fileCount -Folders 0 -Size $size
            
            $script:TotalSize += $size
            $script:TotalFiles += $fileCount
        } else {
            Write-Host "  [CLEAN] $Description - Deleting $fileCount files ($(Format-Bytes $size))..." -ForegroundColor Green
            
            $deletedFiles = 0
            $deletedSize = 0
            
            foreach ($file in $files) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Add-LogEntry -Path $file.FullName -Type "File" -Size $file.Length -Category $Description -Status "Deleted"
                    $script:TotalSize += $file.Length
                    $script:TotalFiles++
                    $deletedFiles++
                    $deletedSize += $file.Length
                } catch {
                    Add-LogEntry -Path $file.FullName -Type "File" -Size $file.Length -Category $Description -Status "Failed-Locked"
                    $script:FailedItems += $file.FullName
                }
            }
            
            Add-CategoryCleaned -Category $Description -Path $Path -Files $deletedFiles -Folders 0 -Size $deletedSize
        }
    }
    catch {
        Write-Host "  [ERROR] $Description - $($_.Exception.Message)" -ForegroundColor Red
        Add-LogEntry -Path "$Path\$Pattern" -Type "Pattern" -Size 0 -Category $Description -Status "Error: $($_.Exception.Message)"
    }
}

# Banner
Write-Host "`n==================== SYSTEM CLEANUP ====================" -ForegroundColor Green
if ($WhatIf) {
    Write-Host "MODE: DRY RUN (WhatIf) - No files will be deleted" -ForegroundColor Yellow
} else {
    Write-Host "MODE: LIVE - Files will be deleted" -ForegroundColor Red
}
Write-Host "Log File: $LogFile" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Green

$cleanupStartTime = Get-Date

# 1. Clean Windows Temp
Write-Host "[1] Cleaning Windows Temp..." -ForegroundColor Cyan
Remove-DirectoryContents -Path "C:\Windows\Temp" -Description "Windows Temp" -Recurse

# 2. Clean System Temp
Write-Host "`n[2] Cleaning System Temp..." -ForegroundColor Cyan
$tempPath = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
if ($tempPath) {
    Remove-DirectoryContents -Path $tempPath -Description "System Temp" -Recurse
}

# 3. Clean all user profile temp folders
Write-Host "`n[3] Cleaning User Temp Folders..." -ForegroundColor Cyan
$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { 
    $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') 
}

foreach ($profile in $userProfiles) {
    $userTempPath = Join-Path $profile.FullName "AppData\Local\Temp"
    Remove-DirectoryContents -Path $userTempPath -Description "User Temp: $($profile.Name)" -Recurse
    
    $userIETempPath = Join-Path $profile.FullName "AppData\Local\Microsoft\Windows\INetCache"
    Remove-DirectoryContents -Path $userIETempPath -Description "IE Cache: $($profile.Name)" -Recurse
}

# 4. Clean browser caches if requested
if ($IncludeBrowserCache) {
    Write-Host "`n[4] Cleaning Browser Caches..." -ForegroundColor Cyan
    
    foreach ($profile in $userProfiles) {
        # Chrome cache
        $chromeCachePath = Join-Path $profile.FullName "AppData\Local\Google\Chrome\User Data\Default\Cache"
        Remove-DirectoryContents -Path $chromeCachePath -Description "Chrome Cache: $($profile.Name)" -Recurse
        
        $chromeCodeCachePath = Join-Path $profile.FullName "AppData\Local\Google\Chrome\User Data\Default\Code Cache"
        Remove-DirectoryContents -Path $chromeCodeCachePath -Description "Chrome Code Cache: $($profile.Name)" -Recurse
        
        # Edge cache
        $edgeCachePath = Join-Path $profile.FullName "AppData\Local\Microsoft\Edge\User Data\Default\Cache"
        Remove-DirectoryContents -Path $edgeCachePath -Description "Edge Cache: $($profile.Name)" -Recurse
        
        $edgeCodeCachePath = Join-Path $profile.FullName "AppData\Local\Microsoft\Edge\User Data\Default\Code Cache"
        Remove-DirectoryContents -Path $edgeCodeCachePath -Description "Edge Code Cache: $($profile.Name)" -Recurse
        
        # Firefox cache
        $firefoxProfilePath = Join-Path $profile.FullName "AppData\Local\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilePath) {
            $firefoxProfiles = Get-ChildItem $firefoxProfilePath -Directory -ErrorAction SilentlyContinue
            foreach ($ffProfile in $firefoxProfiles) {
                $ffCachePath = Join-Path $ffProfile.FullName "cache2"
                Remove-DirectoryContents -Path $ffCachePath -Description "Firefox Cache: $($profile.Name)" -Recurse
            }
        }
    }
}

# 5. Clean Windows Update cache
Write-Host "`n[5] Cleaning Windows Update Cache..." -ForegroundColor Cyan
Remove-DirectoryContents -Path "C:\Windows\SoftwareDistribution\Download" -Description "Windows Update Cache" -Recurse

# 6. Clean Prefetch
Write-Host "`n[6] Cleaning Prefetch..." -ForegroundColor Cyan
Remove-DirectoryContents -Path "C:\Windows\Prefetch" -Description "Prefetch Files" -Recurse

# 7. Clean Thumbnail Cache
Write-Host "`n[7] Cleaning Thumbnail Cache..." -ForegroundColor Cyan
foreach ($profile in $userProfiles) {
    $thumbCachePath = Join-Path $profile.FullName "AppData\Local\Microsoft\Windows\Explorer"
    Remove-FilesByPattern -Path $thumbCachePath -Pattern "thumbcache_*.db" -Description "Thumbnail Cache: $($profile.Name)"
}

# 8. Clean Windows Error Reporting
Write-Host "`n[8] Cleaning Windows Error Reporting..." -ForegroundColor Cyan
Remove-DirectoryContents -Path "C:\ProgramData\Microsoft\Windows\WER\ReportQueue" -Description "Error Reports" -Recurse

# 9. Clean Delivery Optimization
Write-Host "`n[9] Cleaning Delivery Optimization..." -ForegroundColor Cyan
Remove-DirectoryContents -Path "C:\Windows\SoftwareDistribution\DeliveryOptimization" -Description "Delivery Optimization" -Recurse

# 10. Clean Recycle Bin
Write-Host "`n[10] Cleaning Recycle Bin..." -ForegroundColor Cyan
if ($WhatIf) {
    Write-Host "  [WHATIF] Recycle Bin - Would be emptied" -ForegroundColor Cyan
    Add-LogEntry -Path "Recycle Bin" -Type "Action" -Size 0 -Category "Recycle Bin" -Status "WhatIf"
    Add-CategoryCleaned -Category "Recycle Bin" -Path "System" -Files 0 -Folders 0 -Size 0
} else {
    try {
        Clear-RecycleBin -Force -ErrorAction Stop
        Write-Host "  [CLEAN] Recycle Bin - Emptied" -ForegroundColor Green
        Add-LogEntry -Path "Recycle Bin" -Type "Action" -Size 0 -Category "Recycle Bin" -Status "Deleted"
        Add-CategoryCleaned -Category "Recycle Bin" -Path "System" -Files 0 -Folders 0 -Size 0
    } catch {
        Write-Host "  [ERROR] Recycle Bin - $($_.Exception.Message)" -ForegroundColor Red
        Add-LogEntry -Path "Recycle Bin" -Type "Action" -Size 0 -Category "Recycle Bin" -Status "Failed"
    }
}

# 11. Disable Hibernate if requested
if ($DisableHibernate) {
    Write-Host "`n[11] Disabling Hibernation..." -ForegroundColor Cyan
    
    if ($WhatIf) {
        $hiberFile = "C:\hiberfil.sys"
        if (Test-Path $hiberFile) {
            $size = (Get-Item $hiberFile -Force).Length
            Write-Host "  [WHATIF] Would disable hibernation and remove hiberfil.sys ($(Format-Bytes $size))" -ForegroundColor Cyan
            Add-LogEntry -Path $hiberFile -Type "File" -Size $size -Category "Hibernation" -Status "WhatIf"
            Add-CategoryCleaned -Category "Hibernation" -Path $hiberFile -Files 1 -Folders 0 -Size $size
            $script:TotalSize += $size
            $script:TotalFiles++
        } else {
            Write-Host "  [WHATIF] Would disable hibernation (hiberfil.sys not found)" -ForegroundColor Cyan
            Add-LogEntry -Path "Hibernation" -Type "Action" -Size 0 -Category "Hibernation" -Status "WhatIf-NotFound"
        }
    } else {
        try {
            $hiberFile = "C:\hiberfil.sys"
            $hiberSize = 0
            if (Test-Path $hiberFile) {
                $hiberSize = (Get-Item $hiberFile -Force).Length
            }
            
            powercfg.exe /hibernate off
            Write-Host "  [CLEAN] Hibernation disabled ($(Format-Bytes $hiberSize) recovered)" -ForegroundColor Green
            Add-LogEntry -Path $hiberFile -Type "File" -Size $hiberSize -Category "Hibernation" -Status "Deleted"
            
            if ($hiberSize -gt 0) {
                Add-CategoryCleaned -Category "Hibernation" -Path $hiberFile -Files 1 -Folders 0 -Size $hiberSize
                $script:TotalSize += $hiberSize
                $script:TotalFiles++
            }
        } catch {
            Write-Host "  [ERROR] Failed to disable hibernation - $($_.Exception.Message)" -ForegroundColor Red
            Add-LogEntry -Path "Hibernation" -Type "Action" -Size 0 -Category "Hibernation" -Status "Failed"
        }
    }
}

# 12. Run Disk Cleanup if requested
if ($RunDiskCleanup) {
    Write-Host "`n[12] Running Windows Disk Cleanup..." -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would run Disk Cleanup utility" -ForegroundColor Cyan
        Add-LogEntry -Path "Disk Cleanup (cleanmgr.exe)" -Type "Action" -Size 0 -Category "Disk Cleanup" -Status "WhatIf"
        Add-CategoryCleaned -Category "Disk Cleanup" -Path "cleanmgr.exe" -Files 0 -Folders 0 -Size 0
    } else {
        try {
            # Configure Disk Cleanup to clean all options
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
            
            # Set StateFlags0001 for all cleanup options
            $cleanupKeys = @(
                "Active Setup Temp Folders",
                "BranchCache",
                "Downloaded Program Files",
                "Internet Cache Files",
                "Memory Dump Files",
                "Offline Pages Files",
                "Old ChkDsk Files",
                "Previous Installations",
                "Recycle Bin",
                "Service Pack Cleanup",
                "Setup Log Files",
                "System error memory dump files",
                "System error minidump files",
                "Temporary Files",
                "Temporary Setup Files",
                "Thumbnail Cache",
                "Update Cleanup",
                "Upgrade Discarded Files",
                "User file versions",
                "Windows Defender",
                "Windows Error Reporting Archive Files",
                "Windows Error Reporting Queue Files",
                "Windows Error Reporting System Archive Files",
                "Windows Error Reporting System Queue Files",
                "Windows ESD installation files",
                "Windows Upgrade Log Files"
            )
            
            foreach ($key in $cleanupKeys) {
                $keyPath = Join-Path $regPath $key
                if (Test-Path $keyPath) {
                    Set-ItemProperty -Path $keyPath -Name "StateFlags0001" -Value 2 -Type DWord -ErrorAction SilentlyContinue
                }
            }
            
            Write-Host "  [INFO] Starting Disk Cleanup (this may take several minutes)..." -ForegroundColor Cyan
            Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow
            Write-Host "  [CLEAN] Disk Cleanup completed" -ForegroundColor Green
            Add-LogEntry -Path "Disk Cleanup (cleanmgr.exe)" -Type "Action" -Size 0 -Category "Disk Cleanup" -Status "Completed"
            Add-CategoryCleaned -Category "Disk Cleanup" -Path "cleanmgr.exe" -Files 0 -Folders 0 -Size 0
        } catch {
            Write-Host "  [ERROR] Failed to run Disk Cleanup - $($_.Exception.Message)" -ForegroundColor Red
            Add-LogEntry -Path "Disk Cleanup (cleanmgr.exe)" -Type "Action" -Size 0 -Category "Disk Cleanup" -Status "Failed"
        }
    }
}

$cleanupEndTime = Get-Date
$duration = $cleanupEndTime - $cleanupStartTime

# Export log to CSV
Write-Host "`nExporting log to CSV..." -ForegroundColor Cyan

try {
    # Export deleted items
    $script:DeletedItems | Export-Csv -Path $LogFile -NoTypeInformation -Encoding UTF8 -Force
    
    # Create summary text file
    $summaryFile = $LogFile -replace '\.csv$', '_Summary.txt'
    
    $summaryText = New-Object System.Text.StringBuilder
    [void]$summaryText.AppendLine("==================== CLEANUP SUMMARY ====================")
    [void]$summaryText.AppendLine("Cleanup Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$summaryText.AppendLine("Duration: $($duration.ToString('hh\:mm\:ss'))")
    [void]$summaryText.AppendLine("Mode: $(if ($WhatIf) { 'WhatIf (Dry Run)' } else { 'Live' })")
    [void]$summaryText.AppendLine("")
    [void]$summaryText.AppendLine("TOTALS:")
    [void]$summaryText.AppendLine("  Total Files: $script:TotalFiles")
    [void]$summaryText.AppendLine("  Total Folders: $script:TotalFolders")
    [void]$summaryText.AppendLine("  Total Size: $(Format-Bytes $script:TotalSize)")
    
    if ($script:FailedItems.Count -gt 0) {
        [void]$summaryText.AppendLine("  Failed Items: $($script:FailedItems.Count)")
    }
    
    [void]$summaryText.AppendLine("")
    [void]$summaryText.AppendLine("CATEGORIES CLEANED:")
    
    if ($script:CategoriesCleaned.Count -gt 0) {
        foreach ($cat in $script:CategoriesCleaned) {
            [void]$summaryText.AppendLine("")
            [void]$summaryText.AppendLine("  $($cat.Category)")
            [void]$summaryText.AppendLine("    Path: $($cat.Path)")
            [void]$summaryText.AppendLine("    Files: $($cat.Files) | Folders: $($cat.Folders) | Size: $($cat.SizeFormatted)")
        }
    } else {
        [void]$summaryText.AppendLine("  (No categories cleaned)")
    }
    
    [void]$summaryText.AppendLine("")
    [void]$summaryText.AppendLine("LOG FILES:")
    [void]$summaryText.AppendLine("  Detailed Log: $LogFile")
    [void]$summaryText.AppendLine("  Summary: $summaryFile")
    [void]$summaryText.AppendLine("=========================================================")
    
    $summaryText.ToString() | Out-File -FilePath $summaryFile -Encoding UTF8 -Force
    
    Write-Host "  [OK] Log exported to: $LogFile" -ForegroundColor Green
    Write-Host "  [OK] Summary exported to: $summaryFile" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Failed to export log - $($_.Exception.Message)" -ForegroundColor Red
}

# Summary
Write-Host "`n==================== CLEANUP SUMMARY ====================" -ForegroundColor Green
Write-Host "Duration: $($duration.ToString("hh\:mm\:ss"))" -ForegroundColor Cyan
if ($WhatIf) {
    Write-Host "Total files that would be deleted: $script:TotalFiles" -ForegroundColor Yellow
    Write-Host "Total folders that would be deleted: $script:TotalFolders" -ForegroundColor Yellow
    Write-Host "Total space that would be freed: $(Format-Bytes $script:TotalSize)" -ForegroundColor Yellow
    Write-Host "`nRun without -WhatIf to actually delete these files." -ForegroundColor Cyan
} else {
    Write-Host "Total files deleted: $script:TotalFiles" -ForegroundColor Green
    Write-Host "Total folders deleted: $script:TotalFolders" -ForegroundColor Green
    Write-Host "Total space freed: $(Format-Bytes $script:TotalSize)" -ForegroundColor Green
    if ($script:FailedItems.Count -gt 0) {
        Write-Host "Failed items (locked): $($script:FailedItems.Count)" -ForegroundColor Yellow
    }
}
Write-Host "`nLog File: $LogFile" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Green