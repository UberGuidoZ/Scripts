###################################################################################
#
# Scan-HDD_OS.ps1 - Runs CHKDSK on C:, DISM (CheckHealth, ScanHealth,
# RestoreHealth, AnalyzeComponentStore, StartComponentCleanup), and SFC /scannow
#
# Must be run as Administrator or NT AUTHORITY\SYSTEM
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
#
# RUN FOR USAGE: .\Scan-HDD_OS.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

================= SCAN HDD / OS HEALTH (UberGuidoZ) ================

DESCRIPTION:
    Runs a full suite of Windows disk and OS health tools in sequence:
    - CHKDSK on C: to check for filesystem errors
    - DISM CheckHealth, ScanHealth, RestoreHealth to repair the OS image
    - DISM AnalyzeComponentStore and StartComponentCleanup to reclaim space
    - SFC /scannow to scan and repair protected system files
    --> Must be run as Administrator or NT AUTHORITY\SYSTEM. <--
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Scan-HDD_OS.ps1 [-h]

PARAMETERS:
    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Run full scan suite
    .\Scan-HDD_OS.ps1

    Example 2: Show this help
    .\Scan-HDD_OS.ps1 -h

OUTPUT:
    All tool output is written directly to the console.
    Each stage is announced with a colored status line before running.

NOTES:
    - Requires Administrator or NT AUTHORITY\SYSTEM privileges
    - CHKDSK /f may schedule a reboot scan if C: is in use (normal behavior)
    - DISM RestoreHealth requires internet access or a mounted Windows image
    - SFC may require a reboot to fully repair some files
    - Run from an elevated PowerShell prompt or via Task Scheduler as SYSTEM

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator or SYSTEM"
    exit 1
}

Write-Host "`n==================== HDD / OS HEALTH SCAN ====================" -ForegroundColor Green
Write-Host "Starting scan suite..." -ForegroundColor Cyan
Write-Host "==============================================================`n" -ForegroundColor Green

Write-Host "[1] Starting CHKDSK..." -ForegroundColor Cyan
CHKDSK C: /f

Write-Host "`n[2] Starting DISM CheckHealth..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /CheckHealth

Write-Host "`n[3] Starting DISM ScanHealth..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /ScanHealth

Write-Host "`n[4] Starting DISM RestoreHealth..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /RestoreHealth

Write-Host "`n[5] Starting DISM AnalyzeComponentStore..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /AnalyzeComponentStore

Write-Host "`n[6] Starting DISM StartComponentCleanup..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /StartComponentCleanup

Write-Host "`n[7] Starting SFC /scannow..." -ForegroundColor Cyan
SFC /scannow

Write-Host "`n==================== SCAN COMPLETE ==========================" -ForegroundColor Green
Write-Host "All tools completed. Review output above for any errors." -ForegroundColor Cyan
Write-Host "==============================================================`n" -ForegroundColor Green