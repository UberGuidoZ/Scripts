###################################################################################
#
# Get-SysInfo.ps1 - Quick and dirty script to display basic system info, including:
# System make and model, serial number, type (x86/x64), hostname, domain, user
#
# If just run, it will display on screen. You can also output to CSV if specified.
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
#
# RUN FOR USAGE: .\Get-SysInfo.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Csv,
    
    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

============== GET SYSTEM INFO (UberGuidoZ) ==============

DESCRIPTION:
    Quick and dirty script to display basic system info, including:
    - System make, model, and serial number
    - System type (x86/x64)
    - Hostname
    - Domain
    - Current user
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Get-SysInfo.ps1 [[-Csv] <String>] [-h]

PARAMETERS:
    -Csv <String>
        Optional. Path where CSV file will be saved.
        If omitted, results are only displayed on screen.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Display only (no CSV)
    .\Get-SysInfo.ps1

    Example 2: Display and export to CSV
    .\Get-SysInfo.ps1 -Csv "C:\Reports\SysInfo.csv"

    Example 3: Export with timestamp in filename
    .\Get-SysInfo.ps1 -Csv "C:\Reports\SysInfo_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Example 4: Show this help
    .\Get-SysInfo.ps1 -h

OUTPUT:
    The script always displays system information on screen with colored output.
    If -Csv is specified, the data is also exported to a CSV file with columns:
    Manufacturer, Model, Type, Name, Domain, UserName, Serial

NOTES:
    - Does not require NT AUTHORITY\SYSTEM; runs in the context of the current user
    - Domain field will show the local machine name if the system is not domain-joined
    - UserName field may be empty if no user is interactively logged in

=========================================================

"@ -ForegroundColor Cyan
    exit 0
}

Write-Host ""
Write-Host "Basic system info" -ForegroundColor Green
Write-Host ""

$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS

$info = [PSCustomObject]@{
    Manufacturer = $cs.Manufacturer
    Model = $cs.Model
    Type = $cs.SystemType
    Name = $cs.Name
    Domain = $cs.Domain
    UserName = $cs.UserName
    Serial = $bios.SerialNumber
}

# Display with colored values
foreach ($prop in $info.PSObject.Properties) {
    Write-Host ("{0,-13}: " -f $prop.Name) -NoNewline
    Write-Host $prop.Value -ForegroundColor Cyan
}

# Export to CSV if specified
if ($Csv) {
    try {
        $info | Export-Csv -Path $Csv -NoTypeInformation -Force -Encoding UTF8
        Write-Host "`nExported to: $Csv" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}
Write-Host ""