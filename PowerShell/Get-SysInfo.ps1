###################################################################################
#
# Get-SysInfo.ps1 - Quick and dirty script to display basic system info, including:
# System make and model, serial number, type (x86/x64), hostname, domain, user
#
# Use -mem to also display detailed memory slot and chip information.
#
# If just run, it will display on screen. You can also output to CSV if specified.
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts  |  v2.0
#
# RUN FOR USAGE: .\Get-SysInfo.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Csv,

    [Parameter(Mandatory=$false)]
    [switch]$mem,

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
    Use -mem to also show memory slot usage and per-chip details.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Get-SysInfo.ps1 [[-Csv] <String>] [-mem] [-h]

PARAMETERS:
    -Csv <String>
        Optional. Path where CSV file will be saved.
        If omitted, results are only displayed on screen.

    -mem
        Optional. Also queries and displays detailed memory information:
        total/used/empty slots and a per-chip table (capacity, speed,
        manufacturer, part number). The memory table is appended to the
        CSV when -Csv is also specified.

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Display only (no CSV)
    .\Get-SysInfo.ps1

    Example 2: Display and export to CSV
    .\Get-SysInfo.ps1 -Csv "C:\Reports\SysInfo.csv"

    Example 3: Export with timestamp in filename
    .\Get-SysInfo.ps1 -Csv "C:\Reports\SysInfo_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Example 4: Display with extended memory info
    .\Get-SysInfo.ps1 -mem

    Example 5: Extended info exported to CSV
    .\Get-SysInfo.ps1 -mem -Csv "C:\Reports\SysInfo.csv"

    Example 6: Show this help
    .\Get-SysInfo.ps1 -h

OUTPUT:
    The script always displays system information on screen with colored output.
    If -Csv is specified, the data is also exported to a CSV file with columns:
    Manufacturer, Model, Type, Name, Domain, UserName, Serial

    With -mem and -Csv, a second CSV is written alongside the first named
    <basename>.memory.csv with columns:
    Slot, Capacity (GB), Speed (MHz), Manufacturer, Part Number

NOTES:
    - Does not require NT AUTHORITY\SYSTEM; runs in the context of the current user
    - Domain field will show the local machine name if the system is not domain-joined
    - UserName field may be empty if no user is interactively logged in
    - Memory speed falls back to rated Speed if ConfiguredClockSpeed is not populated

=========================================================

"@ -ForegroundColor Cyan
    exit 0
}

# -- Basic system info --------------------------------------------------------

Write-Host ""
Write-Host "Basic system info" -ForegroundColor Green
Write-Host ""

try {
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS           -ErrorAction Stop
} catch {
    Write-Error "Failed to query system information: $_"
    exit 1
}

$info = [PSCustomObject]@{
    Manufacturer = $cs.Manufacturer
    Model        = $cs.Model
    Type         = $cs.SystemType
    Name         = $cs.Name
    Domain       = $cs.Domain
    UserName     = $cs.UserName
    Serial       = $bios.SerialNumber
}

# Display with colored values
foreach ($prop in $info.PSObject.Properties) {
    Write-Host ("{0,-13}: " -f $prop.Name) -NoNewline
    Write-Host $prop.Value -ForegroundColor Cyan
}

# Export basic info to CSV if specified
if ($Csv) {
    try {
        $info | Export-Csv -Path $Csv -NoTypeInformation -Force -Encoding UTF8
        Write-Host "`nExported to: $Csv" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

Write-Host ""

# -- Extended memory info (only when -mem is passed) ---------------------

if ($mem) {

    try {
        $MemoryChips = Get-CimInstance -ClassName Win32_PhysicalMemory     -ErrorAction Stop
        $MemoryArray = Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction Stop
    } catch {
        Write-Error "Failed to query memory information: $_"
        exit 1
    }

    # Sum across all arrays so multi-socket / server systems report correctly
    $TotalSlots = ($MemoryArray | Measure-Object -Property MemoryDevices -Sum).Sum
    $UsedSlots  = ($MemoryChips | Measure-Object).Count
    $EmptySlots = $TotalSlots - $UsedSlots

    Write-Host "--- Memory Slot Summary ---" -ForegroundColor Cyan
    Write-Host "Total Slots Available: $TotalSlots"
    Write-Host "Slots Currently Used:  $UsedSlots"
    Write-Host "Empty Slots:           $EmptySlots"
    Write-Host ""

    Write-Host "--- Installed Memory Details ---" -ForegroundColor Cyan
    $memTable = $MemoryChips | Select-Object `
        @{Name="Slot";          Expression={$_.DeviceLocator}},
        @{Name="Capacity (GB)"; Expression={if ($_.Capacity) {[math]::Round($_.Capacity / 1GB, 2)} else {"N/A"}}},
        @{Name="Speed (MHz)";   Expression={if ($_.ConfiguredClockSpeed) {$_.ConfiguredClockSpeed} else {$_.Speed}}},
        @{Name="Manufacturer";  Expression={if ($_.Manufacturer) {$_.Manufacturer.Trim()} else {""}}},
        @{Name="Part Number";   Expression={if ($_.PartNumber)   {$_.PartNumber.Trim()}   else {""}}}

    $memTable | Format-Table -AutoSize

    # Append memory CSV alongside the main one if -Csv was also given
    if ($Csv) {
        $memCsvPath = [System.IO.Path]::Combine(
            [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Csv)),
            [System.IO.Path]::GetFileNameWithoutExtension($Csv) + ".memory.csv"
        )
        try {
            $memTable | Export-Csv -Path $memCsvPath -NoTypeInformation -Force -Encoding UTF8
            Write-Host "Memory details exported to: $memCsvPath" -ForegroundColor Green
        } catch {
            Write-Error "Failed to export memory CSV: $_"
        }
    }

    Write-Host ""
}
