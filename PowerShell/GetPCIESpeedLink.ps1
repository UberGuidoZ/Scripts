# Script: GetPCIESpeedLink.ps1
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
# Usage: .\GetPCIESpeedLink.ps1 [[-OutputCsv] <String>] [-h]

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
=============== PCIE SPEED & LINK INFO (UberGuidoZ) ================

DESCRIPTION:
    Queries WMI for all PCI bus devices and reports their PCIe spec
    version, maximum link speed/width, and current link speed/width.
    Only devices with an active PCIe link are included in output.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\GetPCIESpeedLink.ps1 [[-OutputCsv] <String>] [-h]

PARAMETERS:
    -OutputCsv <String>
        Optional. Path where CSV file will be saved.
        If omitted, results are only displayed in console.
    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:
    Example 1: Display results in console only
    .\GetPCIESpeedLink.ps1
    Example 2: Display results and export to CSV
    .\GetPCIESpeedLink.ps1 -OutputCsv "C:\Temp\PCIeInfo.csv"
    Example 3: Export with timestamp in filename
    .\GetPCIESpeedLink.ps1 -OutputCsv "C:\Reports\PCIe_`$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    Example 4: Show this help
    .\GetPCIESpeedLink.ps1 -h

OUTPUT:
    The script outputs a table with the following columns:
    - Name               : Device name as reported by Windows
    - ExpressSpecVersion : PCIe specification version supported by the device
    - MaxLinkSpeed       : Maximum PCIe link speed the device supports
    - MaxLinkWidth       : Maximum PCIe lane width the device supports (e.g., x16)
    - CurrentLinkSpeed   : Actual negotiated link speed in use
    - CurrentLinkWidth   : Actual negotiated lane width in use (e.g., x8)

NOTES:
    - Does not require NT AUTHORITY\SYSTEM; standard user access is sufficient
    - Devices without an active PCIe link (e.g., USB, legacy PCI) are excluded
    - CurrentLinkSpeed/Width may be lower than Max if the slot or CPU lanes limit it

====================================================================
"@ -ForegroundColor Cyan
    exit 0
}

# Get all devices related to PCI BUS
$pciStats = (Get-WMIObject Win32_Bus -Filter 'DeviceID like "PCI%"').GetRelated('Win32_PnPEntity') |
  foreach {
    # Request connection properties from WMI
    [pscustomobject][ordered]@{
      Name                 = $_.Name
      ExpressSpecVersion   = $_.GetDeviceProperties('DEVPKEY_PciDevice_ExpressSpecVersion').deviceProperties.data
      MaxLinkSpeed         = $_.GetDeviceProperties('DEVPKEY_PciDevice_MaxLinkSpeed'      ).deviceProperties.data
      MaxLinkWidth         = $_.GetDeviceProperties('DEVPKEY_PciDevice_MaxLinkWidth'      ).deviceProperties.data
      CurrentLinkSpeed     = $_.GetDeviceProperties('DEVPKEY_PciDevice_CurrentLinkSpeed'  ).deviceProperties.data
      CurrentLinkWidth     = $_.GetDeviceProperties('DEVPKEY_PciDevice_CurrentLinkWidth'  ).deviceProperties.data
    } |
    # Only keep devices with PCIe connections
    Where MaxLinkSpeed
  }

# Display results in console table
Write-Host "`n===================== PCIE SPEED SUMMARY ======================" -ForegroundColor Green
if ($pciStats) {
    $pciStats | Format-Table -AutoSize
    Write-Host "Total PCIe devices found: $(@($pciStats).Count)" -ForegroundColor Green
} else {
    Write-Host "No PCIe devices found." -ForegroundColor Yellow
}
Write-Host "===============================================================`n" -ForegroundColor Green

# Export to CSV if path specified
if ($OutputCsv) {
    try {
        $pciStats | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
        Write-Host "Results exported to: $OutputCsv" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}