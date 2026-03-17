# Script: Get-HashManifest.ps1
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
# Generates hash manifest files for integrity verification

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Path = ".",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
    [string[]]$Hash = @('MD5'),
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse,
    
    [Parameter(Mandatory=$false)]
    [string]$Verify,
    
    [Parameter(Mandatory=$false)]
    [string]$Filter = "*",
    
    [Parameter(Mandatory=$false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

=============== HASH MANIFEST GENERATOR (UberGuidoZ) +++============

DESCRIPTION:
    Generates cryptographic hash manifests for files to verify integrity.
    Can create new manifests or verify files against existing manifests.
    Supports multiple hash algorithms simultaneously. Outputs to CSV format.
	Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Get-HashManifest.ps1 [[-Path] <String>] [[-Hash] <String[]>] 
                       [[-OutputFile] <String>] [-Recurse] 
                       [[-Verify] <String>] [[-Filter] <String>] [-h]

PARAMETERS:
    -Path <String>
        Directory path to scan for files.
        Default: Current directory

    -Hash <String[]>
        Hash algorithm(s) to use: MD5, SHA1, SHA256, SHA384, SHA512
        Can specify multiple algorithms separated by commas.
        Default: MD5

    -OutputFile <String>
        Path for the manifest CSV file.
        Default: HashManifest_<Hashes>_<timestamp>.csv

    -Recurse
        Include subdirectories in the scan.

    -Verify <String>
        Path to existing manifest CSV file to verify against.
        Skips manifest generation and performs verification only.

    -Filter <String>
        File filter pattern (e.g., "*.exe", "*.dll").
        Default: * (all files)

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Generate manifest for current directory (MD5)
    .\Get-HashManifest.ps1

    Example 2: Generate manifest with multiple hash algorithms
    .\Get-HashManifest.ps1 -Hash MD5,SHA1,SHA256

    Example 3: Generate manifest with SHA256 for specific path
    .\Get-HashManifest.ps1 -Path "C:\MyFiles" -Hash SHA256

    Example 4: Generate manifest recursively for all DLL files (MD5 + SHA256)
    .\Get-HashManifest.ps1 -Path "C:\Program Files" -Recurse -Filter "*.dll" -Hash MD5,SHA256

    Example 5: Generate manifest with custom output file
    .\Get-HashManifest.ps1 -Path "C:\MyApp" -OutputFile "C:\Manifests\MyApp_Hashes.csv"

    Example 6: Verify files against existing manifest
    .\Get-HashManifest.ps1 -Verify "C:\Manifests\MyApp_Hashes.csv"

    Example 7: Show help
    .\Get-HashManifest.ps1 -h

OUTPUT:
    CSV file with columns:
    - FileName: Name of the file
    - RelativePath: Path relative to the base directory
    - MD5: MD5 hash (if requested)
    - SHA1: SHA1 hash (if requested)
    - SHA256: SHA256 hash (if requested)
    - SHA384: SHA384 hash (if requested)
    - SHA512: SHA512 hash (if requested)

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# Function to generate manifest
function New-Manifest {
    param(
        [string]$BasePath,
        [string[]]$HashAlgorithms,
        [string]$Output,
        [bool]$IncludeSubdirs,
        [string]$FileFilter
    )
    
    Write-Host "`n==================== GENERATING HASH MANIFEST ====================" -ForegroundColor Green
    Write-Host "Path: $BasePath" -ForegroundColor Cyan
    Write-Host "Algorithm(s): $($HashAlgorithms -join ', ')" -ForegroundColor Cyan
    Write-Host "Filter: $FileFilter" -ForegroundColor Cyan
    Write-Host "Recursive: $IncludeSubdirs" -ForegroundColor Cyan
    Write-Host ""
    
    # Get files
    $files = if ($IncludeSubdirs) {
        Get-ChildItem -Path $BasePath -Filter $FileFilter -File -Recurse -ErrorAction SilentlyContinue
    } else {
        Get-ChildItem -Path $BasePath -Filter $FileFilter -File -ErrorAction SilentlyContinue
    }
    
    if ($files.Count -eq 0) {
        Write-Host "No files found matching criteria." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Found $($files.Count) file(s) to process..." -ForegroundColor Cyan
    Write-Host ""
    
    $results = @()
    $counter = 0
    
    foreach ($file in $files) {
        $counter++
        $percentComplete = ($counter / $files.Count) * 100
        Write-Progress -Activity "Computing hashes" -Status "$counter of $($files.Count)" -PercentComplete $percentComplete
        
        try {
            $relativePath = $file.FullName.Replace($BasePath, "").TrimStart('\')
            $hashValues = @{}
            
            # Compute all requested hashes
            foreach ($algo in $HashAlgorithms) {
                $hash = Get-FileHash -Path $file.FullName -Algorithm $algo -ErrorAction Stop
                $hashValues[$algo] = $hash.Hash
            }
            
            $resultObj = [PSCustomObject]@{
                FileName = $file.Name
                RelativePath = $relativePath
            }
            
            # Add hash properties dynamically
            foreach ($algo in $HashAlgorithms) {
                $resultObj | Add-Member -MemberType NoteProperty -Name $algo -Value $hashValues[$algo]
            }
            
            $results += $resultObj
            
            Write-Host "[OK] $relativePath" -ForegroundColor Green
        }
        catch {
            Write-Host "[FAIL] $($file.FullName) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Progress -Activity "Computing hashes" -Completed
    
    # Generate output file name if not specified
    if (-not $Output) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $algoString = $HashAlgorithms -join '_'
        $Output = Join-Path $BasePath "HashManifest_$($algoString)_$timestamp.csv"
    }
    
    # Ensure output has .csv extension
    if ($Output -notmatch '\.csv$') {
        $Output += '.csv'
    }
    
    # Write manifest CSV file
    try {
        $results | Export-Csv -Path $Output -NoTypeInformation -Encoding UTF8 -Force
        
        Write-Host "`n==================== MANIFEST GENERATED ====================" -ForegroundColor Green
        Write-Host "Output File: $Output" -ForegroundColor Cyan
        Write-Host "Format: CSV" -ForegroundColor Cyan
        Write-Host "Total Files: $($results.Count)" -ForegroundColor Cyan
        Write-Host "Algorithms: $($HashAlgorithms -join ', ')" -ForegroundColor Cyan
        Write-Host "============================================================`n" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to write manifest file: $_"
    }
}

# Function to verify manifest
function Test-Manifest {
    param(
        [string]$ManifestPath
    )
    
    Write-Host "`n==================== VERIFYING HASH MANIFEST ====================" -ForegroundColor Green
    Write-Host "Manifest: $ManifestPath" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Path $ManifestPath)) {
        Write-Error "Manifest file not found: $ManifestPath"
        return
    }
    
    # Import CSV manifest
    try {
        $entries = Import-Csv -Path $ManifestPath -Encoding UTF8
    }
    catch {
        Write-Error "Failed to read manifest CSV: $_"
        return
    }
    
    if ($entries.Count -eq 0) {
        Write-Host "No entries found in manifest." -ForegroundColor Yellow
        return
    }
    
    # Determine which hash algorithms are in the manifest
    $algorithms = @()
    $sampleEntry = $entries[0]
    foreach ($prop in $sampleEntry.PSObject.Properties) {
        if ($prop.Name -in @('MD5','SHA1','SHA256','SHA384','SHA512')) {
            $algorithms += $prop.Name
        }
    }
    
    if ($algorithms.Count -eq 0) {
        Write-Error "No hash algorithms found in manifest"
        return
    }
    
    # Determine base path from first entry
    $firstEntry = $entries[0]
    $basePath = $null
    
    # Try to find the base path by checking if the relative path exists from current directory
    $testPath = Join-Path (Get-Location).Path $firstEntry.RelativePath
    if (Test-Path $testPath) {
        $basePath = (Get-Location).Path
    } else {
        # Ask user for base path or try to infer
        Write-Host "Base path not automatically determined." -ForegroundColor Yellow
        Write-Host "Current directory will be used as base path." -ForegroundColor Yellow
        $basePath = (Get-Location).Path
    }
    
    Write-Host "Algorithm(s): $($algorithms -join ', ')" -ForegroundColor Cyan
    Write-Host "Base Path: $basePath" -ForegroundColor Cyan
    Write-Host "Entries: $($entries.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    $passed = 0
    $failed = 0
    $missing = 0
    $counter = 0
    
    foreach ($entry in $entries) {
        $counter++
        $percentComplete = ($counter / $entries.Count) * 100
        Write-Progress -Activity "Verifying hashes" -Status "$counter of $($entries.Count)" -PercentComplete $percentComplete
        
        $fullPath = Join-Path $basePath $entry.RelativePath
        
        if (-not (Test-Path $fullPath)) {
            Write-Host "[MISSING] $($entry.RelativePath)" -ForegroundColor Magenta
            $missing++
            continue
        }
        
        try {
            $allMatch = $true
            $failDetails = @()
            
            # Verify all algorithms present in the manifest
            foreach ($algo in $algorithms) {
                $currentHash = (Get-FileHash -Path $fullPath -Algorithm $algo -ErrorAction Stop).Hash
                $expectedHash = $entry.$algo
                
                if ($currentHash -ne $expectedHash) {
                    $allMatch = $false
                    $failDetails += "[$algo] Expected: $expectedHash, Got: $currentHash"
                }
            }
            
            if ($allMatch) {
                Write-Host "[PASS] $($entry.RelativePath)" -ForegroundColor Green
                $passed++
            } else {
                Write-Host "[FAIL] $($entry.RelativePath)" -ForegroundColor Red
                foreach ($detail in $failDetails) {
                    Write-Host "       $detail" -ForegroundColor Red
                }
                $failed++
            }
        }
        catch {
            Write-Host "[ERROR] $($entry.RelativePath) - $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
    
    Write-Progress -Activity "Verifying hashes" -Completed
    
    # Summary
    Write-Host "`n==================== VERIFICATION SUMMARY ====================" -ForegroundColor Green
    Write-Host "Total Files: $($entries.Count)" -ForegroundColor Cyan
    Write-Host "Passed:      $passed" -ForegroundColor Green
    Write-Host "Failed:      $failed" -ForegroundColor Red
    Write-Host "Missing:     $missing" -ForegroundColor Magenta
    
    if ($failed -eq 0 -and $missing -eq 0) {
        Write-Host "`nResult: ALL FILES VERIFIED SUCCESSFULLY" -ForegroundColor Green
    } else {
        Write-Host "`nResult: VERIFICATION FAILED" -ForegroundColor Red
    }
    Write-Host "============================================================`n" -ForegroundColor Green
}

# Main execution
if ($Verify) {
    # Verification mode
    Test-Manifest -ManifestPath $Verify
} else {
    # Generation mode
    $resolvedPath = Resolve-Path -Path $Path -ErrorAction SilentlyContinue
    if (-not $resolvedPath) {
        Write-Error "Path not found: $Path"
        exit 1
    }
    
    New-Manifest -BasePath $resolvedPath.Path `
                 -HashAlgorithms $Hash `
                 -Output $OutputFile `
                 -IncludeSubdirs $Recurse `
                 -FileFilter $Filter
}