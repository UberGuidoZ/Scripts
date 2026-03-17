#Requires -Version 5.1

###################################################################################
#
# Invoke-RemoteExecutable.ps1 - Remotely executes an executable on a target machine
# via PowerShell Remoting. Creates a persistent PSSession, validates file existence,
# executes with timeout, captures output and exit code, and ensures cleanup.
#
# By: UberGuidoZ | https://github.com/UberGuidoZ/Scripts
#
# RUN FOR USAGE: .\Invoke-RemoteExecutable.ps1 [-h] [-help] [-ShowHelp] [-?]
#
###################################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if ($_ -notmatch '^[a-zA-Z]:\\.*\.exe$') {
            throw "Must be a full path to an .exe file (e.g., C:\Tools\Some_Tool.exe)"
        }
        return $true
    })]
    [string]$ExecutablePath,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3600)]
    [int]$TimeoutSeconds = 300,

    [Parameter(Mandatory = $false)]
    [Alias('h','help','?')]
    [switch]$ShowHelp
)

# Display help if requested
if ($ShowHelp) {
    Write-Host @"

============= REMOTE EXECUTABLE RUNNER (UberGuidoZ) ================

DESCRIPTION:
    Remotely executes an executable on a target machine via PowerShell
    Remoting. Creates a persistent PSSession, validates file existence,
    executes with timeout, captures output and exit code, and ensures cleanup.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\Invoke-RemoteExecutable.ps1 -ComputerName <String> -ExecutablePath <String>
        [[-Credential] <PSCredential>] [[-TimeoutSeconds] <Int>] [-h]

PARAMETERS:
    -ComputerName <String>
        Required. Target machine hostname or IP address.

    -ExecutablePath <String>
        Required. Full path to the executable on the remote machine.
        Must be a valid .exe path (e.g., C:\Tools\Some_Tool.exe).

    -Credential <PSCredential>
        Optional. Credentials to use for the remote session.
        If not provided, a credential prompt will appear.

    -TimeoutSeconds <Int>
        Optional. Maximum execution time in seconds (1-3600).
        Default: 300 (5 minutes).

    -h, -help, -ShowHelp, -?
        Displays this help message.

EXAMPLES:

    Example 1: Basic usage (prompts for credentials)
    .\Invoke-RemoteExecutable.ps1 -ComputerName "SERVER01" -ExecutablePath "C:\Tools\some_tool.exe"

    Example 2: With pre-stored credentials and custom timeout
    `$cred = Get-Credential
    .\Invoke-RemoteExecutable.ps1 -ComputerName "SERVER01" -ExecutablePath "C:\Tools\some_tool.exe" -Credential `$cred -TimeoutSeconds 600

    Example 3: Batch execution across multiple servers
    `$servers = "SERVER01", "SERVER02", "SERVER03"
    `$cred = Get-Credential
    `$exePath = "C:\Tools\some_tool.exe"
    foreach (`$server in `$servers) {
        .\Invoke-RemoteExecutable.ps1 -ComputerName `$server -ExecutablePath `$exePath -Credential `$cred
    }

    Example 4: Show this help
    .\Invoke-RemoteExecutable.ps1 -h

OUTPUT:
    On success, the script displays:
    - Computer      : Target machine name
    - Executable    : Path of the executed file
    - Exit Code     : Remote process exit code
    - Success       : Whether execution completed without error
    - Timed Out     : Whether the process exceeded TimeoutSeconds
    - SHA256        : Hash of the remote executable
    - Executed      : Timestamp of execution

EXIT CODES:
    0       Success
    1       General error (connection, validation, etc.)
    124     Timeout exceeded
    <other> Remote executable's own exit code

NOTES:
    - Does not require NT AUTHORITY\SYSTEM; user must be local admin on target
    - WinRM must be enabled on the target: Enable-PSRemoting -Force
    - Firewall must allow TCP 5985 (HTTP) or TCP 5986 (HTTPS)
    - Test connectivity first: Test-NetConnection -ComputerName <target> -Port 5985
    - Use -Verbose for detailed session and execution output

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

$ErrorActionPreference = 'Stop'

# Prompt for credentials if not provided
if (-not $Credential) {
    $Credential = Get-Credential -Message "Enter admin credentials for $ComputerName"
    if (-not $Credential) {
        Write-Error "Credentials are required"
        exit 1
    }
}

$session = $null

try {
    Write-Verbose "Establishing PSSession to $ComputerName..."
    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
    Write-Host "[+] Connected to $ComputerName" -ForegroundColor Green

    Write-Verbose "Executing $ExecutablePath remotely with $TimeoutSeconds second timeout..."
    
    $result = Invoke-Command -Session $session -ScriptBlock {
        param($exePath, $timeout)
        
        # Validate file exists
        if (-not (Test-Path -Path $exePath -PathType Leaf)) {
            throw "Executable not found: $exePath"
        }

        # Get file metadata for logging
        $fileInfo = Get-Item -Path $exePath
        $fileHash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash

        # Setup output capture
        $outFile = Join-Path $env:TEMP "remote_exec_$([guid]::NewGuid()).out"
        $errFile = Join-Path $env:TEMP "remote_exec_$([guid]::NewGuid()).err"

        try {
            # Execute with timeout using job
            $jobScript = {
                param($exe, $out, $err)
                $proc = Start-Process -FilePath $exe -NoNewWindow -PassThru -Wait `
                    -RedirectStandardOutput $out -RedirectStandardError $err
                return $proc.ExitCode
            }

            $job = Start-Job -ScriptBlock $jobScript -ArgumentList $exePath, $outFile, $errFile
            $completed = Wait-Job -Job $job -Timeout $timeout

            if ($completed) {
                $exitCode = Receive-Job -Job $job
                $timedOut = $false
            } else {
                Stop-Job -Job $job
                $exitCode = -1
                $timedOut = $true
            }

            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

            # Read output
            $stdout = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
            $stderr = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { "" }

            return @{
                ExitCode     = $exitCode
                Success      = ($exitCode -eq 0 -and -not $timedOut)
                TimedOut     = $timedOut
                StdOut       = $stdout
                StdErr       = $stderr
                FileHash     = $fileHash
                FileVersion  = $fileInfo.VersionInfo.FileVersion
                FileSize     = $fileInfo.Length
                ExecutedAt   = Get-Date -Format 'o'
            }

        } finally {
            # Cleanup temp files
            Remove-Item $outFile, $errFile -ErrorAction SilentlyContinue
        }

    } -ArgumentList $ExecutablePath, $TimeoutSeconds

    # Report results
    Write-Host "`n[+] Remote execution completed" -ForegroundColor Green
    Write-Host "    Computer:    $ComputerName"
    Write-Host "    Executable:  $ExecutablePath"
    Write-Host "    Exit Code:   $($result.ExitCode)" -ForegroundColor $(if ($result.Success) { "Green" } else { "Yellow" })
    Write-Host "    Success:     $($result.Success)" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
    Write-Host "    Timed Out:   $($result.TimedOut)" -ForegroundColor $(if ($result.TimedOut) { "Red" } else { "Green" })
    Write-Host "    SHA256:      $($result.FileHash)"
    Write-Host "    Executed:    $($result.ExecutedAt)"

    if ($result.StdOut) {
        Write-Verbose "Standard Output:`n$($result.StdOut)"
    }

    if ($result.StdErr) {
        Write-Warning "Standard Error:`n$($result.StdErr)"
    }

    # Exit with remote exit code
    if (-not $result.Success) {
        if ($result.TimedOut) {
            Write-Error "Process exceeded $TimeoutSeconds second timeout"
            exit 124  # Standard timeout exit code
        } else {
            Write-Error "Process exited with code $($result.ExitCode)"
            exit $result.ExitCode
        }
    }

    exit 0

} catch {
    Write-Error "Remote execution failed: $($_.Exception.Message)"
    Write-Verbose "Full error: $_"
    exit 1

} finally {
    if ($session) {
        Write-Verbose "Cleaning up PSSession..."
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}