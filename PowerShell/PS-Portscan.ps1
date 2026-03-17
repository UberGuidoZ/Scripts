####
#
# ██████╗ ███████╗      ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
# ██╔══██╗██╔════╝      ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
# ██████╔╝███████╗█████╗██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
# ██╔═══╝ ╚════██║╚════╝██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
# ██║     ███████║      ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
# ╚═╝     ╚══════╝      ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
#	PS-Portscan is a PowerShell portscanner that can detect any open ports,
#	find banners, probe TLS, and export to CSV or JSON, all with timestamps!
#	
#	NOTE: Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#	
#   Author: UberGuidoZ  |  https://github.com/UberGuidoZ/Scripts  |  Version: 1.5.5
#
# RUN FOR USAGE: .\PS-Portscan_v1_5_5.ps1 [-h] [-help] [-ShowHelp] [-?]
####

[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory = $false, ParameterSetName = 'Help')]
    [Alias('help','h','?')]
    [switch]$ShowHelp,

    [Parameter(Position = 0, ParameterSetName = 'Scan')]
    [string]$TargetHost,

    [Parameter(Position = 1, ParameterSetName = 'Scan')]
    [string]$Ports = "1-1024",

    [Parameter(ParameterSetName = 'Scan')]
    [int]$TimeoutMs = 1500,

    [Parameter(ParameterSetName = 'Scan')]
    [int]$ReadTimeoutMs = 1500,

    [Parameter(ParameterSetName = 'Scan')]
    [int]$MaxParallel = 100,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$TrySsl,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Json,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$CsvPortsPath,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$CsvOsHintsPath,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$CsvSummaryPath,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$AppendCsv,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$JsonPath
)

# Version/author metadata and single shared scan timestamp (console header only)
$scriptVersion = '1.5.5'
$author = 'UberGuidoZ'
$scanTimestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss'Z'")
$scriptName = (Split-Path -Leaf $PSCommandPath)
if (-not $scriptName) { $scriptName = (Split-Path -Leaf $MyInvocation.MyCommand.Path) }

# If no arguments or ShowHelp or TargetHost == 'help', show usage
if ($PSBoundParameters.Count -eq 0 -or $ShowHelp -or ($TargetHost -and $TargetHost -match '^(?i)help$')) {
    Write-Host @"

============= PS-PORTSCAN (UberGuidoZ) | v$scriptVersion =============

DESCRIPTION:
    Fast TCP port scanner with banner grabbing, optional TLS probing,
    and CSV/JSON export support. Compatible with Windows PowerShell 5.1
    and PowerShell 7+.
    Updates will be posted to https://github.com/UberGuidoZ/Scripts repo.

SYNTAX:
    .\$scriptName -TargetHost <String> [options]

PARAMETERS:
    -TargetHost <String>
        Required. Target hostname or IP address to scan.

    -Ports <String>
        Ports to scan. Supports comma lists and ranges. Default: "1-1024"
        Examples: "80,443"  "1-1024"  "22,80,443,8080-8090"

    -TimeoutMs <Int>
        TCP connect timeout per port in milliseconds. Default: 1500

    -ReadTimeoutMs <Int>
        Banner read timeout in milliseconds. Default: 1500

    -MaxParallel <Int>
        Maximum concurrent connections. Default: 100

    -TrySsl
        Attempt TLS handshake on common TLS ports.

    -Json
        Output JSON to console instead of table + OS hints.

    -CsvPortsPath <String>
        Export per-port results to a CSV file.

    -CsvOsHintsPath <String>
        Export OS hints to a CSV file.

    -CsvSummaryPath <String>
        Export scan summary to a CSV file.

    -CsvPath <String>
        Export all data (ports, OS hints, summary) into one unified CSV.
        Use with -AppendCsv to append instead of overwrite.

    -JsonPath <String>
        Export all data into one unified JSON file (overwrites each run).

    -AppendCsv
        Append to existing CSV files instead of overwriting.

    -ShowHelp, -help, -h, -?
        Displays this help message.

EXAMPLES:

    Example 1: Scan default ports (1-1024)
    .\$scriptName -TargetHost example.com

    Example 2: Scan specific ports with TLS probing and JSON console output
    .\$scriptName -TargetHost example.com -Ports "80,443" -TrySsl -Json

    Example 3: Scan and export to unified CSV (append mode)
    .\$scriptName -TargetHost srv.local -Ports "1-1024" -CsvPath ".\out\unified.csv" -AppendCsv

    Example 4: Scan and export to unified JSON
    .\$scriptName -TargetHost srv.local -Ports "80,443,8080-8090" -TrySsl -JsonPath ".\out\scan.json"

    Example 5: Export to separate CSVs for ports, OS hints, and summary
    .\$scriptName -TargetHost srv.local -Ports "1-1024" -CsvPortsPath ".\out\ports.csv" -CsvOsHintsPath ".\out\os_hints.csv" -CsvSummaryPath ".\out\summary.csv" -AppendCsv

    Example 6: Show this help
    .\$scriptName -h

OUTPUT:
    Console table columns:
    - Host        : Target hostname
    - IP          : Resolved IP address
    - Port        : Port number
    - Service     : Inferred service name (e.g., HTTP, SSH, RDP)
    - Status      : Open / Closed / Filtered/Timeout
    - Product     : Product/version string from banner or cert
    - Banner      : Raw banner text received
    - Certificate : TLS certificate details (if -TrySsl)
    OS Hints section lists likely OS/platform based on open ports and banners.

NOTES:
    - Does not require NT AUTHORITY\SYSTEM; runs as current user
    - Only scan systems you own or have explicit permission to test
    - Locked to sequential execution for Windows PowerShell 5.1 compatibility
    - TLS certificate validation is intentionally bypassed during scanning
    - JSON unified export overwrites on each run; use -AppendCsv for CSV persistence

====================================================================

"@ -ForegroundColor Cyan
    exit 0
}

# Console header
Write-Host "$scriptName - Version $scriptVersion"
Write-Host "Author: $author"
Write-Host "Scan start (UTC): $scanTimestamp"
Write-Host "--------------------------------------"

function Resolve-Target {
    param([string]$Name)
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($Name) | Where-Object {
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -or
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
        }
        if (-not $ips -or $ips.Count -eq 0) { throw "No addresses resolved." }
        return $ips[0]
    } catch {
        throw "Failed to resolve host '$Name': $($_.Exception.Message)"
    }
}

function Get-PortList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Spec
    )

    # Strongly-typed HashSet[int]; ::new() avoids New-Object generic parsing issues
    $portSet = [System.Collections.Generic.HashSet[int]]::new()

    foreach ($part in ($Spec -split '[,\s]+' | Where-Object { $_ -ne '' })) {
        if ($part -match '^\d+$') {
            [void]$portSet.Add([int]$part)
            continue
        }
        if ($part -match '^\s*(\d+)\s*-\s*(\d+)\s*$') {
            [int]$start = [int]$matches[1]
            [int]$end   = [int]$matches[2]
            if ($end -lt $start) { $tmp = $start; $start = $end; $end = $tmp }
            for ($i = $start; $i -le $end; $i++) {
                [void]$portSet.Add([int]$i)
            }
            continue
        }
        # Ignore invalid tokens silently
    }

    # Enumerate HashSet directly; filter and sort
    $ports = $portSet | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object
    if (-not $ports -or $ports.Count -eq 0) { throw "No valid ports to scan." }
    return ,$ports
}

function Read-BannerPlain {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [int]$Port,
        [string]$TargetHost,
        [int]$ReadTimeoutMs
    )
    $Stream.ReadTimeout = $ReadTimeoutMs
    $buffer = New-Object byte[] 4096
    $banner = $null
    try {
        Start-Sleep -Milliseconds 50
        if (-not $Stream.DataAvailable) {
            $probe =
                if ($Port -in 80,8080,8000,8008,8888,81) { "HEAD / HTTP/1.0`r`nHost: $TargetHost`r`n`r`n" }
                elseif ($Port -in 443,8443,9443)       { "HEAD / HTTP/1.0`r`nHost: $TargetHost`r`n`r`n" }
                elseif ($Port -in 21,25,110,143,587,993,995) { "`r`n" }
                else { "`r`n" }
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($probe)
            $Stream.Write($bytes, 0, $bytes.Length)
            $Stream.Flush()
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt $ReadTimeoutMs -and -not $Stream.DataAvailable) {
            Start-Sleep -Milliseconds 50
        }
        if ($Stream.DataAvailable) {
            $read = $Stream.Read($buffer, 0, $buffer.Length)
            if ($read -gt 0) {
                $banner = ([System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)).Trim()
            }
        }
    } catch { }
    return $banner
}

function Read-BannerSsl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.IO.Stream] $BaseStream,
        [Parameter(Mandatory)] [string] $Host,
        [int] $ReadTimeoutMs = 3000
    )

    $ssl = $null
    try {
        # Permissive validation for scanning; we’re not enforcing trust here
        $callback = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s,$cert,$chain,$errors) $true }

        # Wrap base stream; leave inner stream open so caller controls the TCP lifecycle
        $ssl = New-Object System.Net.Security.SslStream($BaseStream, $true, $callback)

        # Timeouts
        try { $ssl.ReadTimeout  = $ReadTimeoutMs }  catch { }
        try { $ssl.WriteTimeout = $ReadTimeoutMs } catch { }

        # SNI: use the hostname
        $ssl.AuthenticateAsClient($Host)

        # Capture certificate info if available
        $certInfo = $null
        if ($ssl.RemoteCertificate) {
            try {
                $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
                $certInfo = [pscustomobject]@{
                    Subject        = $c.Subject
                    Issuer         = $c.Issuer
                    NotBefore      = $c.NotBefore
                    NotAfter       = $c.NotAfter
                    Thumbprint     = $c.Thumbprint
                    SslProtocol    = $ssl.SslProtocol.ToString()
                    Cipher         = $ssl.CipherAlgorithm.ToString()
                    CipherStrength = $ssl.CipherStrength
                }
            } catch { }
        }

        # Send a minimal HEAD to coax headers
        $req = "HEAD / HTTP/1.1`r`nHost: $Host`r`nConnection: close`r`nUser-Agent: PS-Portscan/1.5.5`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $ssl.Write($bytes, 0, $bytes.Length)
        $ssl.Flush()

        # Read a small chunk for banner (headers)
        $buffer   = New-Object byte[] 4096
        $sb       = New-Object System.Text.StringBuilder
        $deadline = [DateTime]::UtcNow.AddMilliseconds($ReadTimeoutMs)

        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not $ssl.CanRead) { break }
            $read = 0
            try { $read = $ssl.Read($buffer, 0, $buffer.Length) } catch { break }
            if ($read -le 0) { break }
            $sb.Append([System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)) | Out-Null
            if ($sb.Length -ge 4096) { break }
            # If no more data is immediately available, stop (we only want a header snippet)
            try { if (-not $ssl.DataAvailable) { break } } catch { break }
        }

        $banner = $sb.ToString().Trim()

        return [pscustomobject]@{
            Banner      = $banner
            Certificate = $certInfo
        }
    } catch {
        return $null
    } finally {
        # Dispose SslStream wrapper only; inner TCP stream remains open for the caller’s finally block
        try { if ($ssl) { $ssl.Dispose() } } catch { }
    }
}

# Service map
$ServiceMap = @{
    7='Echo'; 9='Discard'; 13='Daytime'; 17='Quote'; 19='Chargen';
    20='FTP-Data'; 21='FTP'; 22='SSH'; 23='Telnet'; 25='SMTP'; 37='Time'; 49='TACACS';
    53='DNS'; 67='DHCP-Server'; 68='DHCP-Client'; 69='TFTP'; 80='HTTP'; 81='HTTP-Alt';
    88='Kerberos'; 110='POP3'; 111='RPCbind'; 119='NNTP'; 123='NTP';
    135='MS RPC'; 137='NetBIOS-NS'; 138='NetBIOS-DGM'; 139='NetBIOS-SSN';
    143='IMAP'; 161='SNMP'; 389='LDAP'; 443='HTTPS'; 445='SMB';
    465='SMTPS'; 500='ISAKMP'; 502='Modbus'; 515='LPD'; 520='RIP';
    524='NCP'; 548='AFP'; 554='RTSP'; 587='Submission'; 593='RPC over HTTP';
    623='IPMI'; 631='IPP'; 636='LDAPS'; 694='Corosync'; 873='rsync';
    902='VMware'; 912='VMware'; 990='FTPS'; 993='IMAPS'; 995='POP3S';
    1025='Ephemeral'; 1433='MSSQL'; 1521='Oracle'; 1723='PPTP';
    1883='MQTT'; 2049='NFS'; 2375='Docker'; 2376='Docker TLS';
    27017='MongoDB'; 3000='HTTP-Alt'; 3306='MySQL'; 3389='RDP';
    3690='SVN'; 4369='Erlang Port Mapper'; 4444='Metasploit?';
    4505='Salt-Master'; 4506='Salt-Minion';
    5000='UPnP/HTTP-Alt'; 5001='HTTP-Alt'; 5060='SIP'; 5061='SIPS';
    5432='PostgreSQL'; 5601='Kibana'; 5672='AMQP'; 5900='VNC';
    5985='WinRM-HTTP'; 5986='WinRM-HTTPS'; 6379='Redis';
    6443='Kubernetes API'; 6667='IRC';
    7001='WebLogic-HTTP'; 7002='WebLogic-HTTPS';
    8000='HTTP-Alt'; 8008='HTTP-Alt'; 8080='HTTP-Proxy'; 8081='HTTP-Alt';
    8088='HTTP-Alt'; 8181='HTTP-Alt'; 8443='HTTPS-Alt'; 8888='HTTP-Alt';
    9000='HTTP-Alt'; 9042='Cassandra'; 9200='Elasticsearch'; 9300='Elastic-Node';
    9418='Git'; 9997='Splunk Fwd'; 11211='Memcached';
}

function Infer-ServiceName {
    param([int]$Port, [string]$Banner, [string]$Cert)
    $name = $null
    if ($ServiceMap.ContainsKey($Port)) { $name = $ServiceMap[$Port] }

    if ($Banner) {
        if ($Banner -match '(?im)^\s*HTTP/\d\.\d') {
            $name = if ($Port -in 443,8443,9443) { 'HTTPS' } else { 'HTTP' }
        } elseif ($Banner -match '^\s*SSH-\d') {
            $name = 'SSH'
        } elseif ($Banner -match '^\s*\+OK|\* OK') {
            if ($Port -in 110,995) { $name = if ($Port -eq 995) { 'POP3S' } else { 'POP3' } }
            elseif ($Port -in 143,993) { $name = if ($Port -eq 993) { 'IMAPS' } else { 'IMAP' } }
        } elseif ($Banner -match '^\s*220\b.*FTP') {
            $name = if ($Port -eq 990) { 'FTPS' } else { 'FTP' }
        } elseif ($Banner -match '^\s*220\b.*ESMTP|\bSMTP\b') {
            $name = if ($Port -eq 465) { 'SMTPS' } else { 'SMTP' }
        }
    }
    if (-not $name) { $name = "tcp/$Port" }
    return $name
}

function Extract-Product {
    param([string]$Service, [string]$Banner, [string]$Cert)
    if (-not $Banner -and -not $Cert) { return $null }

    if ($Service -match '^HTTP' -or ($Banner -match '(?im)^\s*HTTP/\d\.\d')) {
        $m = [regex]::Match($Banner, '(?im)^\s*Server:\s*(.+)$')
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        $p = [regex]::Match($Banner, '(?im)^\s*X-Powered-By:\s*(.+)$')
        if ($p.Success) { return $p.Groups[1].Value.Trim() }
    }

    if ($Service -eq 'SSH' -or $Banner -match '^\s*SSH-\d') {
        $line1 = ($Banner -split "`r?`n")[0].Trim()
        if ($line1 -match '^SSH-\d+\.\d+-(.+)$') { return $matches[1].Trim() }
    }

    if ($Service -match 'SMTP') {
        if ($Banner -match '(Postfix|Exim|Sendmail|Exchange|qmail|MailEnable|Haraka|Microsoft ESMTP)') { return $matches[1] }
    }

    if ($Service -match 'FTP') {
        if ($Banner -match '(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Microsoft FTP Service|Serv-U|wu-ftp)') { return $matches[1] }
    }

    if ($Service -match 'POP3|IMAP') {
        if ($Banner -match '(Dovecot|Courier|Cyrus|Microsoft Exchange|UW IMAP)') { return $matches[1] }
    }

    if ($Banner) {
        $first = ($Banner -split "`r?`n")[0]
        if ($first.Length -gt 200) {
            return $first.Substring(0,200)
        } else {
            return $first
        }
    }

    if ($Cert) {
        if ($Cert -match 'Subject=CN=([^;]+)') { return "Cert CN: " + $matches[1].Trim() }
    }
    return $null
}

function Build-OsHints {
    param([object[]]$PortResults)
    $open = $PortResults | Where-Object { $_.Status -eq 'Open' }
    if (-not $open) { return @() }

    $hints = New-Object System.Collections.Generic.HashSet[string]

    $svc     = $open | Select-Object -ExpandProperty Service -Unique
    $prods   = ($open | ForEach-Object { $_.Product }) -join "`n"
    $banners = ($open | ForEach-Object { $_.Banner }) -join "`n"
    $certs   = ($open | ForEach-Object { $_.Certificate }) -join "`n"
    $text    = (($prods, $banners, $certs) -join "`n")

    $ports = $open | Select-Object -ExpandProperty Port

    $has = @{
    RDP       = ($ports -contains 3389)
    WINRM     = ($ports -contains 5985 -or $ports -contains 5986)
    SMB       = ($ports -contains 445 -or $ports -contains 139)
    MSRPC     = ($ports -contains 135)
    IIS       = ($text -match 'Microsoft-IIS')
    OpenSSH   = ($text -match 'OpenSSH')
    Dropbear  = ($text -match 'Dropbear')
    Samba     = ($text -match '\bSamba\b')
    Apache    = ($text -match '\bApache\b')
    Nginx     = ($text -match '\bnginx\b')
    Lighttpd  = ($text -match '\blighttpd\b')
    Caddy     = ($text -match '\bCaddy\b')
    RouterOS  = ($text -match '\bRouterOS\b|\bMikroTik\b')
    PfSense   = ($text -match '\bpfSense\b')
    OPNsense  = ($text -match '\bOPNsense\b')
    Synology  = ($text -match '\bSynology\b|DiskStation')
    QNAP      = ($text -match '\bQNAP\b')
    Ubiquiti  = ($text -match '\bUbiquiti\b|\bUniFi\b|\bEdgeOS\b')
    Cisco     = ($text -match '(?:\bCisco\b|\bASA\b|\bIOS\b(?!\s*HTTP))')
    Fortinet  = ($text -match '\bFortinet\b|\bFortiGate\b')
    PaloAlto  = ($text -match '\bPalo Alto\b|\bPAN-OS\b')
    Sophos    = ($text -match '\bSophos\b')
    FreeBSD   = ($text -match '\bFreeBSD\b')
    OpenBSD   = ($text -match '\bOpenBSD\b')
    NetBSD    = ($text -match '\bNetBSD\b')
    Exchange  = ($text -match '\bExchange\b')
    IISmail   = ($text -match 'Microsoft ESMTP')

    # Vendors/edges from Product/Banner/Cert
    Google     = ($text -match '\bgws\b' -or $text -match '\bGTS\b' -or $text -match '\bGoogle\b')
    Cloudflare = ($text -match '\bcloudflare\b' -or $text -match '\bCF-RAY\b' -or $text -match '\bCloudflare Inc\b')
    Akamai     = ($text -match '\bAkamaiGHost\b' -or $text -match '\bAkamai\b')
    AWS        = ($text -match '\bAmazonS3\b' -or $text -match '\bCloudFront\b' -or $text -match '\bawselb/\d' -or $text -match '\bELB\b')
}
    
	# Windows Services
    if ($has.RDP)     { [void]$hints.Add('Windows likely (RDP detected)') }
    if ($has.WINRM)   { [void]$hints.Add('Windows likely (WinRM detected)') }
    if ($has.IIS)     { [void]$hints.Add('Windows likely (IIS detected)') }
    if ($has.MSRPC)   { [void]$hints.Add('Windows likely (MSRPC detected)') }
    if ($has.SMB -and -not $has.Samba -and ($has.RDP -or $has.WINRM -or $has.MSRPC -or $has.IIS)) {
        [void]$hints.Add('Windows likely (SMB + other Windows services)')
    }
    
	# Web Services
    if ($has.Samba)    { [void]$hints.Add('Unix/Linux likely (Samba SMB server)') }
    if ($has.OpenSSH)  { [void]$hints.Add('Unix-like likely (OpenSSH)') }
    if ($has.Dropbear) { [void]$hints.Add('Unix/embedded likely (Dropbear SSH)') }
    if ($has.Apache)   { [void]$hints.Add('Unix-like likely (Apache HTTPD)') }
    if ($has.Nginx)    { [void]$hints.Add('Unix-like likely (nginx)') }
    if ($has.Lighttpd) { [void]$hints.Add('Unix-like likely (lighttpd)') }
    if ($has.Caddy)    { [void]$hints.Add('Unix-like likely (Caddy)') }
    if ($has.FreeBSD)  { [void]$hints.Add('BSD family (FreeBSD)') }
    if ($has.OpenBSD)  { [void]$hints.Add('BSD family (OpenBSD)') }
    if ($has.NetBSD)   { [void]$hints.Add('BSD family (NetBSD)') }
    
	# Networking
    if ($has.RouterOS) { [void]$hints.Add('MikroTik RouterOS (network appliance)') }
    if ($has.PfSense)  { [void]$hints.Add('pfSense (FreeBSD-based firewall)') }
    if ($has.OPNsense) { [void]$hints.Add('OPNsense (FreeBSD-based firewall)') }
    if ($has.Synology) { [void]$hints.Add('Synology NAS (Linux)') }
    if ($has.QNAP)     { [void]$hints.Add('QNAP NAS (Linux)') }
    if ($has.Ubiquiti) { [void]$hints.Add('Ubiquiti (EdgeOS/UniFi)') }
    if ($has.Cisco)    { [void]$hints.Add('Cisco device (network appliance)') }
    if ($has.Fortinet) { [void]$hints.Add('Fortinet (FortiGate)') }
    if ($has.PaloAlto) { [void]$hints.Add('Palo Alto Networks (PAN-OS)') }
    if ($has.Sophos)   { [void]$hints.Add('Sophos (network appliance)') }
    if ($has.Exchange) { [void]$hints.Add('Windows likely (Microsoft Exchange)') }
    if ($has.IISmail)  { [void]$hints.Add('Windows likely (Microsoft SMTP)') }
	
	# Vendors
	if ($has.Google)     { [void]$hints.Add('Google frontend or Google-hosted (gws/GTS)') }
	if ($has.Cloudflare) { [void]$hints.Add('Cloudflare (CDN/edge)') }
	if ($has.Akamai)     { [void]$hints.Add('Akamai (CDN/edge)') }
	if ($has.AWS)        { [void]$hints.Add('AWS edge/service (CloudFront/ELB/S3)') }

    if (-not $hints.Count -and ($svc -contains 'SSH')) {
        [void]$hints.Add('Possible Unix-like (SSH present)')
    }

    return @($hints) | Sort-Object
}

function Ensure-Directory {
    param([Parameter(Mandatory=$true)][string]$FilePath)
    try {
        $dir = [System.IO.Path]::GetDirectoryName($FilePath)
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    } catch {
        Write-Warning "Failed to ensure directory for '$FilePath': $($_.Exception.Message)"
    }
}

function Export-CsvUtf8 {
    param(
        [Parameter(Mandatory=$true)]$InputObject,
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$Append
    )
    Ensure-Directory -FilePath $Path
    $exists = Test-Path -LiteralPath $Path
    if ($Append -and $exists) {
        $InputObject | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Append
    } else {
        $InputObject | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

# Prep
$ip    = Resolve-Target -Name $TargetHost
$ports = Get-PortList -Spec $Ports

# TLS-capable ports to try when -TrySsl is set
$sslPorts = @(443, 8443, 9443, 993, 995, 465, 587, 990, 5443, 10443)

$results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$po = New-Object System.Threading.Tasks.ParallelOptions
$po.MaxDegreeOfParallelism = [Math]::Max(1, $MaxParallel)

# Share values across threads without $using:
$script:TargetHost    = $TargetHost
$script:ip            = $ip
$script:ReadTimeoutMs = $ReadTimeoutMs
$script:TimeoutMs     = $TimeoutMs
$script:TrySsl        = [bool]$TrySsl
$script:SslPorts      = $sslPorts
$script:results       = $results

# Measure scan duration (just the connections/banners portion)
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()

# Default: enable SSL probing and common SSL ports if not set
if ($null -eq $script:TrySsl) { $script:TrySsl = $true }
if (-not $script:SslPorts -or $script:SslPorts.Count -eq 0) { $script:SslPorts = @(443,465,993,995,8443) }

# If -Ports was not supplied, default to 1..1024
if (-not $PSBoundParameters.ContainsKey('Ports') -or [string]::IsNullOrWhiteSpace([string]$ports)) { $ports = 1..1024 }

# Normalize $ports into an actual int[] from string/int/object inputs
$raw = @($ports)  # wrap scalars, preserve arrays

# Split every element by commas/whitespace/semicolons; collect tokens
$tokens = foreach ($item in $raw) {
    if ($null -eq $item) { continue }
    if ($item -is [int]) { $item; continue }
    foreach ($t in ([string]$item -split '[,\s;]+' | Where-Object { $_ })) {
        $t.Trim()
    }
}

# Expand ranges like "1..1024" or "80-443"; handle reversed ranges and clamp
$expanded = foreach ($t in $tokens) {
    if ($t -is [int]) { $t; continue }
    if ($t -match '^\s*(\d+)\s*(?:\.\.|-)\s*(\d+)\s*$') {
        $a = [int]$matches[1]; $b = [int]$matches[2]
        if ($a -gt $b) { $a,$b = $b,$a }
        $a = [Math]::Max(1, $a); $b = [Math]::Min(65535, $b)
        if ($a -le $b) { $a..$b }
    }
    elseif ($t -match '^\d+$') {
        [int]$t
    }
}

# Cast, clamp, dedupe, and sort
$intPorts = [int[]](
    $expanded |
    Where-Object { $_ -is [int] } |
    Where-Object { $_ -ge 1 -and $_ -le 65535 } |
    Sort-Object -Unique
)

# Optional: fast exit if nothing to scan
if (-not $intPorts -or $intPorts.Count -eq 0) { return }

# Ensure results is thread-safe (kept for future parallel use)
if (-not $script:results -or -not ($script:results -is [System.Collections.Concurrent.ConcurrentBag[psobject]])) {
    $script:results = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()
}

# Normalize SslPorts to an int[] (avoids -contains surprises and nulls)
if ($script:SslPorts) {
    $script:SslPorts = [int[]](@($script:SslPorts) -split '[,\s;]+' |
        Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
} else {
    $script:SslPorts = [int[]]@()
}

# Predeclare a strongly-typed Action[int] and keep all exceptions contained
$action = [System.Action[int]]{
    param([int]$port)

    $tcp = $null
    $status = "Closed"
    $banner = $null
    $certInfo = $null

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ReceiveTimeout = $script:ReadTimeoutMs
        $tcp.SendTimeout    = $script:TimeoutMs

        # Connect with timeout, swallow transient exceptions from Wait()
        $completed = $false
        try { $completed = $tcp.ConnectAsync($script:TargetHost, $port).Wait($script:TimeoutMs) } catch { $completed = $false }
        if (-not $completed) {
            $status = "Filtered/Timeout"
            return
        }
        if (-not $tcp.Connected) {
            $status = "Closed"
            return
        }

        $status = "Open"
        $stream = $tcp.GetStream()

        if ($script:TrySsl -and ($script:SslPorts -contains $port)) {
            try {
                $sslRes = Read-BannerSsl -BaseStream $stream -Host $script:TargetHost -ReadTimeoutMs $script:ReadTimeoutMs
                if ($sslRes) {
                    $banner   = $sslRes.Banner
                    $certInfo = $sslRes.Certificate
                }
            } catch { }
        }

        if (-not $banner) {
            try {
                $plainBanner = Read-BannerPlain -Stream $stream -Port $port -Host $script:TargetHost -ReadTimeoutMs $script:ReadTimeoutMs
                if ($plainBanner) { $banner = $plainBanner }
            } catch { }
        }
    } catch {
        if ($status -eq "Open") { $status = "Error" }
        # Prevent any exception from escaping the iteration
    } finally {
        try { if ($tcp) { $tcp.Close() } } catch { }
        try {
            $obj = [pscustomobject]@{
                Host        = $script:TargetHost
                IP          = [string]$script:ip
                Port        = $port
                Status      = $status
                Banner      = $banner
                Certificate = $certInfo
            }
            $script:results.Add($obj) | Out-Null
        } catch { }
    }
}

# Run sequentially to avoid runspace errors in Windows PowerShell 5.1
foreach ($p in $intPorts) {
    try { $action.Invoke($p) } catch { }
}

$swTotal.Stop()

# Sort and enrich with service + product
$base = $results.ToArray() | Sort-Object Port
$portsOut = foreach ($r in $base) {
    $svc  = Infer-ServiceName -Port $r.Port -Banner $r.Banner -Cert $r.Certificate
    $prod = Extract-Product -Service $svc -Banner $r.Banner -Cert $r.Certificate
    [pscustomobject]@{
        Host        = $r.Host
        IP          = $r.IP
        Port        = $r.Port
        Service     = $svc
        Status      = $r.Status
        Product     = $prod
        Banner      = $r.Banner
        Certificate = $r.Certificate
    }
}

$osHints = Build-OsHints -PortResults $portsOut

# Summary values (used by both separate and unified exports)
$openCount = ($portsOut | Where-Object { $_.Status -eq 'Open' } | Measure-Object).Count
$summaryObj = [pscustomobject]@{
    Host          = $TargetHost
    IP            = $ip.ToString()
    PortsScanned  = $ports.Count
    OpenPorts     = $openCount
    DurationMs    = [int64]$swTotal.ElapsedMilliseconds
    ScanTimestamp = $scanTimestamp
}

# Separate CSV exports (if requested), using the shared ScanTimestamp
try {
    if ($CsvPortsPath) {
        $portsOutForCsv = $portsOut | Select-Object *, @{ Name = 'ScanTimestamp'; Expression = { $scanTimestamp } }
        Export-CsvUtf8 -InputObject $portsOutForCsv -Path $CsvPortsPath -Append:$AppendCsv
    }
    if ($CsvOsHintsPath) {
        $osHintObjs = @()
        foreach ($h in ($osHints | ForEach-Object { $_ })) {
            $osHintObjs += [pscustomobject]@{
                Hint          = $h
                ScanTimestamp = $scanTimestamp
            }
        }
        Export-CsvUtf8 -InputObject $osHintObjs -Path $CsvOsHintsPath -Append:$AppendCsv
    }
    if ($CsvSummaryPath) {
        Export-CsvUtf8 -InputObject $summaryObj -Path $CsvSummaryPath -Append:$AppendCsv
    }
} catch {
    Write-Warning "CSV export failed: $($_.Exception.Message)"
}

# Unified CSV export
try {
    if ($CsvPath) {
        $rows = New-Object System.Collections.Generic.List[object]

        # Port records
        foreach ($p in $portsOut) {
            $rows.Add([pscustomobject]([ordered]@{
                RecordType    = 'Port'
                Host          = $p.Host
                IP            = $p.IP
                Port          = $p.Port
                Service       = $p.Service
                Status        = $p.Status
                Product       = $p.Product
                Banner        = $p.Banner
                Certificate   = $p.Certificate
                Hint          = $null
                PortsScanned  = $null
                OpenPorts     = $null
                DurationMs    = $null
                ScanTimestamp = $scanTimestamp
            })) | Out-Null
        }

        # OS hint records
        foreach ($h in $osHints) {
            $rows.Add([pscustomobject]([ordered]@{
                RecordType    = 'OsHint'
                Host          = $TargetHost
                IP            = $ip.ToString()
                Port          = $null
                Service       = $null
                Status        = $null
                Product       = $null
                Banner        = $null
                Certificate   = $null
                Hint          = $h
                PortsScanned  = $null
                OpenPorts     = $null
                DurationMs    = $null
                ScanTimestamp = $scanTimestamp
            })) | Out-Null
        }

        # Summary record
        $rows.Add([pscustomobject]([ordered]@{
            RecordType    = 'Summary'
            Host          = $TargetHost
            IP            = $ip.ToString()
            Port          = $null
            Service       = $null
            Status        = $null
            Product       = $null
            Banner        = $null
            Certificate   = $null
            Hint          = $null
            PortsScanned  = $summaryObj.PortsScanned
            OpenPorts     = $summaryObj.OpenPorts
            DurationMs    = $summaryObj.DurationMs
            ScanTimestamp = $summaryObj.ScanTimestamp
        })) | Out-Null

        Export-CsvUtf8 -InputObject $rows -Path $CsvPath -Append:$AppendCsv
    }
} catch {
    Write-Warning "Unified CSV export failed: $($_.Exception.Message)"
}

# Unified JSON export (overwrite each run)
try {
    if ($JsonPath) {
        Ensure-Directory -FilePath $JsonPath
        $unifiedJson = [pscustomobject]@{
            Summary = $summaryObj      # includes ScanTimestamp
            Ports   = $portsOut
            OsHints = $osHints
        }
        $jsonText = $unifiedJson | ConvertTo-Json -Depth 8
        $jsonText | Out-File -FilePath $JsonPath -Encoding utf8
    }
} catch {
    Write-Warning "Unified JSON export failed: $($_.Exception.Message)"
}

# Console output (unchanged)
if ($Json) {
    [pscustomobject]@{
        Ports   = $portsOut
        OsHints = $osHints
    } | ConvertTo-Json -Depth 6
} else {
    $portsOut
    ""
    "OS Hints:"
    if ($osHints.Count -gt 0) {
        foreach ($h in $osHints) { " - $h" }
    } else {
        " - (No OS hints derived)"
    }
}

# Examples:
# .\$scriptName -TargetHost example.com
# .\$scriptName -TargetHost example.com -Ports "80,443,8443" -TrySsl -Json
# .\$scriptName -TargetHost srv.local -Ports "1-1024" -CsvPath ".\out\unified.csv" -AppendCsv
# .\$scriptName -TargetHost srv.local -Ports "80,443,8080-8090" -TrySsl -JsonPath ".\out\scan.json"
# .\$scriptName -TargetHost srv.local -Ports "1-1024" -CsvPortsPath ".\out\ports.csv" -CsvOsHintsPath ".\out\os_hints.csv" -CsvSummaryPath ".\out\summary.csv" -AppendCsv
# Only scan systems you own or have explicit permission to test.