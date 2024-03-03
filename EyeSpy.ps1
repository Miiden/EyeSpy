function EyeSpy {

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$Scan,

        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$FullAuto,

        #[Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        #[int]$Threads = 50,

        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [Switch]$Help

    )

    if ($Help) {

        $HelpOutput = @("
[ Help ] ================================================

                    EyeSpy 
                    by: Miiden

=========================================================
 
 Example Usage:

 EyeSpy -Scan 192.168.0.1/24
 Eyespy -FullAuto 192.168.0.1/24

=========================================================
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

    if (!$Scan -and !$FullAuto) {
    
        Write-Host
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "You must provide either -Scan or -FullAuto"
    
        Write-Host "[!] " -ForegroundColor "Red" -NoNewline
        Write-Host "Run ""EyeSpy -Help"" for command line usage"
        Write-Host
    
        return
    
    }

$Banner

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
                    $HostIDInBinary = '0' * $HostBits
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



function PortScan {
        [CmdletBinding(ConfirmImpact = 'None')]
        Param(
            [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $Target
        ) 

    $Ports = @(554, 8554, 5554)
    $Timeout = 300
    $AlivePorts = @()

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
                        return "$Target`:$Port" 
                    }
                }
                catch {
                    #Errorhandling Catch
                    $tcpClient.Close()
                    return "Error with Connection"
                }
            }
            else {
                #Port Closed
                $tcpClient.Close()
                return "Error with Connection"
            }
        }

        foreach ($Computer in $Target) {
            foreach ($Port in $Ports){
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
}


function Async-Runspaces {
        [CmdletBinding(ConfirmImpact = 'None')]
        Param(
            [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $Target,
            [Parameter(Mandatory, ValueFromPipeline, Position = 1)]
            [string[]] $Option

        )     
        $Threads = 50
        $Timeout = 300

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
        $runspacePool.Open()
        $runspaces = New-Object System.Collections.ArrayList

        if ($Option = "PortScan"){
            PortScan -Target $Target
        }

        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
                if ($runspace.Handle.IsCompleted) {
                    
                    $runspace.Completed = $true
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                    $runspace.Runspace.Dispose()
                    $runspace.Handle.AsyncWaitHandle.Close()

                    if ($result -eq "Error with Connection"){
                        continue
                    }
                    else {
                        Write-Host -ForegroundColor Green "$result"
                        $ReturnedResult += $result
                    }
                }
            }

            Start-Sleep -Milliseconds 100
        } while ($runspaces | Where-Object { -not $_.Completed })

        # Clean up
        $runspacePool.Close()
        $runspacePool.Dispose()
        return $ReturnedResult
}


function Send-Packets {
        [CmdletBinding(ConfirmImpact = 'None')]
        Param(
            [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $AlivePorts
        )   

        foreach ($AlivePort in $AlivePorts){
        
            $IP = ($AlivePort -split ':')[0]
            [int]$Port = ($AlivePort -split ':')[1]
            $Encoding = [System.Text.Encoding]::ASCII
            [int] $TimeoutMilliseconds = 100 
            $open = $false

            $Sock = New-Object System.Net.Sockets.TcpClient

            try {
                $connectionResult = $Sock.BeginConnect($IP,$Port,$null,$null)
                $connectionSuccess = $connectionResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)

                if ($connectionSuccess -and $Sock.Connected) { 
                    $open = $true 
                } 
                else { 
                    throw "Connection attempt failed or timed out" 
                }
            }
            catch {
                Write-Host "Failed to connect to $IP`:$Port"
                #return [pscustomobject]@{ Address = $IP; Port = $port; Open = $open }
            }

            if ($open) {
                $Stream = $Sock.GetStream()
                $Reader = New-Object System.IO.StreamReader($Stream)
                $Reader.BaseStream.ReadTimeout = $TimeoutMilliseconds
                $Writer = New-Object System.IO.StreamWriter($Stream)

                $CRLF = [char]13 + [char]10  # Carriage Return + Line Feed
                $request = "DESCRIBE rtsp://$IP`:$Port/ RTSP/1.0$CRLF" +
                           "CSeq: 2$CRLF$CRLF"

                $Writer.Write($request)
                $Writer.Flush()

                $response = ''
                try {
                    Start-Sleep -Milliseconds 100
                    while ($Stream.CanRead) {
                        $line = $Reader.ReadLine()
                        if ($line -eq $null) { break }
                        $response += $line + $CRLF
                    }
                } catch [System.IO.IOException] {
                    # Catching the exception without taking any action
            
                    # Debugging: Handle timeout or connection closed gracefully
                    #Write-Host "Error reading response: $_"
                }

                Write-Host $response

                $Reader.Dispose()
                $Writer.Dispose()
                $Stream.Dispose()
                $Sock.Close()
            }
           }
}

        $AlivePorts = @()
        
        if ($Scan){
            $IpAddr = Get-IpRange -Target $Scan
            $AlivePorts += Async-Runspaces -Target $IpAddr -Option "PortScan"
            return
        }
        
        if ($FullAuto){
            $IpAddr = Get-IpRange -Target $FullAuto
            $AlivePorts += Async-Runspaces -Target $IpAddr -Option "PortScan"
            Start-Sleep -Seconds 3
            Send-Packets -AlivePorts $AlivePorts
            return
        }
}
