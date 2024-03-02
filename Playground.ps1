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
                        exit
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
                    exit
                }
            }
            # Remember: Only returns an IP list, not active hosts.
            return $Computers
        }
}



function Async-TCP-Scan {
        [CmdletBinding(ConfirmImpact = 'None')]
        Param(
            [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $Target
        )     
        $Threads = 50
        $Timeout = 300
        $Ports = @(554, 8554, 5554)
        $AlivePorts = @()

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
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
                        return "$Target`:$Port" 
                    }
                }
                catch {
                    #Errorhandling Catch
                    $tcpClient.Close()
                    return "Unable to connect"
                }
            }
            else {
                #Port Closed
                $tcpClient.Close()
                return "Unable to connect"
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

        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
                if ($runspace.Handle.IsCompleted) {
                    
                    $runspace.Completed = $true
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                    $runspace.Runspace.Dispose()
                    $runspace.Handle.AsyncWaitHandle.Close()

                    if ($result -eq "Unable to connect"){
                        continue
                    }
                    else {
                        Write-Host -ForegroundColor Green "$result"
                        $ReturnedPorts += $result
                    }
                }
            }

            Start-Sleep -Milliseconds 100
        } while ($runspaces | Where-Object { -not $_.Completed })

        # Clean up
        $runspacePool.Close()
        $runspacePool.Dispose()
        return $ReturnedPorts
}

$AlivePorts = @()
$IpAddr = Get-IpRange -Target 192.168.0.210/28
$OpenPorts += Async-TCP-Scan -Target $IpAddr

#$OpenPorts
