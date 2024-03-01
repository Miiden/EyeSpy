function Get-IpRange {
        Param(
            [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $Targets
        )
                
        process {
            $Computers = @()
            foreach ($subnet in $Targets) {
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
                        continue
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
                    $imax = [convert]::ToInt32(('1' * $HostBits), 2) - 1 # -2 to exclude network and broadcast addresses
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
            return $Computers
        }
    }


    Get-IpRange -Targets 192.168.0.0/29
