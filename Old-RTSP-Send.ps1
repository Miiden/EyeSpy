function RTSPscan()
{
    param(
        [int] $Port = 8554,
        $IP = "192.168.0.219",
        [int] $TimeoutMilliseconds = 500  # Timeout for waiting for response (in milliseconds)
    )

    $Encoding = [System.Text.Encoding]::ASCII
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
        Write-Host "Failed to connect to $IP`:$Port: $_"
        return [pscustomobject]@{ Address = $IP; Port = $port; Open = $open }
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
            while ($true) {
                $line = $Reader.ReadLine()
                if ($line -eq $null) { break }
                $response += $line + $CRLF
            }
        } 
        catch {
            # Catching the exception without taking any action
        }

        Write-Host $response

        $Reader.Dispose()
        $Writer.Dispose()
        $Stream.Dispose()
        $Sock.Close()
    }

    return [pscustomobject]@{ Address = $IP; Port = $port; Open = $open }
}

RTSPscan
