Function MiiStream {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param(
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$Path,
		[Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$User = "admin",
		[Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String]$Pass = "admin"
	)

	function StartStream {
		[CmdletBinding(ConfirmImpact = 'None')]
        Param(
            [Parameter(ValueFromPipeline, Position = 0)]
            [string[]] $Path,
			[Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $User,
			[Parameter(Mandatory, ValueFromPipeline, Position = 0)]
            [string[]] $Pass
        ) 

		$Creds = "$User`:$Pass"
				
		start-process powershell -ArgumentList '-noexit -command "C:\Users\cctv\Desktop\MediaMTX\mediamtx.exe"'	
		Start-Sleep -Seconds 1
		if ($Path){
			#ffmpeg -re -stream_loop -1 -i file.ts -c copy -f rtsp rtsp://myuser:mypass@localhost:8554/mystream
			start-process powershell -ArgumentList "-noexit -command ""C:\ffmpeg\bin\ffmpeg.exe -re -stream_loop -1 -i ""C:\CCTV-Stream\videostream.mp4"" -c copy -f rtsp ""rtsp://${Creds}@localhost:8554/$Path"""""	
		} else {
			start-process powershell -ArgumentList "-noexit -command ""C:\ffmpeg\bin\ffmpeg.exe -re -stream_loop -1 -i ""C:\CCTV-Stream\videostream.mp4"" -c copy -f rtsp ""rtsp://${Creds}@localhost:8554/"""""	
			}
	}

	if ($Path) {
		StartStream -Path $Path -User $User -Pass $Pass
		
	} else {
		StartStream -User $User -Pass $Pass
	}

}
#MiiStream
