Get-WmiObject Win32_PnPSignedDriver |
    Where-Object {$_.devicename -eq 'Intel(R) Ethernet Connection (7) I219-LM'} |
    ForEach-Object {
        if ([Version]$_.Driverversion -ge [Version]'12.17.8.9') {
            Write-Output "Version is Current"
            # return from a function ?
            # return 0
            # exit script with exitcode?
            # exit 0
        }
        else {
            Start-Process -FilePath "\\servername\share\share\Dell\Drivers\Dell 3630\Network Card\setup.exe" -ArgumentList '/s' -Wait -NoNewWindow
        }
    }