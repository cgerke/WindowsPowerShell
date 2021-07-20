$Exclusions = "administrator","defaultuser0", "all users","default user","default", "localservice","networkservice","public","myserviceaccount"
$LastUsed = Get-WMIObject -Class Win32_UserProfile -Filter "special=False AND loaded=False" | Select-Object LocalPath,@{Name="LastUsed";Expression={$_.ConvertToDateTime($_.LastUseTime)}} | Where-Object {$_.LastUseTime -lt $(Get-Date).AddDays(30)}

    foreach ( $Profile in $LastUsed ) {

        If ( $Exclusions -notcontains $Profile.LocalPath.Substring($Profile.LocalPath.lastindexofany("\") + 1, $Profile.LocalPath.Length - ($Profile.LocalPath.lastindexofany("\") + 1)) ) {
            "{0} ..attempting deletion." -f $Profile.LocalPath
            Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq $Profile.LocalPath } | Remove-CimInstance
        }

    }