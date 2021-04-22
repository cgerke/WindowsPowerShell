function New-BackupUserProfile
{
  <#
    .SYNOPSIS
      Basic user profile backup
    .DESCRIPTION
      Backup "known" user profile data
    .EXAMPLE
      New-BackupUserProfile -Computer $hostname -User
    #>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string[]] $Computer,
    [Parameter(Position = 1, mandatory = $true)]
    [string[]] $User
  )

  $TimeString = Get-Date -format "yyyyMMdd-Hmmss"
  $BackupPath = "C:\temp\$($Computer)_$($TimeString)"
  $LogFileName = "$($Computer)_$($TimeString)"
  $LogFile = "$BackupPath\$LogFileName.log"

  New-Item -Itemtype Directory -Force -Path $BackupPath
  New-Item -Itemtype File -Force -Path $LogFile

  If (Test-Connection -Computername $Computer -Buffersize 16 -Count 1 -Ea 0 -Quiet)
  {
    "$Computer - Online!" | Tee-Object -FilePath "$LogFile" -Append
  } Else {
    "$Computer - Offline!" | Tee-Object -FilePath "$LogFile" -Append
  }

  $DesktopSource = Get-ChildItem "\\$Computer\C$\Users\$User\Downloads" -Directory -Recurse
  $DesktopDestination = "$BackupPath\Downloads\"
  New-Item -Itemtype Directory -Force -Path $DesktopDestination

  Copy-Item "$DesktopSource" -Destination $DesktopDestination -force


}