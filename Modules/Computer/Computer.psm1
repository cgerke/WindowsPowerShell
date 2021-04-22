function Format-TimeSpan {
  process {
    "{0:00} days {1:00} hours {2:00} minutes {3:00} seconds" -f $_.Days,$_.Hours,$_.Minutes,$_.Seconds
  }
}

Function Write-Log {
  Param ([String]$LogString)
  If (Test-Path $LogFile){
      If ((Get-Item $LogFile).Length -Gt 2mb){
          Rename-Item $LogFile ($LogFile + ".Bak") -Force
          New-Item -Itemtype File -Force -Path $LogFile
      }
  }
  (Get-Date -UFormat "%Y-%M-%D").Tostring() + " " + $LogString | Out-File -Filepath $LogFile -Append
}