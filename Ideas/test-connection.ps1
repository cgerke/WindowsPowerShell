If (Test-Connection -Computername $Computer -Buffersize 16 -Count 1 -Ea 0 -Quiet)
  {
    "$Computer - Online!" | Tee-Object -FilePath "$LogFile" -Append
  } Else {
    "$Computer - Offline!" | Tee-Object -FilePath "$LogFile" -Append
  }