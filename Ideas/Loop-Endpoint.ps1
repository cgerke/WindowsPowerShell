$Endpoints = "COMPUTERNAME"
foreach ($Endpoint in $Endpoints) {
  If (Test-Connection -Computername "$Endpoint" -Buffersize 16 -Count 1 -Ea 0 -Quiet) {
    "$Endpoint" + " :ONLINE"
    If (Test-Path -Path "\\$Endpoint\c$\Users"){
      Get-ChildItem "\\$Endpoint\c$\Users\" | Select-Object FullName,LastWriteTime | sort-object -property Lastwritetime -descending
      $users = Get-ChildItem (Join-Path -Path "\\$Endpoint\c$" -ChildPath 'Users') -Exclude 'Public', 'ADMINI~*', 'Administrator', 'defaultuser0'
      if ($null -ne $users) {
          foreach ($user in $users) {
            If (Test-Path -Path "\\$Endpoint\c$\Users\$user"){
              Get-ChildItem "\\$Endpoint\c$\Users\$user\" | Select-Object FullName,LastWriteTime | sort-object -property Lastwritetime -descending
            }
          }
      }
    }
  }
}