function Get-App {
    <#
    .SYNOPSIS
      Wildcard search apps.
    .DESCRIPTION
      Find app GUID with a  wildcard search on a remote machine.
    .EXAMPLE
      Get-App -App "Google" -Computer "HOSTNAME"
    #>
      Param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $app,$computer
      )
      #Get-WmiObject win32_product -ComputerName "$computer" | Where-Object name -Like "*$app*"

      $app
      $computer
      # & wmic /node:"$computer" process call create 'powershell -command "Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Out-File C:\temp\uninstall.txt"'
      # & wmic /node:"$computer" process call create 'powershell -command "Get-ChildItem -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Out-File C:\temp\uninstall.txt"'
      # Get-Content "\\$computer\c$\temp\uninstall.txt"
    }