function Uninstall-App {
    <#
  .SYNOPSIS
    Uninstall an app on a remote device.
  .DESCRIPTION
    Using wmi to uninstall an app using its GUID.
  .EXAMPLE
    Uninstall-App -App "{AC76BA86-7AD7-1033-7B44-AC0F074E4100}" -Computer "HOSTNAME"
  #>
  Param(
    [Parameter(Position=0,mandatory=$true)]
      [string] $app,
      [Parameter(Position=0,mandatory=$true)]
      [string] $computer
  )
      $startup=[wmiclass]"Win32_ProcessStartup"
      $startup.Properties['ShowWindow'].value=$False

      $app
      $computer
      #([wmiclass]"\\$computer\root\cimv2:win32_Process").create("msiexec.exe /x $app /qn",'C:\',$startup)

      #(Get-WmiObject -Computer $computer -Class Win32_Product -Filter "Name='$app'").Uninstall()
      #Invoke-WmiMethod -Path "Win32_Product.Name='Google Chrome'" -Computer 'HOSTNAME' -Name Uninstall
  }

