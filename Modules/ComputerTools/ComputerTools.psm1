function Get-Computer
{
  <#
    .SYNOPSIS
      System information
    .DESCRIPTION
      Retrieve system information from a remote computer.
    .EXAMPLE
      Get-Computer -Computer $hostname
    #>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Computer
  )

  if (-not (Test-Connection -Quiet -ComputerName "$Computer" -Count 2))
  {
    Write-Information "$Computer appears to be offline" -InformationAction Continue
  } else {
    ### WinRM remoting by default
    ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
    If (Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue)
    {
      Write-Information "WinRM available" -InformationAction Continue
      $CimSession = New-CimSession -ComputerName $Computer
    }
    Else
    {
      Write-Information "Using DCOM as WinRM is not available" -InformationAction Continue
      $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
      $CimSession = New-CimSession -ComputerName $Computer -SessionOption $CimSessionOption
    }

    switch ((Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem).Version)
    {
      10.0.18362 { $Build = 1903 }
      10.0.17763 { $Build = 1809 }
      10.0.17134 { $Build = 1803 }
      10.0.16299 { $Build = 1709 }
      default { $Build = "N/A" }
    }

    $CIMcomsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
    $CIMopsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
    $CIMbios = Get-CimInstance -CimSession $CimSession -ClassName Win32_Bios
    $CIMcpu = Get-CimInstance -CimSession $CimSession -ClassName Win32_Processor
    $CIMdisk = Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $TotalDiskSpace = [math]::round($CIMdisk.Size / 1GB, 0)
    $FreeDiskSpace = [math]::round($CIMdisk.FreeSpace / 1GB, 0)

    $ComputerObject = [PSCustomObject]@{
      Name = $Computer
      Manufacturer = $CIMcomsys.Manufacturer
      Model = $CIMcomsys.Model
      Serial = $CIMbios.SerialNumber
      CPU = $CIMcpu.Name
      TotalDiskSpace = "$TotalDiskSpace GB"
      FreeDiskSpace = "$FreeDiskSpace GB"
      TotalPhysicalMemory = "$([math]::round($CIMopsys.TotalVisibleMemorySize / 1MB, 0)) GB"
      FreePhysicalMemory = "$([math]::round($CIMopsys.FreePhysicalMemory/ 1MB, 0)) GB"
      LastBootUpTime = $CIMopsys.LastBootUpTime
      OperatingSystem = $CIMopsys.caption
      Build = $Build
      InstallDate = $CIMopsys.InstallDate
    }

    $ComputerObject

    # Updates
    Get-CimInstance -CimSession $CimSession -ClassName Win32_QuickFixEngineering |
    Select-Object Description, HotFixID, InstalledOn |
    Sort-Object -Descending -Property InstalledOn |
    Format-Table
  }
}

function Format-TimeSpan {
  process {
    "{0:00} days {1:00} hours {2:00} minutes {3:00} seconds" -f $_.Days,$_.Hours,$_.Minutes,$_.Seconds
  }
}

function Get-ComputerUptime
{
  <#
    .SYNOPSIS
      System uptime
    .DESCRIPTION
      Retrieve system uptime from a remote computer.
    .EXAMPLE
      Get-ComputerUptime -Computer $hostname
    #>
  Param(
    [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
    [string[]] $Computer
  )

  process {
    foreach ( $i in $Computer ) {
      ### WinRM remoting by default
      ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
      If (Test-WSMan -ComputerName $i -ErrorAction SilentlyContinue)
      {
        Write-Information "WinRM available."
        $CimSession = New-CimSession -ComputerName $i
      }
      Else
      {
        # Use DCOM if WinRM is not available
        $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
        $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
      }

      $CIMopsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
      $ComputerObject = [PSCustomObject]@{
        Name = $i
        LastBootUpTime = $CIMopsys.LastBootUpTime
        LastBootUpTimeRelative = (Get-Date) - $CIMopsys.LastBootUpTime  | Format-TimeSpan
      }
      return $ComputerObject
    }
  }

}

Function Get-ToshibaWarranty
{
  <#
    .SYNOPSIS
      Toshiba computer warranty.
    .DESCRIPTION
      Get warranty information for Toshiba computers via a json response.
    .EXAMPLE
      Get-ToshibaWarranty -Serial $Serial
    #>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Serial
  )
  $web = New-Object Net.WebClient
  $url = "http://support.toshiba.com/support/warrantyResults?sno="
  $url = $url + $Serial
  $content = $web.DownloadString($url) | Out-String | ConvertFrom-Json
  $warranty = $content.commonBean
  $warranty
}