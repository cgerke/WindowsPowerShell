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
      10.0.19041 { $Build = 2004 }
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
    $CIMmac = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$null -ne $_.MACAddress} | Select-Object Description, MACAddress
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

    $CIMmac

    # Updates
    Get-CimInstance -CimSession $CimSession -ClassName Win32_QuickFixEngineering |
    Select-Object Description, HotFixID, InstalledOn |
    Sort-Object -Descending -Property InstalledOn |
    Format-Table
  }
}