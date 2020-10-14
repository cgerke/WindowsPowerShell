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

  ### WinRM remoting by default
  ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
  If (Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue)
  {
    $CimSession = New-CimSession -ComputerName $Computer
  }
  Else
  {
    # Use DCOM if WinRM is not available
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

  $CIMcs = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
  $CIMos = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
  $CIMbios = Get-CimInstance -CimSession $CimSession -ClassName Win32_Bios
  $CIMcpu = Get-CimInstance -CimSession $CimSession -ClassName Win32_Processor
  $CIMdisk = Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
  $TotalDiskSpace = [math]::round($CIMdisk.Size / 1GB, 0)
  $FreeDiskSpace = [math]::round($CIMdisk.FreeSpace / 1GB, 0)

  $ComputerCO = [PSCustomObject]@{
    Name = $Computer
    Manufacturer = $CIMcs.Manufacturer
    Model = $CIMcs.Model
    Serial = $CIMbios.SerialNumber
    CPU = $CIMcpu.Name
    TotalDiskSpace = "$TotalDiskSpace GB"
    FreeDiskSpace = "$FreeDiskSpace GB"
    TotalPhysicalMemory = "$([math]::round($CIMos.TotalVisibleMemorySize / 1MB, 0)) GB"
    FreePhysicalMemory = "$([math]::round($CIMos.FreePhysicalMemory/ 1MB, 0)) GB"
    LastBootUpTime = $CIMos.LastBootUpTime
    OperatingSystem = $CIMos.caption
    Build = $Build
    InstallDate = $CIMos.InstallDate
  }

  $ComputerCO

  # Updates
  Get-CimInstance -CimSession $CimSession -ClassName Win32_QuickFixEngineering |
  Select-Object Description, HotFixID, InstalledOn |
  Sort-Object -Descending -Property InstalledOn |
  Format-Table
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
        $CimSession = New-CimSession -ComputerName $i
      }
      Else
      {
        # Use DCOM if WinRM is not available
        $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
        $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
      }

      $CIMos = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
      $ComputerCO = [PSCustomObject]@{
        Name = $i
        LastBootUpTime = (Get-Date) - $CIMos.LastBootUpTime  | Format-TimeSpan
      }
      return $ComputerCO
    }
  }

}