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

function New-WinPE {
  <#
    .SYNOPSIS
      Basic WinPE creation.
    .DESCRIPTION
      Setup a basic WinPE environment including powershell and tools.
    .EXAMPLE
      New-WinPE -Architecture amd64
    #>
  param (
        [ValidateSet("amd64","x86")]
        [String]
        $Architecture
    )

  # Configure basic
  $peCache = "C:\WinPE_${Architecture}_PS"
  $env = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat"
  cmd.exe /c """$env"" && copype $Architecture $peCache"

  # Customise
  Dism /Unmount-Image /MountDir:"$peCache\mount" /discard
  Dism /Mount-Image /ImageFile:"$peCache\media\sources\boot.wim" /Index:1 /MountDir:"$peCache\mount"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\WinPE-WMI.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\en-us\WinPE-WMI_en-us.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\WinPE-NetFX.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\en-us\WinPE-NetFX_en-us.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\WinPE-Scripting.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\en-us\WinPE-Scripting_en-us.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\WinPE-PowerShell.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\en-us\WinPE-PowerShell_en-us.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\WinPE-StorageWMI.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\en-us\WinPE-StorageWMI_en-us.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\WinPE-DismCmdlets.cab"
  Dism /Add-Package /Image:"$peCache\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\${Architecture}\WinPE_OCs\en-us\WinPE-DismCmdlets_en-us.cab"

  # Permissions hack
  $tmpDir = "C:\winpe_temp"
  New-Item -ItemType Directory -Path "$tmpDir"
  Get-Acl "$tmpDir" | Set-Acl "$peCache\mount\Windows\System32\startnet.cmd"
  Remove-Item -Path $tmpDir -Force

  # High performance profile
  Add-Content -Path "$peCache\mount\Windows\System32\startnet.cmd" -Value 'powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'

  # Startnet PowerShell
  Add-Content -Path "$peCache\mount\Windows\System32\startnet.cmd" -Value 'X:\Windows\system32\WindowsPowerShell\v1.0\powershell -nologo -executionpolicy bypass'

  #$profile
  Add-Content -Path "$peCache\mount\Windows\System32\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -Value 'Set-Location X:\Windows\system32'
  Add-Content -Path "$peCache\mount\Windows\System32\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -Value 'hostname'
  Add-Content -Path "$peCache\mount\Windows\System32\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -Value 'Get-Disk | Where-Object {$_.bustype -ne "USB"}'
  Add-Content -Path "$peCache\mount\Windows\System32\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -Value 'dir *.ps1'

  # Utilities
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'Get-Disk | Where-Object {$_.bustype -ne "USB"} | Foreach-Object {'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value '$command = @"'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'list disk'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'list volume'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'select disk $($_.Number)'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'clean all'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'create partition primary'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'select parition 1'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'active'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'format FS=NTFS quick label=CLEANED'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'list disk'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'list volume'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value 'exit'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value '"@'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value '$command | diskpart'
  Add-Content -Path "$peCache\mount\Windows\System32\erase.ps1" -Value '}'

  Dism /Unmount-Image /MountDir:$peCache\mount /Commit

  explorer "$peCache\media"

  # New-Item -ItemType Directory -Path "$peCache\iso"
  # MakeWinPEMedia.cmd /iso "$peCache" "$peCache\iso\WinPE.iso"
}