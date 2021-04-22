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