exit

#Generate high cpu
$x = 1; foreach ($n in 1..2147483647) {$x = $x * $n};

<#
.SYNOPSIS
   Creates firewall rules for Teams.
.DESCRIPTION
   (c) Microsoft Corporation 2018. All rights reserved. Script provided as-is without any warranty of any kind. Use it freely at your own risks.
   Must be run with elevated permissions. Can be run as a GPO Computer Startup script, or as a Scheduled Task with elevated permissions.
   The script will create a new inbound firewall rule for each user folder found in c:\users.
   Requires PowerShell 3.0.
#>

#Requires -Version 3

# APPDATA LOOP
$users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public', 'ADMINI~*', 'Administrator'
if ($null -ne $users) {
    foreach ($user in $users) {
        $progPath = Join-Path -Path $user.FullName -ChildPath "AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
        if (Test-Path $progPath) {
                "WT settings for user $($user.Name) $progPath"
        }
        Clear-Variable progPath
    }
}

# Profile loop
$Exclusions = "administrator","defaultuser0","all users","default user","default", "localservice","networkservice","public","myserviceaccount"
$LastUsed = Get-WMIObject -Class Win32_UserProfile -Filter "special=False AND loaded=False" | Select-Object LocalPath,@{Name="LastUsed";Expression={$_.ConvertToDateTime($_.LastUseTime)}} | Where-Object {$_.LastUseTime -lt $(Get-Date).AddDays(60)}

foreach ( $Profile in $LastUsed ) {

    If ( $Exclusions -notcontains $Profile.LocalPath.Substring($Profile.LocalPath.lastindexofany("\") + 1, $Profile.LocalPath.Length - ($Profile.LocalPath.lastindexofany("\") + 1)) ) {
        "{0} ..attempting deletion." -f $Profile.LocalPath
        Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq $Profile.LocalPath } | Remove-CimInstance
    }
}

# Profile loop via registry
$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
$ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
    Where-Object {$_.PSChildName -match $PatternSID} |
    Select-Object  @{name="SID";expression={$_.PSChildName}},
        @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}},
        @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}

Foreach ($UserProfile in $ProfileList) {
    # Load User ntuser.dat if it's not already loaded
    if ($UserProfile.Username -notmatch '^defaultuser0$|^.*administrator$') {
        $UserProfile.Username
        $UserProfile.SID
    }
}

    #Firewall example
    $users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public', 'ADMINI~*', 'Administrator', 'defaultuser0', 'mdt-build'
if ($null -ne $users) {
    foreach ($user in $users) {
        $progPath = Join-Path -Path $user.FullName -ChildPath "AppData\Local\Microsoft\Teams\Current\Teams.exe"
        if (Test-Path $progPath) {
            if (-not (Get-NetFirewallApplicationFilter -Program $progPath -ErrorAction SilentlyContinue)) {
                $ruleName = "Teams.exe for user $($user.Name)"
                "UDP", "TCP" | ForEach-Object { New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Profile Domain -Program $progPath -Action Allow -Protocol $_ }
                Clear-Variable ruleName
            }
        }
        Clear-Variable progPath
    }
}

function Set-Repository {
  Import-Module PowerShellGet
  $PsRepoPath = (Resolve-Path "C:\temp").ProviderPath
  $PsRepo = @{
    Name               = 'MyRepo'
    SourceLocation     = $PsRepoPath
    PublishLocation    = $PsRepoPath
    InstallationPolicy = 'Trusted'
  }
  Register-PSRepository @PsRepo
  Get-PSRepository
  Find-Module -Repository 'MyRepo' -Verbose
}

${function:~} = { Set-Location ~ }
${function:Get-Fun} = { Get-ChildItem function:\ | select-String "-" | ForEach-Object { Get-Help $_ } | Format-Table -Property Name, Synopsis }
${function:Reload-Powershell} = { & $profile }
${function:Set-ParentLocation} = { Set-Location .. }; Set-Alias ".." Set-ParentLocation

function Restart-Powershell {
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

function Get-PowershellAs {
    <#
    .SYNOPSIS
    Run a powershell process as a specified user or as System NT
    .DESCRIPTION
    Run a powershell process as a specified user, a specific user elevated, or SYSTEM NT.
    .EXAMPLE
    Get-PowershellAs -User username
    .EXAMPLE
    Get-PowershellAs -User username -Elevated
    .EXAMPLE
    Get-PowershellAs -User username -System
    .PARAMETER User
    Mandatory user name to "Run as"
    .PARAMETER System
    Optional parameter to run as System NT. Requires PSEXEC
    .PARAMETER Elevated
    Optional parameter to run elevated (UAC).
    #>
    param (
        [Parameter(Mandatory=$false)]
        [string]$User=$Default.Username,
        [Parameter(Mandatory=$false)]
        [Switch]$System,
        [Parameter(Mandatory=$false)]
        [Switch]$Elevated
    )

    # User domain context
    $Domain = switch ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
        true { (Get-WmiObject Win32_ComputerSystem).Domain } default { (Get-WmiObject Win32_ComputerSystem).Name }
    }

    # Eventually remove this, debugging only.
    if (-not($PSBoundParameters.ContainsKey('User')) -and $User) {
        Write-Host "Using default."
    }

    if($System){
        $cwd = Get-Location
        Start-Process psexec -ArgumentList "-accepteula -nobanner -w ""$cwd"" -i -s powershell -ExecutionPolicy Bypass" -WindowStyle Hidden -Verb runAs
    } else {
        $arglist = "Start-Process powershell -ArgumentList '-NoLogo -ExecutionPolicy Unrestricted'"
        if($Elevated){
            $arglist = $arglist + " -Verb runAs"
        }
        if($User){
            Start-Process powershell -Credential "$Domain\$User" -ArgumentList $arglist
        }
    }

}

<# $File = "C:\Users\$env:UserName\AppData\Roaming\Jabra Direct\Devices.txt"
If ( Test-Path -Path $File ){
    $Hash = @{}
    [System.IO.File]::ReadLines($File) | ForEach-Object {
        If ( $_ | Select-String "Product Name:"){
            $k = $_.split(':')
        }
        If ( $_ | Select-String "Serial Number:"){
            $v = $_.split(':')
            $Hash = $Hash + @{$k[1] = $v[1] }
        }
    }

    $Hash
} #>

<# . source
But research the best way to use "preferences" and debug
workflows.
#>
<# $PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
Push-Location "$PSRoot\WindowsPowerShell"
"preferences","debug" |
  Where-Object {Test-Path "Microsoft.PowerShell_$_.ps1"} |
  ForEach-Object -process {
    Invoke-Expression ". .\Microsoft.PowerShell_$_.ps1"
}
 #>
<# #consuming json
$json = Join-Path -Path $PSDirectory -ChildPath "Microsoft.PowerShell_options.json"
if ( Test-Path -path $json ) {
    $Defaults = Get-Content $json | ConvertFrom-Json
    #$JsonObject.Defaults[0]
    #$Defaults.AdminAccount[0].Username
} #>

<# Clean up hard drive space (profiles)
$Exclusions = "administrator","defaultuser0", "all users","default user","default", "localservice","networkservice","public","myserviceaccount"
$LastUsed = Get-WMIObject -Class Win32_UserProfile -Filter "special=False AND loaded=False" | Select-Object LocalPath,@{Name="LastUsed";Expression={$_.ConvertToDateTime($_.LastUseTime)}} | Where-Object {$_.LastUseTime -lt $(Get-Date).AddDays(30)}

    foreach ( $Profile in $LastUsed ) {

        If ( $Exclusions -notcontains $Profile.LocalPath.Substring($Profile.LocalPath.lastindexofany("\") + 1, $Profile.LocalPath.Length - ($Profile.LocalPath.lastindexofany("\") + 1)) ) {
            "{0} ..attempting deletion." -f $Profile.LocalPath
            Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath -eq $Profile.LocalPath } | Remove-CimInstance
        }

    }
#>

# Repair the store
Get-AppXPackage *WindowsStore* -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
Get-Appxpackage –Allusers
Microsoft.MPEG2VideoExtension_1.0.22661.0_x64__8wekyb3d8bbwe
Add-AppxPackage -register "C:\Program Files\WindowsApps\Microsoft.MPEG2VideoExtension_1.0.22661.0_x64__8wekyb3d8bbwe" –DisableDevelopmentMode
Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}

#WOL
$Mac = ""
$MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_"}
[Byte[]] $MagicPacket = (,0xFF * 6) + ($MacByteArray  * 16)
$UdpClient = New-Object System.Net.Sockets.UdpClient
$UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
$UdpClient.Send($MagicPacket,$MagicPacket.Length)
$UdpClient.Close()


# WinPE
copype x86 C:\WinPE_x86_PS
Dism /Mount-Image /ImageFile:"C:\WinPE_x86_PS\media\sources\boot.wim" /Index:1 /MountDir:"C:\WinPE_x86_PS\mount"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\WinPE-WMI.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\en-us\WinPE-WMI_en-us.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\WinPE-NetFX.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\en-us\WinPE-NetFX_en-us.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\WinPE-Scripting.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\en-us\WinPE-Scripting_en-us.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\WinPE-PowerShell.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\en-us\WinPE-PowerShell_en-us.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\WinPE-StorageWMI.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\en-us\WinPE-StorageWMI_en-us.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\WinPE-DismCmdlets.cab"
Dism /Add-Package /Image:"C:\WinPE_x86_PS\mount" /PackagePath:"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs\en-us\WinPE-DismCmdlets_en-us.cab"
Dism /Unmount-Image /MountDir:C:\WinPE_x86_PS\mount /Commit
xcopy c:\WinPE_x86_PS\media\*.* /s /e /f d:\

copype amd64 C:\WinPE_amd64_PS

# Re-profile
#1. Rename C:\Users\XXXXXXX.old
#2. Rename HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\ProfileList\S-1-5-21-xxxxxxxxxxxx.old
#3. Rename HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Current Version\ProfileGuid\{xxxxxxxxx}\S-1-5-21-xxxxxxxxxxxx.old
#4. Reboot

# plan b
# /node:HOSTNAME process call create "msiexec /i C:\temp\installer.msi /qn"
# /node:HOSTNAME process call create "MsiExec.exe /X{A728AD51-72D5-4992-8367-91E7CF686604}"
# /node:HOSTNAME process call create "'C:\Program Files (x86)\xxxx\xxxx.exe' --something --somethingelse"
# /node:HOSTNAME process list
# /node:HOSTNAME process call create "wevtutil epl System C:\temp\system.evtx"

# do not remember last logged in user
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnDisplayName /f"
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnSAMUser /f"
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnUser /f"
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnUserSID /f"

# All BIOS
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings"

# Thunderbolt
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings where InstanceName='ACPI\\PNP0C14\\0_73'"
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings where InstanceName='ACPI\\PNP0C14\\0_74'"
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings where InstanceName='ACPI\\PNP0C14\\0_75'"

# Disable Outlook GPU acceleration
REG ADD "HKCU\Software\Microsoft\Office\15.0\Common\Graphics" /V DisableHardwareAcceleration /T REG_DWORD /D 1 /F
REG ADD "HKCU\Software\Microsoft\Office\16.0\Common\Graphics" /V DisableHardwareAcceleration /T REG_DWORD /D 1 /F
REG ADD "HKCU\Software\Microsoft\Office\18.0\Common\Graphics" /V DisableHardwareAcceleration /T REG_DWORD /D 1 /F

# Todo Calendar
REG ADD "HKCU\Software\Microsoft\office\15.0\Outlook\Preferences" /V HideMailFavorites /T REG_DWORD /D 1 /F
REG ADD "HKCU\Software\Microsoft\office\16.0\Outlook\Preferences" /V HideMailFavorites /T REG_DWORD /D 1 /F
REG ADD "HKCU\Software\Microsoft\office\18.0\Outlook\Preferences" /V HideMailFavorites /T REG_DWORD /D 1 /F

# Todo Calendar
REG ADD "HKCU\Software\Microsoft\office\15.0\Outlook\Preferences" /V PinMail /T REG_DWORD /D 2 /F
REG ADD "HKCU\Software\Microsoft\office\16.0\Outlook\Preferences" /V PinMail /T REG_DWORD /D 2 /F
REG ADD "HKCU\Software\Microsoft\office\18.0\Outlook\Preferences" /V PinMail /T REG_DWORD /D 2 /F

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

    function Get-InstalledApplications() {
        [cmdletbinding(DefaultParameterSetName = 'GlobalAndAllUsers')]

        Param (
            [Parameter(ParameterSetName="Global")]
            [switch]$Global,
            [Parameter(ParameterSetName="GlobalAndCurrentUser")]
            [switch]$GlobalAndCurrentUser,
            [Parameter(ParameterSetName="GlobalAndAllUsers")]
            [switch]$GlobalAndAllUsers,
            [Parameter(ParameterSetName="CurrentUser")]
            [switch]$CurrentUser,
            [Parameter(ParameterSetName="AllUsers")]
            [switch]$AllUsers
        )

        # Excplicitly set default param to True if used to allow conditionals to work
        if ($PSCmdlet.ParameterSetName -eq "GlobalAndAllUsers") {
            $GlobalAndAllUsers = $true
        }

        # Check if running with Administrative privileges if required
        if ($GlobalAndAllUsers -or $AllUsers) {
            $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if ($RunningAsAdmin -eq $false) {
                Write-Error "Finding all user applications requires administrative privileges"
                break
            }
        }

        # Empty array to store applications
        $Apps = @()
        $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

        # Retreive globally insatlled applications
        if ($Global -or $GlobalAndAllUsers -or $GlobalAndCurrentUser) {
            Write-Host "Processing global hive"
            $Apps += Get-ItemProperty "HKLM:\$32BitPath"
            $Apps += Get-ItemProperty "HKLM:\$64BitPath"
        }

        if ($CurrentUser -or $GlobalAndCurrentUser) {
            Write-Host "Processing current user hive"
            $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$32BitPath"
            $Apps += Get-ItemProperty "Registry::\HKEY_CURRENT_USER\$64BitPath"
        }

        if ($AllUsers -or $GlobalAndAllUsers) {
            Write-Host "Collecting hive data for all users"
            $AllProfiles = Get-CimInstance Win32_UserProfile | Select LocalPath, SID, Loaded, Special | Where {$_.SID -like "S-1-5-21-*"}
            $MountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $true}
            $UnmountedProfiles = $AllProfiles | Where-Object {$_.Loaded -eq $false}

            Write-Host "Processing mounted hives"
            $MountedProfiles | % {
                $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
                $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
            }

            Write-Host "Processing unmounted hives"
            $UnmountedProfiles | % {

                $Hive = "$($_.LocalPath)\NTUSER.DAT"
                Write-Host " -> Mounting hive at $Hive"

                if (Test-Path $Hive) {

                    REG LOAD HKU\temp $Hive

                    $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
                    $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"

                    # Run manual GC to allow hive to be unmounted
                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()

                    REG UNLOAD HKU\temp

                } else {
                    Write-Warning "Unable to access registry hive at $Hive"
                }
            }
        }

        Write-Output $Apps
    }

    Get-InstalledApplications | Select-Object DisplayName, InstallLocation


    function Install-GoogleEarth {
        <#
      .SYNOPSIS
        Installs GoogleEarthPro on a remote endpoint.
      .DESCRIPTION
        Using wmi to install GoogleEarthPro.
      .EXAMPLE
        Install-GoogleEarthPro "HOSTNAME"
      #>
      Param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $computer
      )

        $installpath="temp\googleearthprowin-7.3.2-x64_automate.cmd"

        If (Test-Path \\$computer\c$\$installpath){
          $WinProc=[wmiclass]"Win32_ProcessStartup"
          $WinProc.Properties['ShowWindow'].value=$False
          ([wmiclass]"\\$computer\root\cimv2:win32_Process").create('cmd.exe /c C:\temp\googleearthprowin-7.3.2-x64_automate.cmd')
        } Else {
          Write-Host 'Install path googleearthprowin-7.3.2-x64_automate.cmd on the remote device is not available.'
        }
      }

      $date = (Get-Date).ToString("yyyymmdd-hhmmss")
      $file = "C:\temp\myfile.txt"
      If (Test-Path -Path $file){
        "zip backup to $file.$date"
        try {
          Compress-Archive -LiteralPath "$file" -DestinationPath "$file.zip"
        } catch {
          $_.Exception.GetType().FullName
        }
      } Else {
        "Not here"
      }

      $file = "C:\temp\myfile.txt"
      Get-ItemProperty $file | Get-Member


      $FakeArray = @("johndoe", "admin-johndoe")
      $MaxPasswordAge=(Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
      Foreach ($AdminAccount in $FakeArray) {
        $PasswordLastSet=""
        $PasswordExpires=""
        If ($AdminAccount.StartsWith("admin-")) {
          $ADUser = $AdminAccount.split('-')[-1]
          $Mail = (Get-ADUser "$ADUser" -Properties mail).mail
          $ADUser = $AdminAccount
          $PasswordLastSet=(Get-ADUser $ADUser -Properties PasswordLastSet).PasswordLastSet
          $PasswordExpires = $PasswordLastSet.AddDays($MaxPasswordAge)
        }
        Else {
          $ADUser = $AdminAccount
          $Mail = (Get-ADUser "$ADUser" -Properties mail).mail
          $PasswordLastSet=(Get-ADUser $ADUser -Properties PasswordLastSet).PasswordLastSet
          $PasswordExpires = $PasswordLastSet.AddDays($MaxPasswordAge)
        }
        "$ADUser at $Mail password LastSet : $PasswordLastSet due to expire $PasswordExpires"
      }


      function New-Compare {
        <#
        .SYNOPSIS
          Tree comparison.
        .DESCRIPTION
          Compare the contents of two paths.
        .EXAMPLE
          New-Compare -Path C:\temp -Alt C:\temp1
        #>
        Param(
          [Parameter(Position=0,mandatory=$true)]
          [string] $Path,$Alt
        )

          $Ref = Get-ChildItem -Recurse -path "$Path"
          $Diff = Get-ChildItem -Recurse -path "$Alt"
          Compare-Object -ReferenceObject $Ref -DifferenceObject $Diff | ForEach-Object {$_.InputObject.FullName}

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


wmic /node:computer process call create 'tskill chrome'

$Endpoints = "COMPUTERNAME"
foreach ($Endpoint in $Endpoints) {
    If (Test-Connection -Computername "$Endpoint" -Buffersize 16 -Count 1 -Ea 0 -Quiet) {
        "$Endpoint" + " :ONLINE"
        Get-ChildItem "\\$Endpoint\c$\Users\" | Select-Object FullName,LastWriteTime | sort-object -property Lastwritetime -descending
        $users = Get-ChildItem (Join-Path -Path "\\$Endpoint\c$" -ChildPath 'Users') -Exclude 'Public', 'ADMINI~*', 'Administrator', 'defaultuser0', 'mdt-build'
        if ($null -ne $users) {
            foreach ($user in $users) {
                Get-ChildItem "\\$Endpoint\c$\Users\$user\" | Select-Object FullName,LastWriteTime | sort-object -property Lastwritetime -descending
            }
        }
    }
}