
<# Preferences #>
$DebugPreference = "SilentlyContinue" # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" # Support TLS

<# Globals #>
$PSDirectory = (Get-Item $profile).DirectoryName
# $PSDirectory = Join-Path $env:USERPROFILE "\Documents\WindowsPowerShell" # Account for folder redirection

<# Alias / 1-Liner #>
${function:~} = { Set-Location ~ }
${function:Get-Fun} = { Get-ChildItem function:\ | select-String "-" | ForEach-Object { Get-Help $_ } | Format-Table -Property Name, Synopsis }
${function:Get-Sudo} = { Start-Process powershell -ArgumentList "-executionpolicy bypass" -Verb RunAs }
${function:Reload-Powershell} = { & $profile }
${function:Set-ParentLocation} = { Set-Location .. }; Set-Alias ".." Set-ParentLocation

<# PATH #>
function Set-EnvPath([string] $path ) {
    if ( -not [string]::IsNullOrEmpty($path) ) {
        if ( (Test-Path $path) -and (-not $env:PATH.contains($path)) ) {
            #Write-Host "PATH" $path -ForegroundColor Cyan
            $env:PATH += ';' + "$path"
       }
    }
 }

#region helpers
function Get-Profile {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cgerke/dotfiles/master/Microsoft.PowerShell_profile.ps1" -OutFile "$profile"
}

function Restart-Powershell {
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

 function Test-IsAdmin {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-RegistryValue {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}
#endregion helpers

#region source
Push-Location ($PSDirectory)
"organisation" | Where-Object {Test-Path "Microsoft.PowerShell_$_.ps1"} | ForEach-Object -process {
    Invoke-Expression ". .\Microsoft.PowerShell_$_.ps1"; Write-Host Microsoft.PowerShell_$_.ps1
}
Pop-Location
#endregion source

#region defaults
# Saved state defaults, think about testing in funcs etc
$Defaults = Get-Content (Join-Path -Path $PSDirectory -ChildPath "Microsoft.PowerShell_options.json") | ConvertFrom-Json
#$JsonObject.Defaults[0]
$Defaults.AdminAccount[0].Username
#end region defaults

#region essentials
function Get-Sandbox {
    Start-Process -FilePath powershell.exe -ArgumentList {
        -noprofile
        Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
    } -verb RunAs
}

function Get-Ssh {
    Start-Process -FilePath powershell.exe -ArgumentList {
        -noprofile
        Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*' | Add-WindowsCapability -Online
    } -verb RunAs
}

function Get-Telnet {
    Start-Process -FilePath powershell.exe -ArgumentList {
        -noprofile
        Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
        Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
    } -verb RunAs
}
#end region essentials

#region git
Push-Location (Split-Path -parent $profile)
Get-ChildItem .\bin\ | Where-Object {Test-Path .git*} | ForEach-Object -process {
    If (-Not (Test-Path $_)) { Copy-Item .\bin\$_ $env:USERPROFILE }
}
Pop-Location
#endregion git

<# Support Helpers #>
function Get-ADMemberCSV {
    <#
    .SYNOPSIS
    Export AD group members to CSV.
    .DESCRIPTION
    Export AD group members to CSV.
    .EXAMPLE
    Get-ADMemberCSV -GroupObj MyAdGroup
    .PARAMETER GroupObj
    The group name. Just one.
    #>
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$GroupObj
    )

    try {
        Get-ADGroupMember "$GroupObj" | Export-CSV -path "c:\temp\$GroupObj.csv"
        explorer c:\temp
    } catch {
        return $false
    }
}

function Get-FilePathLength {
    <#
    .SYNOPSIS
    Count file path characters.
    .DESCRIPTION
    Help identifying 260 chars.
    .EXAMPLE
    Get-FilePathLength -FolderPath C:\temp
    .PARAMETER FolderPath
    The folder path to query. Just one.
    #>
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$FolderPath
    )
    Get-ChildItem -Path $FolderPath -Recurse -Force |
        #Where-Object {$_.FullName.length -ge 248 } |
        Select-Object -Property FullName, @{Name="FullNameLength";Expression={($_.FullName.Length)}} |
        Sort-Object -Property FullNameLength -Descending
}

function Get-Log {
    <#
    .SYNOPSIS
    Captain's log.
    .DESCRIPTION
    A running commentary of interesting events.
    .EXAMPLE
    Get-Log
    #>
    try {
        notepad "$PSDirectory\log.txt"
    } catch {
        return $false
    }
}; Set-Alias qq Get-Log

function Get-LAPS {
    <#
    .SYNOPSIS
    https://technet.microsoft.com/en-us/mt227395.aspx
    .DESCRIPTION
    Query Active Directory for the local administrator password of a ComputerObj.
    .EXAMPLE
    Get-LAPS -ComputerObj mycomputer-1
    .PARAMETER ComputerObj
    The computer name to query. Just one.
    #>
    param (
        [parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]$ComputerObj
    )

    try {
        Get-ADComputer $ComputerObj -Properties ms-Mcs-AdmPwd | Select-Object name, ms-Mcs-AdmPwd
    } catch {
        return $false
    }
}; Set-Alias laps Get-LAPS

function Get-LAPSExpiry{
    <#
    .SYNOPSIS
    https://technet.microsoft.com/en-us/mt227395.aspx
    .DESCRIPTION
    Query Active Directory for the local administrator password expiry date for a ComputerObj.
    .EXAMPLE
    Get-LAPSExpiry -ComputerObj mycomputer-1
    .PARAMETER ComputerObj
    The computer name to query. Just one.
    #>
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$ComputerObj
    )

    $PwdExp = Get-ADComputer $ComputerObj -Properties ms-MCS-AdmPwdExpirationTime
    $([datetime]::FromFileTime([convert]::ToInt64($PwdExp.'ms-MCS-AdmPwdExpirationTime',10)))
}

function Get-MSIProdCode {
    <#
    .SYNOPSIS
        Retrieves a list of all installed software UNINSTALL msi product codes.
    .EXAMPLE
        This example retrieves all installed software UNINSTALL msi product codes.
        Get-MSIProdCode
    .EXAMPLE
        This example retrieves all installed software UNINSTALL msi product codes including 'Office' in the display name.
        Get-MSIProdCode -DisplayName "Office"
    .PARAMETER Name
        The software title you'd like to limit the query to.
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName
    )

    $UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
    foreach ($UninstallKey in $UninstallKeys) {
        if ($PSBoundParameters.ContainsKey('DisplayName')) {
            $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "*$DisplayName*") }
        }
        else {
            $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) }
        }
        $gciParams = @{
            Path        = $UninstallKey
            ErrorAction = 'SilentlyContinue'
        }
        $selectProperties = @(
            @{n = 'GUID'; e = {$_.PSChildName}}, 
            @{n = 'Name'; e = {$_.GetValue('DisplayName')}}
        )
        Get-ChildItem @gciParams | Where-Object $WhereBlock | Select-Object -Property $selectProperties
    }
}

function Get-DotNet {
    $Lookup = @{
        378389 = [version]'4.5'
        378675 = [version]'4.5.1'
        378758 = [version]'4.5.1'
        379893 = [version]'4.5.2'
        393295 = [version]'4.6'
        393297 = [version]'4.6'
        394254 = [version]'4.6.1'
        394271 = [version]'4.6.1'
        394802 = [version]'4.6.2'
        394806 = [version]'4.6.2'
        460798 = [version]'4.7'
        460805 = [version]'4.7'
        461308 = [version]'4.7.1'
        461310 = [version]'4.7.1'
        461808 = [version]'4.7.2'
        461814 = [version]'4.7.2'
    }

    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
        Get-ItemProperty -name Version, Release -EA 0 |
        Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
        Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}}, 
    @{name = "Product"; expression = {$Lookup[$_.Release]}}, 
    Version, Release
}

function Get-PowershellAs {
    <#
    .SYNOPSIS
    Run a powershell process as a specified user or as System NT
    .DESCRIPTION
    Run a powershell process as a specified user, a specific user elevated, or SYSTEM NT.
    .EXAMPLE
    Get-PowershellAs -UserObj myuser
    .EXAMPLE
    Get-PowershellAs -UserObj myuser -ElevatedObj
    .EXAMPLE
    Get-PowershellAs -UserObj myuser -SystemObj
    .PARAMETER UserObj
    Mandatory user name to "Run as"
    .PARAMETER SystemObj
    Optional parameter to run as System NT. Requires PSEXEC
    .PARAMETER ElevatedObj
    Optional parameter to run elevated (UAC).
    #>
    param (
        [Parameter(Mandatory=$false)]
        [string]$UserObj=$Defaults.PowershellAs[0].Username,
        [Parameter(Mandatory=$false)]
        [Switch]$SystemObj,
        [Parameter(Mandatory=$false)]
        [Switch]$ElevatedObj
    )
    
    if (-not($PSBoundParameters.ContainsKey('UserObj')) -and $UserObj) {
        Write-Host "User relied on default value. We should really test the key exists in case there is no JSON"
    }

    $DomainObj = (Get-WmiObject Win32_ComputerSystem).Domain
    if ( $DomainObj -eq 'WORKGROUP' ){
        $DomainObj = (Get-WmiObject Win32_ComputerSystem).Name
    }

    if($SystemObj){
        $arglist = "Start-Process psexec -ArgumentList '-i -s powershell.exe -executionpolicy RemoteSigned' -Verb runAs"
    } else {
        $arglist = "Start-Process powershell.exe"
        if($ElevatedObj){
            $arglist = $arglist + " -Verb runAs"
        }
    }

    Start-Process powershell.exe -Credential "$DomainObj\$UserObj" -NoNewWindow -ArgumentList $arglist
}; Set-Alias pa Get-PowershellAs
<# End Support Helpers #>

<# HUD #>
Write-Host "$profile"
Write-Host (Get-ExecutionPolicy)

<# Prompt #>
function prompt {
    # https://github.com/dahlbyk/posh-git/wiki/Customizing-Your-PowerShell-Prompt
    $origLastExitCode = $LastExitCode

    if (Get-GitStatus){
        if (Get-Command git -TotalCount 1 -ErrorAction SilentlyContinue) {
            Set-EnvPath((Get-Item "Env:ProgramFiles").Value + "\Git\bin")
            Write-Host (git --version) -ForegroundColor Cyan
        }
    }

    if (Test-IsAdmin) {  # if elevated
        Write-Host "(Elevated $env:USERNAME ) " -NoNewline -ForegroundColor Red
    } else {
        Write-Host "$env:USERNAME " -NoNewline -ForegroundColor Blue
    }

    Write-Host "$env:COMPUTERNAME " -NoNewline -ForegroundColor DarkCyan
    Write-Host $ExecutionContext.SessionState.Path.CurrentLocation -ForegroundColor Cyan -NoNewline
    Write-VcsStatus
    $LASTEXITCODE = $origLastExitCode
    "`n$('PS>' * ($nestedPromptLevel + 1)) "
}

<# Notes #>

# Build a better function
# https://technet.microsoft.com/en-us/library/hh360993.aspx?f=255&MSPPError=-2147217396

# Research ways of using execution policy
# Set-ExecutionPolicy RemoteSigned -scope CurrentUser

# function Get-evtx {
#     wevtutil epl application c:\temp\application.evtx
# }

# function Get_Health {
#     DISM /Online /Cleanup-Image /CheckHealth
#     DISM /Online /Cleanup-Image /ScanHealth
#     DISM /Online /Cleanup-Image /RestoreHealth
# }

# function Get-Remote {
#     Start-Process C:\Windows\CmRcViewer.exe
# }

# function Get-Uptime {
#     (Get-Date)-(Get-CimInstance Win32_OperatingSystem).lastbootuptime | Format-Table
# }

# function Get-Documentation {
#     <#
#     .SYNOPSIS
#     Quick access to edit documentation.
#     .DESCRIPTION
#     Lightweight documentation.
#     .EXAMPLE
#     Get-Documentation -DocObj printers
#     .PARAMETER DocObj
#     The document name. Just one.
#     #>
#     param (
#         [parameter(Mandatory=$true)]
#         [ValidateNotNullOrEmpty()]$DocObj
#     )
#     try {
#         Import-Csv "$PSDirectory\$DocObj.txt" | Format-Table | Out-String -stream
#         Write-Host "`nFilter with (sls) : | Select-String 'STRING'`n"
#     } catch {
#         Write-Host "No such document."
#         return $false
#     }

# }; Set-Alias gd Get-Documentation

# SSH
# Test pipe
#Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*' | Add-WindowsCapability -Online
# Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install the OpenSSH Client
#Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Install the OpenSSH Server
# Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Find the powershell way
# msinfo32 /nfo C:\TEMP\SYSSUM.NFO /categories +systemsummary
