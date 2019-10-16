exit

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

function Get-Sandbox {
 Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
}

function Get-Ssh {
 Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Client*" | Add-WindowsCapability -Online
}

function Get-Telnet {
 Start-Process -FilePath powershell.exe -ArgumentList {
     -noprofile
     Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
     Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
 } -verb RunAs
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

}; Set-Alias "Get-Sudo" Get-PowershellAs

<# Active Directory LAZY ADMIN #>

function Get-Group {
<#
.SYNOPSIS
  Wilcard search for groups.
.DESCRIPTION
  Find groups with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-Group "Fuzzy search"
#>
  Param(
    [Parameter(Position=0,mandatory=$true)]
    [string] $group
  )
  Get-ADGroup -Filter "name -like '*$group*'" | Select-Object Name | Out-String -Stream
}

function Get-GroupMember {
<#
.SYNOPSIS
  Get group members.
.DESCRIPTION
  Find group members with a search in Active Directory.
.EXAMPLE
  Get-GroupMember "Group Name"
#>
  Param(
    [Parameter(Position=0,mandatory=$true)]
    [string] $group
  )
    Get-ADGroupMember -Identity "$group" | Get-ADUser | Select-Object givenname, surname, userprincipalname | Format-Table -AutoSize | Out-String -Stream
}

function Get-Title {
<#
.SYNOPSIS
  Wildcard search titles.
.DESCRIPTION
  Find Titles with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-Title "Team Leader"
#>
  Param(
    [Parameter(Position=0,mandatory=$true)]
    [string] $description
  )
    Get-ADUser -properties * -filter "title -like '*$description*'" | Select-Object GivenName,surname,company,department,description | Out-String -Stream
}

function Get-Expiry {
<#
.SYNOPSIS
  Wildcard search account expiry.
.DESCRIPTION
  Find Expiry date with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-PasswordExpiry "Chris"
.EXAMPLE
  Get-PasswordExpiry "Gerke"
.EXAMPLE
  Get-PasswordExpiry "Chris Gerke"
.EXAMPLE
  Get-PasswordExpiry "cgerke"
#>
  Param(
    [Parameter(Position=0,mandatory=$true)]
    [string] $Name
  )
  $displayName = Get-ADUser -properties * -filter "displayName -like '*$Name*'" | Select-Object GivenName,surname,company,department,description,AccountExpirationDate | Out-String -Stream
  If ($displayName) {
    # Probably doing a First, Last or Display Name search.
    $displayName
  } Else {
    Get-ADUser -properties * -filter "samAccountName -like '*$Name*'" | Select-Object GivenName,surname,company,department,description,AccountExpirationDate | Out-String -Stream
  }
}

function Get-PasswordExpiry {
<#
.SYNOPSIS
  Wildcard search account password expiry.
.DESCRIPTION
  Find Password Expiry date with a quick wildcard search in Active Directory. The wildcard can be any
  combination of First name and Last name or the samAccountName.
.EXAMPLE
  Get-PasswordExpiry "Chris"
.EXAMPLE
  Get-PasswordExpiry "Gerke"
.EXAMPLE
  Get-PasswordExpiry "Chris Gerke"
.EXAMPLE
  Get-PasswordExpiry "cgerke"
#>
  Param(
    [Parameter(Position=0,mandatory=$true)]
    [string] $Name
  )
  $maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
  $displayName = Get-ADUser -filter "displayName -like '*$Name*'" -Properties * |
  Select-Object -Property "Displayname", @{n="ExpiryDate";e={$_.PasswordLastSet.AddDays($maxPasswordAge)}}
  
  If ($displayName) {
    # Probably doing a First, Last or Display Name search.
    $displayName
  } Else {
    # Probably doing a samAccount search.
    Get-ADUser -filter "samAccountName -like '*$Name*'" -Properties * |
    Select-Object -Property "Displayname", @{n="ExpiryDate";e={$_.PasswordLastSet.AddDays($maxPasswordAge)}}
  }
}

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

    # old way
    # get-wmiobject Win32_Product | Format-Table IdentifyingNumber, Name | Out-String -stream
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
function Remove-ReadOnly {
    <#
    .SYNOPSIS
    Recursively remove read only attributes.
    .DESCRIPTION
    Recursively remove read only attributes.
    .EXAMPLE
    Remove-ReadOnly -PathObj
    .PARAMETER PathObj
    Mandatory path
    #>
    param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]$PathObj
    )
    Get-ChildItem "$PathObj" -Recurse | ForEach-Object {$_.Attributes = 'Normal'}
}

Function Set-FileTime {
    <#
    .SYNOPSIS
    Set a date stamp attribute.
    .DESCRIPTION
    Set a date stamp attribute.
    .EXAMPLE
    Set-FileTime -PathObj C:\temp\log.txt -date 7/1/11
    .PARAMETER PathObj
    Mandatory path
    #>
    Param (
        [Parameter(mandatory = $true)]
        [string[]]$PathObj,
        [Parameter(mandatory = $true)]
        [datetime]$date
    )

    Get-ChildItem -Path $PathObj |

    ForEach-Object {
        $_.CreationTime = $date
        $_.LastWriteTime = $date
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

<# #consuming json
$json = Join-Path -Path $PSDirectory -ChildPath "Microsoft.PowerShell_options.json"
if ( Test-Path -path $json ) {
    $Defaults = Get-Content $json | ConvertFrom-Json
    #$JsonObject.Defaults[0]
    #$Defaults.AdminAccount[0].Username
} #>

#self executing function
#& { param($msg) Write-Host $msg } "Hello World"
