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
$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
Push-Location "$PSRoot\WindowsPowerShell"
"preferences","debug" |
  Where-Object {Test-Path "Microsoft.PowerShell_$_.ps1"} |
  ForEach-Object -process {
    Invoke-Expression ". .\Microsoft.PowerShell_$_.ps1"
}

<# #consuming json
$json = Join-Path -Path $PSDirectory -ChildPath "Microsoft.PowerShell_options.json"
if ( Test-Path -path $json ) {
    $Defaults = Get-Content $json | ConvertFrom-Json
    #$JsonObject.Defaults[0]
    #$Defaults.AdminAccount[0].Username
} #>

