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