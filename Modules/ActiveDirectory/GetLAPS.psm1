function Get-LAPS
{
    <#
    .SYNOPSIS
    https://technet.microsoft.com/en-us/mt227395.aspx
    .DESCRIPTION
    Query Active Directory for the local administrator password of a Computer.
    .EXAMPLE
    Get-LAPS -Computer mycomputer-1
    .PARAMETER Computer
    The computer name to query. Just one.
    #>
    param (
        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]$Computer
    )

    try
    {
        Get-ADComputer $Computer -Properties ms-Mcs-AdmPwd | Select-Object name, ms-Mcs-AdmPwd
    }
    catch
    {
        return $false
    }
}

function Get-LAPSExpiry
{
    <#
    .SYNOPSIS
    https://technet.microsoft.com/en-us/mt227395.aspx
    .DESCRIPTION
    Query Active Directory for the local administrator password expiry date for a Computer.
    .EXAMPLE
    Get-LAPSExpiry -Computer mycomputer-1
    .PARAMETER Computer
    The computer name to query. Just one.
    #>
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Computer
    )

    $PwdExp = Get-ADComputer $Computer -Properties ms-MCS-AdmPwdExpirationTime
    $([datetime]::FromFileTime([convert]::ToInt64($PwdExp.'ms-MCS-AdmPwdExpirationTime', 10)))
}