function Get-ComputerMacAddress
{
    <#
  .SYNOPSIS
    System macaddress information
  .DESCRIPTION
    Retrieve macddress information from a computer
  .EXAMPLE
    Get-ComputerMacAddress -Computer $hostname
  #>
    Param(
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
        [string] $Computer
    )

    process
    {
        foreach ( $i in $Computer )
        {
            ### WinRM remoting by default
            ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
            If (Test-WSMan -ComputerName $i -ErrorAction SilentlyContinue)
            {
                Write-Information "WinRM available." -InformationAction Continue
                $CimSession = New-CimSession -ComputerName $i
            }
            Else
            {
                Write-Information "Using DCOM as WinRM is not available" -InformationAction Continue
                $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
                $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
            }

            $ComputerObject = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration |
            Where-Object { $null -ne $_.MACAddress } | Select-Object Description, MACAddress |
            Format-Table

            Remove-CimSession -ComputerName $i

            return $ComputerObject
        }
    }
}