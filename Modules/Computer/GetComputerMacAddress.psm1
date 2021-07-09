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
            $(Get-Computer -Computer $Computer).MacAddress
        }
    }
}