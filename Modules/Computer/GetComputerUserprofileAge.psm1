
function Get-ComputerUserprofileAge
{
    <#
  .SYNOPSIS
    Local userprofile age
  .DESCRIPTION
    Retrieve userprofile age from a computer.
  .EXAMPLE
    Get-ComputerUserprofileAge -Computer $hostname
  .EXAMPLE
    "$hostname","$hostname2" | Get-ComputerUserprofileAge
  #>
    Param(
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
        [string] $Computer
    )

    process
    {
        foreach ( $i in $Computer )
        {
            $(Get-Computer -Computer $Computer).Userprofile
        }
    }
}