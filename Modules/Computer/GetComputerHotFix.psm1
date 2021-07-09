function Get-ComputerHotFix
{
    <#
  .SYNOPSIS
    System HotFix information
  .DESCRIPTION
    Retrieve HotFix information from a computer
  .EXAMPLE
    Get-ComputerHotFix -Computer $hostname
  .EXAMPLE
    "$hostname","$hostname2" | Get-ComputerHotFix
  #>
    Param(
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
        [string] $Computer
    )

    process
    {
        foreach ( $i in $Computer )
        {
            $(Get-Computer -Computer $Computer).HotFix
        }
    }
}