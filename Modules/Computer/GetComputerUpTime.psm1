function Get-ComputerUptime
{
    <#
  .SYNOPSIS
    System uptime
  .DESCRIPTION
    Retrieve system uptime from a computer.
  .EXAMPLE
    Get-ComputerUptime -Computer $hostname
  #>
    Param(
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
        [string] $Computer
    )

    process
    {
        foreach ( $i in $Computer )
        {
            Get-Computer -Computer $Computer | Select-Object LastBootUpTime,LastBootUpTimeRelative
        }
    }
}