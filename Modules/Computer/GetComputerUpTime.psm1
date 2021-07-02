﻿function Get-ComputerUptime
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

            $CIMopsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
            $ComputerObject = [PSCustomObject]@{
                Name                   = $i
                LastBootUpTime         = $CIMopsys.LastBootUpTime
                LastBootUpTimeRelative = (Get-Date) - $CIMopsys.LastBootUpTime | Format-TimeSpan
            }

            Remove-CimSession -ComputerName $i

            return $ComputerObject
        }
    }
}