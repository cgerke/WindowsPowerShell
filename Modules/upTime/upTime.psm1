function Format-TimeSpan {
    process {
      "{0:00} days {1:00} hours {2:00} minutes {3:00} seconds" -f $_.Days,$_.Hours,$_.Minutes,$_.Seconds
    }
  }

function Get-Uptime
{
<#
  .SYNOPSIS
    System uptime
  .DESCRIPTION
    Retrieve system uptime from a remote computer.
  .EXAMPLE
    Get-Uptime -Computer $hostname
  #>
Param(
    [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
    [string[]] $Computer
)

    process {
        foreach ( $i in $Computer ) {
        ### WinRM remoting by default
        ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
        If (Test-WSMan -ComputerName $i -ErrorAction SilentlyContinue)
        {
            Write-Information "WinRM available."
            $CimSession = New-CimSession -ComputerName $i
        }
        Else
        {
            # Use DCOM if WinRM is not available
            $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
            $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
        }

        $CIMopsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
        $ComputerObject = [PSCustomObject]@{
            Name = $i
            LastBootUpTime = $CIMopsys.LastBootUpTime
            LastBootUpTimeRelative = (Get-Date) - $CIMopsys.LastBootUpTime | Format-TimeSpan
        }
        return $ComputerObject
        }
    }
}