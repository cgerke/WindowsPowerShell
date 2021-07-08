
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
            if (-not (Test-Connection -Quiet -ComputerName "$Computer" -Count 2))
            {
                Write-Information "$Computer appears to be offline" -InformationAction Continue
            }
            else
            {
                ### WinRM remoting by default
                ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
                if (Test-WSMan -ComputerName $i -ErrorAction SilentlyContinue)
                {
                    Write-Information "WinRM available" -InformationAction Continue
                    $CimSession = New-CimSession -ComputerName $i
                }
                else
                {
                    Write-Information "Using DCOM as WinRM is not available" -InformationAction Continue
                    $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
                    $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
                }

                $ComputerObject = Get-CimInstance -CimSession $CimSession -ClassName Win32_Userprofile | Select-Object lastusetime, localpath, sid

                Remove-CimSession -ComputerName $i

                return $ComputerObject
            }
        }
    }
}