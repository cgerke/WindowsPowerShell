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

            $ComputerObject = Get-CimInstance -CimSession $CimSession -ClassName Win32_QuickFixEngineering |
            Select-Object Description, HotFixID, InstalledOn |
            Sort-Object -Descending -Property InstalledOn |
            Format-Table

            Remove-CimSession -ComputerName $i

            return $ComputerObject
        }
    }
}