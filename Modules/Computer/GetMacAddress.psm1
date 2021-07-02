function Get-MacAddress
{
  <#
    .SYNOPSIS
      Retrieve macaddresses
    .DESCRIPTION
      Retrieve macaddresses from a remote computer.
    .EXAMPLE
      Get-MacAddress -Computer $hostname
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
        Write-Information "WinRM available."
        $CimSession = New-CimSession -ComputerName $i
      }
      Else
      {
        # Use DCOM if WinRM is not available
        $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
        $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
      }

      $ComputerObject = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration |
      Where-Object { $null -ne $_.MACAddress } |
      Select-Object Description, MACAddress

      Remove-CimSession -ComputerName $i

      return $ComputerObject
    }
  }
}