function Get-UserExpiry
{
  <#
.SYNOPSIS
  Wildcard search account expiry.
.DESCRIPTION
  Find Expiry date with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-UserExpiry "Chris"
.EXAMPLE
  Get-UserExpiry "Gerke"
.EXAMPLE
  Get-UserExpiry "Chris Gerke"
.EXAMPLE
  Get-UserExpiry "gerkec"
#>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Name
  )

  Get-User -Name $Name | Select-Object DisplayName, AccountExpirationDate

}