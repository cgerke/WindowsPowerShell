function Get-Expiry
{
  <#
.SYNOPSIS
  Wildcard search account expiry.
.DESCRIPTION
  Find Expiry date with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-Expiry "Chris"
.EXAMPLE
  Get-Expiry "Gerke"
.EXAMPLE
  Get-Expiry "Chris Gerke"
.EXAMPLE
  Get-Expiry "gerkec"
#>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Name
  )
  $displayName = Get-ADUser -Properties * -Filter "displayName -like '*$Name*'" |
    Select-Object GivenName, surname, company, department, description, AccountExpirationDate
  If ($displayName)
  {
    # Probably doing a First, Last or Display Name search.
    $displayName
  }
  Else
  {
    Get-ADUser -Properties * -Filter "samAccountName -like '*$Name*'" |
      Select-Object GivenName, surname, company, department, description, AccountExpirationDate
  }
}