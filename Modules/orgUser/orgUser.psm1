function Get-User
{
  <#
.SYNOPSIS
  Wildcard search account audit.
.DESCRIPTION
  Find account details with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-User -Name "Chris Gerke"
#>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Name
  )
  $maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
  Get-ADUser -Filter "displayName -like '*$Name*'" -Properties * |
  Select-Object DisplayName, userPrincipalName, DistinguishedName, Title, Mail, `
  @{n = "Directorate"; e = { $_.Company } },`
  @{n = "Branch"; e = { $_.Department } },`
  @{n = "Employment Status"; e = { $_.Description } }, `
  manager, `
  MemberOf, `
  AccountExpirationDate, PasswordLastSet, @{n = "ExpiryDate"; e = { $_.PasswordLastSet.AddDays($maxPasswordAge) } }
}