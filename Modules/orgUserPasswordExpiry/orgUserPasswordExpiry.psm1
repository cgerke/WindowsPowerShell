function Get-PasswordExpiry
{
  <#
  .SYNOPSIS
    Wildcard search account password expiry.
  .DESCRIPTION
    Find Password Expiry date with a quick wildcard search in Active Directory. The wildcard can be any
    combination of First name and Last name or the samAccountName.
  .EXAMPLE
    Get-PasswordExpiry "Chris"
  .EXAMPLE
    Get-PasswordExpiry "Gerke"
  .EXAMPLE
    Get-PasswordExpiry "Chris Gerke"
  .EXAMPLE
    Get-PasswordExpiry "gerkec"
  #>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Name
  )
  $maxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
  $displayName = Get-ADUser -Filter "displayName -like '*$Name*'" -Properties * |
  Select-Object -Property "Displayname", PasswordLastSet, @{n = "ExpiryDate"; e = { $_.PasswordLastSet.AddDays($maxPasswordAge) } }

  If ($displayName)
  {
    # Probably doing a First, Last or Display Name search.
    $displayName
  }
  Else
  {
    # Probably doing a samAccount search.
    Get-ADUser -Filter "samAccountName -like '$Name*'" -Properties * |
    Select-Object -Property "Displayname", PasswordLastSet, @{n = "ExpiryDate"; e = { $_.PasswordLastSet.AddDays($maxPasswordAge) } }
  }
}