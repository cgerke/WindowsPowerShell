function Get-Title
{
  <#
.SYNOPSIS
  Wildcard search titles.
.DESCRIPTION
  Find Titles with a quick wildcard search in Active Directory.
.EXAMPLE
  Get-Title -Name "Team Leader"
#>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Name
  )
  Get-ADUser -Properties * -Filter "title -like '*$Name*'" |
    Select-Object GivenName, surname, company, department, description
}