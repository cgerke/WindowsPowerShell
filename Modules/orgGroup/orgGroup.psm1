function Get-Group
{
  <#
.SYNOPSIS
  "Fuzzy" search active directory groups.
.DESCRIPTION
  Retrieve Active Directory groups using a "fuzzy" search.
.EXAMPLE
  Get-Group "Fuzzy search"
.LINK
  Get-GroupMember

#>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $group
  )
  Get-ADGroup -Filter "name -like '*$group*'" | Select-Object Name
}