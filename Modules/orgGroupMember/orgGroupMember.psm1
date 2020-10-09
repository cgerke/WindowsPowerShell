Function Get-GroupRecurse ([string]$Group)
{
  ForEach ($Object in (Get-ADGroupMember -Identity $Group) )
  {
    if ($Object.objectClass -eq "group")
    {
      Get-GroupRecurse -Group $Object.Name
    }
    else
    {
      [PSCustomObject]@{Group = $Group; User = $Object.Name; }
    }
  }
}

function Get-GroupMember
{
  <#
.SYNOPSIS
  Get group members.
.DESCRIPTION
  Find group members with a search in Active Directory. Recurses sub-group members.
.EXAMPLE
  Get-GroupMember -Name "Group Name"
.LINK
  Get-Group
#>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Name
  )

  $return = Get-GroupRecurse "$Name"
  $return | Sort-Object Group
}