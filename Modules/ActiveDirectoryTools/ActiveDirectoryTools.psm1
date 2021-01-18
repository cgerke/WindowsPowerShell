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

function Get-LAPS
{
    <#
    .SYNOPSIS
    https://technet.microsoft.com/en-us/mt227395.aspx
    .DESCRIPTION
    Query Active Directory for the local administrator password of a Computer.
    .EXAMPLE
    Get-LAPS -Computer mycomputer-1
    .PARAMETER Computer
    The computer name to query. Just one.
    #>
    param (
        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]$Computer
    )

    try
    {
        Get-ADComputer $Computer -Properties ms-Mcs-AdmPwd | Select-Object name, ms-Mcs-AdmPwd
    }
    catch
    {
        return $false
    }
}

function Get-LAPSExpiry
{
    <#
    .SYNOPSIS
    https://technet.microsoft.com/en-us/mt227395.aspx
    .DESCRIPTION
    Query Active Directory for the local administrator password expiry date for a Computer.
    .EXAMPLE
    Get-LAPSExpiry -Computer mycomputer-1
    .PARAMETER Computer
    The computer name to query. Just one.
    #>
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Computer
    )

    $PwdExp = Get-ADComputer $Computer -Properties ms-MCS-AdmPwdExpirationTime
    $([datetime]::FromFileTime([convert]::ToInt64($PwdExp.'ms-MCS-AdmPwdExpirationTime', 10)))
}

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
      [PSCustomObject]@{
        Group = $Group
        User = $(Get-ADUser -Identity $Object.Name -Property DisplayName | Select-Object DisplayName).DisplayName
      }
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

  Get-GroupRecurse "$Name" | Sort-Object Group
}

function Get-Password
{
  <#
  .SYNOPSIS
    Generate a random complex password.
  .DESCRIPTION
    Generate a random complex password, 8 chars in length containing, 1 upper case char, 1 integer, 1 special char
  .EXAMPLE
    Get-Password
  #>
  $password = -join ((97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_}) #ASCII lower case
  $password += -join ((65..90) | Get-Random -Count 1 | ForEach-Object {[char]$_}) #ASCII upper case
  $password += -join ((1..9) | Get-Random -Count 1) + "*" #Integer + *
  return $password
}