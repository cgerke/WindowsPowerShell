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