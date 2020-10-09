function Get-RandomChar($length, $characters)
{
  $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
  $private:ofs = ""
  return [String]$characters[$random]
}

function Get-Password
{
  $password = Get-RandomChar -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
  $password += Get-RandomChar -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
  $password += Get-RandomChar -length 1 -characters '1234567890'
  $password += Get-RandomChar -length 1 -characters '!$%=?#*'
  $password
}