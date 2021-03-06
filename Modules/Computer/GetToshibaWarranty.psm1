Function Get-ToshibaWarranty
{
  <#
    .SYNOPSIS
      Retrieve warranty information for a Toshiba computer.
    .DESCRIPTION
      Retrieve warranty information for a Toshiba computer via a json response.
    .EXAMPLE
      Get-ToshibaWarranty -Serial $Serial
    .EXAMPLE
      "$serial,"$serial2" | Get-ToshibaWarranty
    #>
  Param(
    [Parameter(Position = 0, mandatory = $true)]
    [string] $Serial
  )

  process
  {
    foreach ( $i in $Serial )
    {
      $web = New-Object Net.WebClient
      $url = "http://support.toshiba.com/support/warrantyResults?sno="
      $url = $url + $i
      $content = $web.DownloadString($url) | Out-String | ConvertFrom-Json
      $warranty = $content.commonBean
      $warranty
    }
  }
}