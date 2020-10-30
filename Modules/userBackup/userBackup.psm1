function Copy-WithRobocopy
{
  <#
  .SYNOPSIS
    Robocopy with progress.
  .DESCRIPTION
    Robocopy with progress and log files.
  .EXAMPLE
    Copy-WithRobocopy -Source "$env:APPDATA\Microsoft\Signatures" -Destination "$env:OneDrive\Backup\Signatures"
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string] $Source,
    [Parameter(Mandatory = $true)]
    [string] $Destination)

    robocopy "$Source" "$Destination" /MIR /NDL /NJH /NJS |
    ForEach-Object {
      $data = $_.Split([char]9);
      if ("$($data[4])" -ne "") {
        $file = "$($data[4])"
      };
      Write-Progress "Percentage $($data[0])" -Activity "Robocopy" -CurrentOperation "$($file)" -ErrorAction SilentlyContinue;
      "$($data[0]) $($file)" | Tee-Object -FilePath "C:\temp\robo.txt" -Append
    }
}

function New-Backup
{
  Copy-WithRobocopy -Source "$env:APPDATA\Microsoft\Signatures" -Destination "$env:OneDrive\Backup\Signatures"
}