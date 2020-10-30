function Get-FilePathLength {
  <#
  .SYNOPSIS
  Count file path characters.
  .DESCRIPTION
  Help identifying 260 chars.
  .EXAMPLE
  Get-FilePathLength -Path C:\temp
  .PARAMETER Path
  The folder path to query. Just one.
  #>
  param (
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Path
  )
  Get-ChildItem -Path "$Path" -Recurse -Force |
      #Where-Object {$_.FullName.length -ge 248 } |
      Select-Object -Property FullName, @{Name="FullNameLength";Expression={($_.FullName.Length)}} |
      Sort-Object -Property FullNameLength -Descending
}

function Remove-ReadOnly {
  <#
  .SYNOPSIS
  Recursively remove read only attributes.
  .DESCRIPTION
  Recursively remove read only attributes from a file system path.
  .EXAMPLE
  Remove-ReadOnly -Path
  .PARAMETER Path
  Mandatory file or folder path.
  #>
  param (
      [Parameter(Mandatory = $True)]
      [ValidateNotNullOrEmpty()]$Path
  )
  Get-ChildItem "$Path" -Recurse | ForEach-Object {$_.Attributes = 'Normal'}
}

Function Set-FileTime {
  <#
  .SYNOPSIS
  Set a date stamp attribute.
  .DESCRIPTION
  Set a date stamp attributes for a file system path.
  .EXAMPLE
  Set-FileTime -Path C:\temp\log.txt -date 7/1/11
  .PARAMETER Path
  Mandatory file system path
  #>
  Param (
      [Parameter(mandatory = $true)]
      [string[]]$Path,
      [Parameter(mandatory = $true)]
      [datetime]$date
  )

  Get-ChildItem -Path "$Path" |

  ForEach-Object {
      $_.CreationTime = $date
      $_.LastWriteTime = $date
  }
}

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
  <#
  .SYNOPSIS
    Default backup set.
  .DESCRIPTION
    Default backup to OneDrive.
  .EXAMPLE
    New-Backup
  #>
  Copy-WithRobocopy -Source "$env:APPDATA\Microsoft\Signatures" -Destination "$env:OneDrive\Backup\Signatures"
}