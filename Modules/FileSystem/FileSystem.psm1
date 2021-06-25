function Get-FilePathLength
{
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
    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]$Path
  )
  Get-ChildItem -Path "$Path" -Recurse -Force |
  #Where-Object {$_.FullName.length -ge 248 } |
  Select-Object -Property FullName, @{Name = "FullNameLength"; Expression = { ($_.FullName.Length) } } |
  Sort-Object -Property FullNameLength -Descending
}

function Remove-ReadOnly
{
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
  Get-ChildItem "$Path" -Recurse | ForEach-Object { $_.Attributes = 'Normal' }
}

Function Set-FileTime
{
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
    $date
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
    if ("$($data[4])" -ne "")
    {
      $file = "$($data[4])"
    };
    Write-Progress "Percentage $($data[0])" -Activity "Robocopy" -CurrentOperation "$($file)" -ErrorAction SilentlyContinue;
    "$($data[0]) $($file)" | Tee-Object -FilePath "$env:TEMP\robo.txt" -Append
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

function Test-RegistryValue {
  param (
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Path,
      [parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]$Value
  )

  try {
      Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
      return $true
  } catch {
      return $false
  }
}

function Get-DotNet {
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
      Get-ItemProperty -name Version, Release -EA 0 |
      Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
      Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}},@{name = "Product"; expression = {$_.Release}},Version, Release
}

function Get-MSIProdCode {
  <#
  .SYNOPSIS
      Retrieves a list of all installed software UNINSTALL msi product codes.
  .EXAMPLE
      This example retrieves all installed software UNINSTALL msi product codes.
      Get-MSIProdCode
  .EXAMPLE
      This example retrieves all installed software UNINSTALL msi product codes including 'Office' in the display name.
      Get-MSIProdCode -DisplayName "Office"
  .PARAMETER Name
      The software title you'd like to limit the query to.
  #>
  [OutputType([System.Management.Automation.PSObject])]
  [CmdletBinding()]
  param (
      [Parameter()]
      [ValidateNotNullOrEmpty()]
      [string]$DisplayName
  )

  # old way
  # get-wmiobject Win32_Product | Format-Table IdentifyingNumber, Name | Out-String -stream
  $UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  $null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
  foreach ($UninstallKey in $UninstallKeys) {
      if ($PSBoundParameters.ContainsKey('DisplayName')) {
          $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "*$DisplayName*") }
      }
      else {
          $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) }
      }
      $gciParams = @{
          Path        = $UninstallKey
          ErrorAction = 'SilentlyContinue'
      }
      $selectProperties = @(
          @{n = 'GUID'; e = {$_.PSChildName}},
          @{n = 'Name'; e = {$_.GetValue('DisplayName')}}
      )
      Get-ChildItem @gciParams | Where-Object $WhereBlock | Select-Object -Property $selectProperties
  }
}