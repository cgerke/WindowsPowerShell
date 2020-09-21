[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" # Support TLS

$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent

<# . source
But research the best way to use "preferences" and debug
workflows.
#>
Push-Location "$PSRoot\WindowsPowerShell"
"preferences","debug" |
  Where-Object {Test-Path "Microsoft.PowerShell_$_.ps1"} |
  ForEach-Object -process {
    Invoke-Expression ". .\Microsoft.PowerShell_$_.ps1"
}

# winget checks here

# USER Env:Path
function Set-EnvPath([string] $path ) {
  if ( -not [string]::IsNullOrEmpty($path) ) {
    if ( (Test-Path $path) -and (-not $env:PATH.contains($path)) ) {
      $env:PATH += ';' + "$path"
    }
  }
}

function Test-IsAdmin {
  $user = [Security.Principal.WindowsIdentity]::GetCurrent();
  (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function prompt {
  # WindowsPowershell version
  $PSVersionTable.PSVersion |
    ForEach-Object -process { "$_ " } |
    Write-Host -NoNewLine -ForegroundColor Cyan
  Write-Host $(Get-ExecutionPolicy) -NoNewline -ForegroundColor Cyan

  # User
  If (Test-IsAdmin) {  # if elevated
    Write-Host " (Elevated $env:USERNAME ) " -NoNewline -ForegroundColor Red
  } Else {
    Write-Host " $env:USERNAME " -NoNewline -ForegroundColor White
  }

  # Host
  Write-Host "$env:COMPUTERNAME " -NoNewline -ForegroundColor White
  Write-Host $ExecutionContext.SessionState.Path.CurrentLocation -ForegroundColor Gray -NoNewline
  # Git
  Write-VcsStatus

  # Prompt
  "`n$('PS>' * ($nestedPromptLevel + 1)) "
}