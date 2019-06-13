
#region globals
$DebugPreference = "SilentlyContinue" # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" # Support TLS

$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent

# . source
Push-Location "$PSRoot\WindowsPowerShell"
"preferences","debug" |
  Where-Object {Test-Path "Microsoft.PowerShell_$_.ps1"} |
  ForEach-Object -process {
    Invoke-Expression ". .\Microsoft.PowerShell_$_.ps1"
}
#Pop-Location

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
  if (Test-IsAdmin) {  # if elevated
    Write-Host " (Elevated $env:USERNAME ) " -NoNewline -ForegroundColor Red
  } else {
    Write-Host " $env:USERNAME " -NoNewline -ForegroundColor White
  }

  # Host
  Write-Host "$env:COMPUTERNAME " -NoNewline -ForegroundColor White
  Write-Host $ExecutionContext.SessionState.Path.CurrentLocation -ForegroundColor Gray -NoNewline

  # Git https://github.com/dahlbyk/posh-git/wiki/Customizing-Your-PowerShell-Prompt
  if (Get-GitStatus){
    if (Get-Command git -TotalCount 1 -ErrorAction SilentlyContinue) {
      Set-EnvPath((Get-Item "Env:ProgramFiles").Value + "\Git\bin")
    }
    Write-VcsStatus
  }

  # Prompt
  "`n$('PS>' * ($nestedPromptLevel + 1)) "
}