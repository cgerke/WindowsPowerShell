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

  Write-Host "$env:COMPUTERNAME " -NoNewline -ForegroundColor White
  Write-Host $ExecutionContext.SessionState.Path.CurrentLocation -ForegroundColor Gray -NoNewline
  Write-VcsStatus

  # Prompt
  "`n$('PS>' * ($nestedPromptLevel + 1)) "
}

<#
$PSPath = "$(Split-Path -Parent $PROFILE)"
$ModulePath = "$PSPath\Modules)
Invoke-Plaster -TemplatePath "$PSPath" -DestinationPath $ModulePath -Verbose
#>
