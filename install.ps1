<#
.Synopsis
  Setup WindowsPowerShell on Windows
.DESCRIPTION
  Invoke-Expression $(Invoke-WebRequest https://raw.githubusercontent.com/cgerke/WindowsPowerShell/master/install.ps1)
#>

# Repositories
"PSGallery" | ForEach-Object -process {
  if (-not (Get-PSRepository -Name "$_")) {
    Set-PSRepository -Name "$_" -InstallationPolicy Trusted -Verbose
  }
}

# Package Provider (Requires PSGallery Trust)
"Nuget" | ForEach-Object -process {
   Install-PackageProvider -Name "$_" -Scope CurrentUser -Force -Verbose
}

# Modules (Requires Nuget)
"PowerShellGet","oh-my-posh","posh-git","PSReadLine", "PSScriptAnalyzer","Pester","Plaster","PSSudo" | ForEach-Object -process {
  if (-not (Get-Module -ListAvailable -Name "$_")) {
    Install-Module "$_" -Scope CurrentUser -Force -Confirm:$false -Verbose
  }
}

# Git
$git = $(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object {$_.DisplayName -like "*Git*"})
If (-not ($git)) {
  Start-Process "winget" -ArgumentList "install --id Git.Git --silent" -Wait -NoNewWindow
}

# Fetch REPO
New-Item -Path $Profile -Type File
$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
$PWShell = "$PSRoot\WindowsPowerShell"
Remove-Item -Path "$PWShell\.git" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $Profile -Force -ErrorAction SilentlyContinue

<# TODO Need to investigate this further, why does this environment var
cause git init to fail? Should I just (temporarily remove HOMEPATH)
Remove-Item Env:\HOMEPATH
-or #>
New-TemporaryFile | ForEach-Object {
  Remove-Item "$_" -Force -ErrorAction SilentlyContinue
  New-Item -Path "$_" -ItemType Directory -Force -Verbose
  Set-Location "$_"
  Set-Item -Path Env:HOME -Value $Env:USERPROFILE
  Start-Process "git" -ArgumentList "init" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "remote add origin https://github.com/cgerke/WindowsPowerShell" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "fetch --all" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "checkout master" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "push --set-upstream origin master" -Wait -NoNewWindow
  Move-Item -Path .\.git -Destination "$PWShell\" -Force -Verbose
  Set-Location "$PWShell"
  Start-Process "git" -ArgumentList "reset --hard origin/master" -Wait -NoNewWindow
  Set-Location "$PSRoot"
  Set-Location "$PWShell"
}