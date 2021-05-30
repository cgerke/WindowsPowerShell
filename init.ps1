<#
.Synopsis
  Setup WindowsPowerShell on Windows
.DESCRIPTION
  Invoke-Expression $(Invoke-WebRequest https://raw.githubusercontent.com/cgerke/WindowsPowerShell/main/init.ps1)
#>

# SSH
Start-Process -FilePath powershell.exe -ArgumentList {
  -noprofile
  Set-ItemProperty "REGISTRY::HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" UseWUserver -value 0
  Get-WindowsCapability -Name 'OpenSSH.Client*' -Online | Where-Object state -ne 'Installed' | Add-WindowsCapability -Online
  Set-ItemProperty "REGISTRY::HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" UseWUserver -value 1
} -verb RunAs

# Telnet
Start-Process -FilePath powershell.exe -ArgumentList {
  -noprofile
  Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient" | Where-Object state -ne 'Installed' | Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
} -verb RunAs

# Sandbox
Start-Process -FilePath powershell.exe -ArgumentList {
  -noprofile
  Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" | Where-Object state -ne 'Installed' | Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
} -verb RunAs

# Paths
New-Item -Path $Profile -Type File
$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
$PWShell = "$PSRoot\WindowsPowerShell"
Remove-Item -Path $Profile -Force -ErrorAction SilentlyContinue

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
"PowerShellGet","oh-my-posh","posh-git", "Posh-SSH", "PSScriptAnalyzer","Pester","Plaster","PSSudo" | ForEach-Object -process {
  if (-not (Get-Module -ListAvailable -Name "$_")) {
    Install-Module "$_" -Scope CurrentUser -Force -Confirm:$false -Verbose
  }
}

# Winget
$appinstaller = $(Get-AppxPackage -Name "Microsoft.DesktopAppInstaller")
If (-not ($appinstaller)){
  Add-AppxPackage -Path "$PWShell\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.appxbundle"
}

$winget = $(& winget --version)
If (-not ($winget)) {
  Exit 1
}

# Git
$git = $(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object {$_.DisplayName -like "*Git*"})
If (-not ($git)) {
  Start-Process "winget" -ArgumentList "install --id Git.Git --silent" -Wait -NoNewWindow
}

#if (-not (Test-Path "$env:HOMEPATH\.bashrc")){
  New-Item -Path "$env:HOMEPATH\.config" -ItemType Directory -Force -Verbose
  New-Item -Path "$env:HOMEPATH\.config\git" -ItemType Directory -Force -Verbose
  Copy-Item -Path "$PWShell\git-prompt.sh" "$env:HOMEPATH\.config\git\git-prompt.sh"
  Copy-Item -Path "$PWShell\.bashrc" "$env:HOMEPATH\.bashrc"
#}

# Fetch REPO
Remove-Item -Path "$PWShell\.git" -Recurse -Force -ErrorAction SilentlyContinue

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
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.SendKeys]::SendWait("%n{ENTER}")
}

# Windows Terminal
$wt = $(Get-AppxPackage -Name "Microsoft.WindowsTerminal")
If (-not ($wt)) {
  Start-Process "winget" -ArgumentList "install --id Microsoft.WindowsTerminal --silent" -Wait -NoNewWindow
}
Copy-Item -Path "$PWShell\settings.json" "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"

# Windows Terminal Powerline Font
if (-not (Test-Path "$env:LOCALAPPDATA\Microsoft\Windows\Fonts\CascadiaCodePL.ttf")){
  Copy-Item -Path "$PWShell\CascadiaCode\ttf\CascadiaCodePL.ttf" "$env:LOCALAPPDATA\Microsoft\Windows\Fonts\CascadiaCodePL.ttf"
}

# VSCode
$vscode = $(Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Microsoft Visual Studio Code*"})
If (-not ($vscode)) {
  Start-Process "winget" -ArgumentList "install --id Microsoft.VisualStudioCode-User-x64 --silent" -Wait -NoNewWindow
}