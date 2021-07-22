<#
.Synopsis
  Setup Windows environment.
.DESCRIPTION
  Setup WindowsPowerShell on Windows along with some tools.
#>

# Tools
# Disable enterprise Windows Update Server temporarily
$WUServer = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
try {
  Start-Process -FilePath powershell.exe -ArgumentList {
    -noprofile
    # SSH
    Set-ItemProperty -Path $WUServer UseWUserver -Value 0 -ErrorAction Ignore
    Get-WindowsCapability -Name 'OpenSSH.Client*' -Online |
    Where-Object state -NE 'Installed' |
    Add-WindowsCapability -Online
    Set-ItemProperty -Path $WUServer UseWUserver -Value 1 -ErrorAction Ignore
    # Telnet and Sandbox
    $Feature = 'TelnetClient', 'Containers-DisposableClientVM'
    foreach($FeatureName in $Feature) {
      Get-WindowsOptionalFeature -Online -FeatureName $FeatureName |
      Where-Object state -NE 'Enabled' |
      Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart
    }
  } -Verb RunAs -ErrorAction Ignore
} catch {
    If ( $_.Exception.Message -like "*canceled*" ) {
      "Skipped"
    } Else {
      "Error"
    }
}

# Paths
New-Item -Path $Profile -Type File -ErrorAction Ignore
$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
$PWShell = "$PSRoot\WindowsPowerShell"
Remove-Item -Path $Profile -Force -ErrorAction SilentlyContinue

# Repositories
"PSGallery" | ForEach-Object -Process {
  if (-not (Get-PSRepository -Name "$_")) {
    Set-PSRepository -Name "$_" -InstallationPolicy Trusted
  }
}

# Package Provider (Requires PSGallery Trust)
"Nuget" | ForEach-Object -Process {
  Install-PackageProvider -Name "$_" -Scope CurrentUser -Force
}

# Modules (Requires Nuget)
"PowerShellGet",
"oh-my-posh","posh-git","Posh-SSH",
"PSScriptAnalyzer", "Pester", "Plaster",
"PSSudo" |
ForEach-Object -Process {
  if (-not (Get-Module -ListAvailable -Name "$_")) {
    Install-Module "$_" -Scope CurrentUser -Force -Confirm:$false
  }
}

# Winget
$winget = $(& winget --version)
If (-not ($winget))
{
  $appinstaller = $(Get-AppxPackage -Name "Microsoft.DesktopAppInstaller")
  If (-not ($appinstaller))
  {
    $Msix = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $Uri = "https://github.com/microsoft/winget-cli/releases/download/v1.0.11692/$Msix"
    Invoke-WebRequest -Uri $Uri -OutFile "$PWShell\$Msix"
    Add-AppxPackage -Path "$PWShell\$Msix"
    #Exit 1
  }
}

# Git
$UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
$GitInstalled = $(Get-ItemProperty $UninstallKey | Where-Object { $_.DisplayName -like "*Git*" })
If (-not ($GitInstalled)) {
  Start-Process "winget" -ArgumentList "install --id Git.Git --silent" -Wait -NoNewWindow
}

New-Item -Path "$env:HOMEPATH\.config" -ItemType Directory -Force
New-Item -Path "$env:HOMEPATH\.config\git" -ItemType Directory -Force
Copy-Item -Path "$PWShell\git-prompt.sh" "$env:HOMEPATH\.config\git\git-prompt.sh"
Copy-Item -Path "$PWShell\.bashrc" "$env:HOMEPATH\.bashrc"

# Fetch REPO
# Remove-Item -Path "$PWShell\.git" -Recurse -Force -ErrorAction SilentlyContinue
# BUG: "Remove-Item : Access to the cloud file is denied." This simply removes files recursively.
"$PWShell\.git" | ForEach-Object {
  Get-ChildItem -Recurse $_ -Force -File |
  ForEach-Object {
    Remove-Item $_.FullName -Force
  }
}

<# TODO Need to investigate this further, why does this environment var
cause git init to fail? Should I just (temporarily remove HOMEPATH)
Remove-Item Env:\HOMEPATH
-or #>
$GitRepo = "https://github.com/cgerke/WindowsPowerShell"
New-TemporaryFile | ForEach-Object {
  Remove-Item "$_" -Force -ErrorAction SilentlyContinue
  New-Item -Path "$_" -ItemType Directory -Force
  Set-Location -Path "$_"
  Set-Item -Path Env:HOME -Value $Env:USERPROFILE
  Start-Process "git" -ArgumentList "init" -Wait -NoNewWindow -WorkingDirectory "$_"
  Start-Process "git" -ArgumentList "remote add origin $GitRepo" -Wait -NoNewWindow -WorkingDirectory "$_"
  Start-Process "git" -ArgumentList "fetch --all" -Wait -NoNewWindow -WorkingDirectory "$_"
  Start-Process "git" -ArgumentList "checkout main" -Wait -NoNewWindow -WorkingDirectory "$_"
  Start-Process "git" -ArgumentList "push --set-upstream origin main" -Wait -NoNewWindow -WorkingDirectory "$_"
  Copy-Item -Path "$_\.git" -Destination "$PWShell\" -Recurse -Force
  Set-Location "$PWShell"
  Start-Process "git" -ArgumentList "reset --hard origin/main" -Wait -NoNewWindow -WorkingDirectory "$PWShell"
  Set-Location "$PSRoot"
  Set-Location "$PWShell"
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
}

# Windows Terminal
$WindowsTerminal = $(Get-AppxPackage -Name "Microsoft.WindowsTerminal")
$WTSettings = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
If (-not ($WindowsTerminal)) {
  Start-Process "winget" -ArgumentList "install --id Microsoft.WindowsTerminal --silent" -Wait -NoNewWindow
  Copy-Item -Path "$PWShell\settings.json" $WTSettings
}

# VSCode
$UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
$CodeInstalled = $(Get-ItemProperty $UninstallKey | Where-Object { $_.DisplayName -like "*Microsoft Visual Studio Code*" })
If (-not ($CodeInstalled)) {
  Start-Process "winget" -ArgumentList "install --id Microsoft.VisualStudioCode-User-x64 --silent" -Wait -NoNewWindow
}