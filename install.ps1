<#
.Synopsis
  Setup WindowsPowerShell $profile on Windows
.DESCRIPTION
  Invoke-Expression $(Invoke-WebRequest https://raw.githubusercontent.com/cgerke/WindowsPowerShell/master/install.ps1)
#>

# Setup $profile
$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
Set-Location "$PSRoot\" -ErrorAction Stop
New-Item -Path "$PSRoot\WindowsPowerShell" -ItemType Directory -Force
Set-Location "$PSRoot\WindowsPowerShell" -ErrorAction Stop

# Repositories
"PSGallery" | ForEach-Object -process {
  if (-not (Get-PSRepository -Name "$_")) {
    Set-PSRepository -Name "$_" -InstallationPolicy Trusted -Verbose
  }
}

# Modules
"PowerShellGet","posh-git" | ForEach-Object -process {
  if (-not (Get-Module -ListAvailable -Name "$_")) {
    Install-Module "$_" -Scope CurrentUser -Force -Confirm:$false -Verbose
  }
}

# Git
If (-not $env:PATH.contains("Git")) {
  (Invoke-RestMethod https://api.github.com/repos/git-for-windows/git/releases/latest).assets |
    ForEach-Object -process {
    if ($_.name -match 'Git-\d*\.\d*\.\d*-64-bit\.exe') {
      $url = $_.browser_download_url
      $tmp = New-TemporaryFile
      Invoke-WebRequest -Uri $url -OutFile "$tmp.exe" -Verbose
      Start-Process -Wait "$tmp.exe" -ArgumentList /silent -Verbose
    }
  }
}

# Fetch REPO
# Avoid Remove-Item issues.
New-TemporaryFile | ForEach-Object {
  Remove-Item "$_" -Force -Verbose
  New-Item -Path "$_" -ItemType Directory -Force -Verbose
  Move-Item -Path .\.git -Destination "$_\" -Force -Verbose
}

<# TODO Need to investigate this further, why does this environment var
cause git init to fail? Should I just (temporarily remove HOMEPATH)
Remove-Item Env:\HOMEPATH
-or #>
Set-Item -Path Env:HOME -Value $Env:USERPROFILE
& git init
& git remote add origin https://github.com/cgerke/WindowsPowerShell
& git fetch --all
& git reset --hard origin/master
& git checkout master
& git push --set-upstream origin master

<# One profile to rule them all? This is annoying though, have to elevate
 to create symoblic links.

New-Item -ItemType SymbolicLink `
  -Path "$PSRoot\PowerShell" `
  -Name "Microsoft.PowerShell_profile.ps1" `
  -Target "$PSRoot\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
#>