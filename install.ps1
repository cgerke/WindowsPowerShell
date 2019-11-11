<#
.Synopsis
  Setup WindowsPowerShell $profile on Windows
.DESCRIPTION
  Invoke-Expression $(Invoke-WebRequest https://raw.githubusercontent.com/cgerke/WindowsPowerShell/master/install.ps1)
#>

# Repositories
"PSGallery" | ForEach-Object -process {
  if (-not (Get-PSRepository -Name "$_")) {
    # Example verbose parameter if I want to invoke the install.ps1 script silently later on.
    #Set-PSRepository -Name "$_" -InstallationPolicy Trusted -Verbose:($PSBoundParameters['Verbose'] -eq $true)
    Set-PSRepository -Name "$_" -InstallationPolicy Trusted -Verbose
  }
}

# Package Provider
"Nuget" | ForEach-Object -process {
   Install-PackageProvider -Name "$_" -Scope CurrentUser -Force -Verbose
}

# Modules
"PowerShellGet","posh-git","PSScriptAnalyzer","Plaster","PSSudo" | ForEach-Object -process {
  if (-not (Get-Module -ListAvailable -Name "$_")) {
    Install-Module "$_" -Scope CurrentUser -Force -Confirm:$false -Verbose
  }
}

# Git
If (-not $env:PATH.contains("Git")) {
  (Invoke-RestMethod https://api.github.com/repos/git-for-windows/git/releases/latest).assets |
    ForEach-Object -process {
    if ($_.name -match 'Git-.*-64-bit\.exe') {
      $url = $_.browser_download_url
      $tmp = New-TemporaryFile
      Invoke-WebRequest -Uri $url -OutFile "$tmp.exe" -Verbose
      Start-Process -Wait "$tmp.exe" -ArgumentList /silent -Verbose
    }
  }
}

# Chocolatey
# $InstallDir='C:\ProgramData\chocoportable'
# $env:ChocolateyInstall="$InstallDir"
# Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Fetch REPO
$PSRoot = Split-Path ((Get-Item $profile).DirectoryName) -Parent
Remove-Item -Path "$PSRoot\WindowsPowerShell\.git" -Recurse -Force -Verbose -ErrorAction SilentlyContinue

<# TODO Need to investigate this further, why does this environment var
cause git init to fail? Should I just (temporarily remove HOMEPATH)
Remove-Item Env:\HOMEPATH
-or #>
New-TemporaryFile | ForEach-Object {
  Remove-Item "$_" -Force -Verbose
  New-Item -Path "$_" -ItemType Directory -Force -Verbose
  Set-Location "$_"
  Set-Item -Path Env:HOME -Value $Env:USERPROFILE
  Start-Process "git" -ArgumentList "init" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "remote add origin https://github.com/cgerke/WindowsPowerShell" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "fetch --all" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "checkout master" -Wait -NoNewWindow
  Start-Process "git" -ArgumentList "push --set-upstream origin master" -Wait -NoNewWindow
  Move-Item -Path .\.git -Destination "$PSRoot\WindowsPowerShell\" -Force -Verbose
  Set-Location "$PSRoot\WindowsPowerShell\"
  Start-Process "git" -ArgumentList "reset --hard origin/master" -Wait -NoNewWindow
}

<# One profile to rule them all? This is annoying though, have to elevate
 to create symoblic links.

New-Item -ItemType SymbolicLink `
  -Path "$PSRoot\PowerShell" `
  -Name "Microsoft.PowerShell_profile.ps1" `
  -Target "$PSRoot\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
#>
