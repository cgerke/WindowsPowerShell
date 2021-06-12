# https://github.com/PowerShell/vscode-powershell/issues/742#issuecomment-301915916
#[System.Console]::OutputEncoding = [System.Text.Encoding]::ASCII
Import-Module -Name PSReadline -Version 2.0.0
Import-Module posh-git
Import-Module oh-my-posh
Set-Theme ys