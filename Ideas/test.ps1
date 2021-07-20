exit
function Set-Repository {
  Import-Module PowerShellGet
  $PsRepoPath = (Resolve-Path "C:\temp").ProviderPath
  $PsRepo = @{
    Name               = 'MyRepo'
    SourceLocation     = $PsRepoPath
    PublishLocation    = $PsRepoPath
    InstallationPolicy = 'Trusted'
  }
  Register-PSRepository @PsRepo
  Get-PSRepository
  Find-Module -Repository 'MyRepo' -Verbose
}

${function:~} = { Set-Location ~ }
${function:Get-Fun} = { Get-ChildItem function:\ | select-String "-" | ForEach-Object { Get-Help $_ } | Format-Table -Property Name, Synopsis }
${function:Reload-Powershell} = { & $profile }
${function:Set-ParentLocation} = { Set-Location .. }; Set-Alias ".." Set-ParentLocation
























