#consuming json
$json = Join-Path -Path $PSDirectory -ChildPath "Microsoft.PowerShell_options.json"
if ( Test-Path -path $json ) {
    $Defaults = Get-Content $json | ConvertFrom-Json
    #$JsonObject.Defaults[0]
    #$Defaults.AdminAccount[0].Username
}