$PSPath = "$(Split-Path -Parent $PROFILE)"
$ModulePath = "$PSPath\Modules"
Invoke-Plaster -TemplatePath "$PSPath" -DestinationPath $ModulePath -Verbose