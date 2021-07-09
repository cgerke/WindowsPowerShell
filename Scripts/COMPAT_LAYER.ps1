<# Some legacy apps are not compiled correctly, or they make use of unsigned drivers and certificates.
This may cause a UAC prompt even though the application doesn't actually require elevated permissions.
You can sometimes get around this by using a command to start your application with RunAsInvoker
#>
$Env:__COMPAT_LAYER='RunAsInvoker'; & '.\app.exe'