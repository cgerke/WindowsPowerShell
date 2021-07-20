# Repair the store
Get-AppXPackage *WindowsStore* -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
Get-Appxpackage –Allusers -Name Microsoft.MPEG2VideoExtension_1.0.22661.0_x64__8wekyb3d8bbwe
Add-AppxPackage -register "C:\Program Files\WindowsApps\Microsoft.MPEG2VideoExtension_1.0.22661.0_x64__8wekyb3d8bbwe" –DisableDevelopmentMode
Get-AppxPackage -allusers Microsoft.WindowsStore | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}

