# User context Domain/Workgroup, but this assume Workgroup is WORKGROUP so make this smarter
$DomainObj = switch ((Get-WmiObject Win32_ComputerSystem).Domain) {
    "WORKGROUP" { (Get-WmiObject Win32_ComputerSystem).Name } default { (Get-WmiObject Win32_ComputerSystem).Domain }
}
$PshAs = "$DomainObj\cgerke"
