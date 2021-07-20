# All BIOS
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings"

# Thunderbolt
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings where InstanceName='ACPI\\PNP0C14\\0_73'"
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings where InstanceName='ACPI\\PNP0C14\\0_74'"
Get-WmiObject -NameSpace "root\wmi" -Query "SELECT * FROM QueryBiosSettings where InstanceName='ACPI\\PNP0C14\\0_75'"

