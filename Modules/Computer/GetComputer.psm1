function Get-Computer
{
    <#
  .SYNOPSIS
    System information
  .DESCRIPTION
    Retrieve system information from a computer.
  .EXAMPLE
    Get-Computer -Computer $hostname
  .EXAMPLE
    "$hostname","$hostname2" | Get-Computer
  #>
    Param(
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $true)]
        [string] $Computer
    )

    process
    {
        foreach ( $i in $Computer )
        {
            if (-not (Test-Connection -Quiet -ComputerName "$Computer" -Count 2))
            {
                Write-Information "$Computer appears to be offline" -InformationAction Continue
            }
            else
            {
                ### WinRM remoting by default
                ### Enable-PSRemoting -SkipNetworkProfileCheck -Force
                if (Test-WSMan -ComputerName $i -ErrorAction SilentlyContinue)
                {
                    Write-Information "WinRM available" -InformationAction Continue
                    $CimSession = New-CimSession -ComputerName $i
                }
                else
                {
                    Write-Information "Using DCOM as WinRM is not available" -InformationAction Continue
                    $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
                    $CimSession = New-CimSession -ComputerName $i -SessionOption $CimSessionOption
                }

                switch ((Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem).Version)
                {
                    10.0.19042 { $Version = "20H2" }
                    10.0.19041 { $Version = "2004" }
                    10.0.18362 { $Version = "1903" }
                    10.0.17763 { $Version = "1809" }
                    10.0.17134 { $Version = "1803" }
                    10.0.16299 { $Version = "1709" }
                    default { $Version = "N/A" }
                }

                $CIMcomsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem
                $CIMopsys = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem
                $CIMbios = Get-CimInstance -CimSession $CimSession -ClassName Win32_Bios
                $CIMcpu = Get-CimInstance -CimSession $CimSession -ClassName Win32_Processor
                $CIMdisk = Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
                $CIMmac = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $null -ne $_.MACAddress } | Select-Object Description, MACAddress
                $CIMHotFix = Get-CimInstance -CimSession $CimSession -ClassName Win32_QuickFixEngineering
                $TotalDiskSpace = [math]::round($CIMdisk.Size / 1GB, 0)
                $FreeDiskSpace = [math]::round($CIMdisk.FreeSpace / 1GB, 0)

                $ComputerObject = [PSCustomObject]@{
                    Name                   = $i
                    Manufacturer           = $CIMcomsys.Manufacturer
                    Model                  = $CIMcomsys.Model
                    Serial                 = $CIMbios.SerialNumber
                    CPU                    = $CIMcpu.Name
                    TotalDiskSpace         = "$TotalDiskSpace GB"
                    FreeDiskSpace          = "$FreeDiskSpace GB"
                    TotalPhysicalMemory    = "$([math]::round($CIMopsys.TotalVisibleMemorySize / 1MB, 0)) GB"
                    FreePhysicalMemory     = "$([math]::round($CIMopsys.FreePhysicalMemory/ 1MB, 0)) GB"
                    MacAddress             = $CIMmac
                    LastBootUpTime         = $CIMopsys.LastBootUpTime
                    LastBootUpTimeRelative = (Get-Date) - $CIMopsys.LastBootUpTime | Format-TimeSpan
                    OperatingSystem        = $CIMopsys.caption
                    Build                  = ((Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem).Version)
                    Version                = $Version
                    InstallDate            = $CIMopsys.InstallDate
                    HotFix                 = $CIMHotFix
                }
                Remove-CimSession -ComputerName $i

                return $ComputerObject
            }
        }
    }
}