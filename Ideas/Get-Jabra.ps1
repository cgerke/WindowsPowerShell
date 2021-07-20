$File = "C:\Users\$env:UserName\AppData\Roaming\Jabra Direct\Devices.txt"
If ( Test-Path -Path $File ){
    $Hash = @{}
    [System.IO.File]::ReadLines($File) | ForEach-Object {
        If ( $_ | Select-String "Product Name:"){
            $k = $_.split(':')
        }
        If ( $_ | Select-String "Serial Number:"){
            $v = $_.split(':')
            $Hash = $Hash + @{$k[1] = $v[1] }
        }
    }

    $Hash
}