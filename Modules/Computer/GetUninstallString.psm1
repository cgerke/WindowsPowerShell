#requires -version 3.0
function Get-UninstallString
{
    <#
  .SYNOPSIS
    Software uninstall strings
  .DESCRIPTION
    Retrieve uninstall strings from a computer.
  .EXAMPLE
    Get-UninstallString -Computer $hostname
  .EXAMPLE
    Get-UninstallString -Computer $hostname -credential domain\administrator -includeUsers
  #>

    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias("cn")]
        [ValidateNotNullorEmpty()]
        [string]$Computername = $env:computername,
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        [switch]$IncludeUsers
    )

    Begin
    {
        Write-Verbose -Message "Starting $($MyInvocation.Mycommand)"
        $HKEY_USERS = 2147483651
        $HKLM = 2147483650
        $rpaths = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

        $progParam = @{
            Activity         = $MyInvocation.MyCommand
            Status           = "Starting"
            CurrentOperation = ""
            PercentComplete  = 0
        }

    } #begin

    Process
    {
        Write-Verbose "Creating CIMSession to $computername"

        $progParam.CurrentOperation = "Creating CIMSession to $computername"

        Write-Progress @progParam

        #initialize $data
        $data = @()

        Try
        {
            $ncsParams = @{
                ComputerName = $computername
                ErrorAction  = "Stop"
            }
            if ($Credential.UserName)
            {
                $ncsParams.Add("Credential", $Credential)
            }

            $progparam.currentOperation = "Creating CIM session and class objects"
            Write-Progress @progParam

            $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
            $cs = New-CimSession @ncsParams -SessionOption $CimSessionOption
            $regcim = Get-CimClass -Namespace root\default -class StdRegProv -CimSession $cs

        }
        Catch
        {
            Write-Warning "There was a problem creating a CIMSession to $computername"
            Throw
        }

        foreach ($rpath in $rpaths)
        {
            Write-Verbose "Querying $rpath"
            $progParam.Status = "Querying $rpath"
            $progParam.CurrentOperation = "EnumKey"
            Write-Progress @progParam

            $enumArgs = @{hDefKey = $HKLM; sSubKeyName = $rpath }

            $paramHash = @{
                cimclass   = $regcim
                CimSession = $cs
                Name       = "EnumKey"
                Arguments  = $enumArgs
            }

            $mySnames = Invoke-CimMethod @paramHash | Select-Object -expand snames | Where-Object { $_ -notmatch '(\.)?KB\d+' }
            $i = 0
            $data += foreach ($item in $MySnames)
            {

                $i++
                $progParam.CurrentOperation = $_
                $progParam.Status = "EnumValues $rpath"
                $pct = ($i / $mySNames.count) * 100
                $progParam.PercentComplete = $pct
                Write-Progress @progParam

                $keyPath = "$rpath\$item"

                #revise paramhash
                $paramHash.Name = "EnumValues"
                $paramHash.Arguments = @{hDefKey = $HKLM; sSubKeyName = $keyPath }
                Invoke-CimMethod @paramHash | ForEach-Object {
                    #get value data
                    $hash = [ordered]@{Path = $KeyPath }

                    #add a list of known properties
                    "Displayname", "DisplayVersion", "Publisher",
                    "InstallDate", "InstallLocation", "Comments", "UninstallString" | ForEach-Object {

                        $paramHash.Name = "GetStringValue"
                        $paramhash.Arguments = @{hDefKey = $HKLM ; sSubKeyName = $KeyPath; sValueName = $_ }
                        $value = Invoke-CimMethod @paramhash
                        $hash.Add($_, $($value.sValue))
                    } #foreach property name

                    #write a custom object to the pipeline
                    [pscustomobject]$hash
                } #foreach subkey name

            } #foreach sname

        } #foreach rpath


        #get information from HKEY_USERS
        if ($IncludeUsers)
        {
            Write-Verbose "Getting data from HKEY_USERS"
            $progParam.Status = "Getting data from HKEY_USERS"

            $progParam.CurrentOperation = ""
            $progParam.PercentComplete = 0

            Write-Progress @progParam

            $enumArgs = @{hDefKey = $HKEY_USERS; sSubKeyName = "" }

            $CimSessionOption = New-CimSessionOption -Protocol "DCOM"
            $cs = New-CimSession @ncsParams -SessionOption $CimSessionOption
            $paramHash = @{
                cimclass   = $regcim
                CimSession = $cs
                Name       = "EnumKey"
                Arguments  = $enumArgs
            }

            #snames is the collection of user hives and filter out *Classes and .DEFAULT
            $snames = Invoke-CimMethod @paramhash | Select-Object -ExpandProperty sNames | Where-Object { $_ -notmatch "_Classes$" }

            $i = 0
            $data += foreach ($item in $snames)
            {
                $i++
                $pct = ($i / $snames.count) * 100
                $progParam.CurrentOperation = $item
                $progParam.PercentComplete = $pct

                Write-Progress @progParam

                $rpath = "$item\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                Write-Verbose "Checking $rpath"
                $paramHash.Arguments = @{hDefKey = $HKEY_USERS; sSubKeyName = $rpath }

                #get subkeys with defined sname values
                $mydata = Invoke-CimMethod @paramhash
                if ($mydata.snames)
                {
                    #only process if sname data discovered
                    $paramHash.Arguments = @{hDefKey = $HKEY_USERS; sSubKeyName = $rpath }

                    $appnames = Invoke-CimMethod @paramhash
                    if ($appnames.snames)
                    {
                        #resolve the SID using Get-WSManInstance
                        Write-Verbose "Resolving $item"
                        $WSManParamHash = @{
                            resourceURI  = "wmi/root/cimv2/Win32_SID?SID=$item"
                            computername = $cs.ComputerName
                            Credential   = $credential
                        }

                        $Resolve = Get-WSManInstance @WSManParamHash

                        if ($resolve.accountname)
                        {
                            $Username = "$($resolve.ReferencedDomainName)\$($resolve.AccountName)"
                        }
                        else
                        {
                            $Username = $item
                        }

                        #enumerate each sname which will be an application of some kind
                        foreach ($app in $appnames.sNames)
                        {
                            $hash = [ordered]@{Username = $Username; Path = $rpath }

                            Write-Verbose "Querying $rpath\$app"

                            #add a list of known properties
                            "Displayname", "DisplayVersion", "Publisher",
                            "InstallDate", "InstallLocation", "Comments", "UninstallString" | ForEach-Object {
                                $paramHash.Name = "GetStringValue"
                                $paramHash.Arguments = @{hDefKey = $HKEY_USERS; sSubKeyName = "$rpath\$app"; sValueName = $_ }
                                $value = Invoke-CimMethod @paramhash

                                $hash.Add($_, $value.svalue)
                            } #foreach property name
                            #write a custom object to the pipeline
                            [pscustomobject]$hash
                        } #foreach app

                    } #if appnames
                    #reset
                    Clear-Variable mydata
                } #if snames found

            } #foreach item in snames

        } #if users

        #write results to pipeline
        $data

        #clean up
        Write-Verbose "Removing CIMSession"

        $progParam.CurrentOperation = ""
        $progParam.Status = "Removing CIMSession"
        Write-Progress @progParam

        Remove-CimSession $cs

    } #process

    End
    {
        $progParam.Status = "Finished"
        Write-Progress @Progparam -Completed
        Write-Verbose -Message "Ending $($MyInvocation.Mycommand)"
    } #end

}