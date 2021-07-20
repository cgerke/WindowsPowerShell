# Profile loop via registry
$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
$ProfileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
    Where-Object {$_.PSChildName -match $PatternSID} |
    Select-Object  @{name="SID";expression={$_.PSChildName}},
        @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}},
        @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}

Foreach ($UserProfile in $ProfileList) {
    # Load User ntuser.dat if it's not already loaded
    if ($UserProfile.Username -notmatch '^defaultuser0$|^.*administrator$') {
        $UserProfile.Username
        $UserProfile.SID
    }
}