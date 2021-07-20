# do not remember last logged in user
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnDisplayName /f"
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnSAMUser /f"
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnUser /f"
# /node:HOSTNAME process call create "reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v LastLoggedOnUserSID /f"