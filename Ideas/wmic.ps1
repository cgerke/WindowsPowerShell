wmic /node:computer process call create 'tskill chrome'



# plan b
# /node:HOSTNAME process call create "msiexec /i C:\temp\installer.msi /qn"
# /node:HOSTNAME process call create "MsiExec.exe /X{A728AD51-72D5-4992-8367-91E7CF686604}"
# /node:HOSTNAME process call create "'C:\Program Files (x86)\xxxx\xxxx.exe' --something --somethingelse"
# /node:HOSTNAME process list
# /node:HOSTNAME process call create "wevtutil epl System C:\temp\system.evtx"


