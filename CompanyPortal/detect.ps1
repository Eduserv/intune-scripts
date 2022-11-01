    $ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if ($ResolveWingetPath){
               $WingetPath = $ResolveWingetPath[-1].Path
        }
    
    $Winget = $WingetPath + "\winget.exe"
    $wingettest = &$winget list --id 9WZDNCRFJ3PZ
    if ($wingettest -like "*9WZDNCRFJ3PZ*"){
        Write-Host "Found it!"
        exit 0
    } else {
        exit -1
    }
