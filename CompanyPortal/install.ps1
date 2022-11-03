    $ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if ($ResolveWingetPath){
               $WingetPath = $ResolveWingetPath[-1].Path
        }
    
    $Winget = $WingetPath + "\winget.exe"
    . $winget install --id 9WZDNCRFJ3PZ --silent --force --accept-package-agreements --accept-source-agreements
