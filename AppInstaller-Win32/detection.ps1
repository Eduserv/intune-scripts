if ((Get-AppxPackage "Microsoft.DesktopApp*").Length -gt 0) {
    Write-Host "Found it!"
    exit 0
} else {
    exit -1
}