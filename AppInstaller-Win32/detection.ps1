if ((Get-AppxPackage "Microsoft.DesktopApp*").Length -gt 0) {
    Write-Host "Found it!"
    return 0
} else {
    return -1
}