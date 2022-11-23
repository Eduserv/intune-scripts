<#PSScriptInfo
.VERSION 1.0.0
.GUID e05c1158-13d9-4ad2-92d6-fda3e6cbdaad
.AUTHOR Nick Brown
.DESCRIPTION Updates all Dell Devices in the Tenant with their Warranty Info
.COMPANYNAME Jisc
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment winget win32
.PROJECTURI https://github.com/Eduserv/intune-scripts
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
 Sets extension attributes for the dell warranty info
.DESCRIPTION
.Searches Graph for devices from dell
.Updates those devices will dell's warranty info
.INPUTS
.OUTPUTS
In-Line Outputs
.EXAMPLE
N/A
#>
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
$path = "$($env:TEMP)\intune"
Start-Transcript -Path "$path\intune-$date.log"

Write-Host "Installing Intune modules if required (current user scope)"

#Install Graph Module if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "Graph Module Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
        exit
    }
}

Select-MgProfile beta
Connect-MgGraph -Scopes DeviceManagementManagedDevices.ReadWrite.All,Directory.ReadWrite.All

$devices = Get-MgDeviceManagementManagedDevice -Filter "manufacturer eq 'Dell Inc.'"

$i = 0

foreach ($device in $devices) {
    $i++
    Write-Progress "$i / $($devices.count) - Updating $($device.deviceName)" -PercentComplete ($i / $devices.Count * 100)
#    $warranty = Get-DellWarranty -ServiceTag $device.SerialNumber
#    Update-MgDevice -DeviceId $device.AzureActiveDirectoryDeviceId -ExtensionAttributes "{
#        `"extenstionAttribute5`": `"$($warranty.WarrantyDate)`"
#    }"
#    Write-Host "Updating $($device.DeviceName) with warranty info"
#    Write-Host $warranty
}

Disconnect-MgGraph

Stop-Transcript