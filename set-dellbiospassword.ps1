<#PSScriptInfo
.VERSION 1.0.0
.GUID ed7e27b6-e0c5-4125-b3a5-336d13931ba1
.AUTHOR Nick Brown
.DESCRIPTION Sets the BIOS Password on Dell Devices
.COMPANYNAME Jisc
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment dell bios
.PROJECTURI https://github.com/Eduserv/intune-scripts
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#Requires -Module DellBIOSProvider
#>
<#
.SYNOPSIS
Creates and sets a BIOS password based on the service tag
.DESCRIPTION
.Creates and sets a BIOS password based on the service tag
.INPUTS
Seed key
.OUTPUTS
In-Line Outputs
.EXAMPLE
N/A
#>
      
param
(
    [Parameter(Mandatory=$true)][string]$Seed,
    [int]$Length=14,
    [string]$OldBIOSPWD
)

##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path "$($env:TEMP)\dell-bios-$date.log"

$DetectionRegPath = "HKLM:\SOFTWARE\Dell"
$DetectionRegName = "PasswordSet"

$Dsregcmd = New-Object PSObject ; Dsregcmd /status | Where-Object {$_ -match ' : '} `
    | ForEach-Object {
        $Item = $_.Trim() -split '\s:\s'
        $Dsregcmd | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]','') -Value $Item[1] -EA SilentlyContinue
}
$tag = $((Get-Item -Path DellSmbios:\SystemInformation\SvcTag).CurrentValue)
$fullseed = "$($Dsregcmd.TenantId)$tag$($Dsregcmd.TenantName)"
$fullseed = "$fullseed$fullseed$fullseed"

$NewPassword = ""

$tseed = "$Seed$tag"
$boolrev = $true
while ($tseed.Length -lt $Length) {
    if ($boolrev) {
        $tseed += -join [Array]::Reverse("$Seed$tag".ToCharArray())
        $boolrev = $false
    } else {
        $tseed += "$Seed$tag"
        $boolrev = $true
    }
}

foreach ($i in 0..($Length - 1)) {
    $lookup = ([int]([byte]($tseed[$i])));
    while ($lookup -gt $fullseed.Length) {
        Write-Verbose "Lookup too large, div 2 $([Math]::Floor($lookup / 2))"
        $lookup = [Math]::Floor($lookup / 2)
    }
    $NewPassword += $($fullseed[$lookup])
}

$IsAdminPassSet = (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).CurrentValue
 
if ($IsAdminPassSet -eq $false) {
    Write-Output "Admin password is not set at this moment, will try to set it."
    Set-Item -Path DellSmbios:\Security\AdminPassword "$NewPassword"
    if ( (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).CurrentValue -eq $true ){
        Write-Output "Admin password has now been set."
        New-ItemProperty -Path "$DetectionRegPath" -Name "$DetectionRegName" -Value 1 | Out-Null
    }
}
else {
    Write-Output "Admin password is already set"
    if ($null -eq $OldBIOSPWD) {
        Write-Output "`$OldPassword variable has not been specified, will not attempt to change admin password"
 
    }
    else {
        Write-Output "`$OldBIOSPWD variable has been specified, will try to change the admin password"
        Set-Item -Path DellSmbios:\Security\AdminPassword "$NewPassword" -Password "$OldBIOSPWD"
        New-ItemProperty -Path "$DetectionRegPath" -Name "$DetectionRegName" -Value 1 | Out-Null
    }
}

Stop-Transcript