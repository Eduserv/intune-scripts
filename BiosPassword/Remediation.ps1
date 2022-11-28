<#
 .SYNOPSIS
  Generates, sets and stores the BIOS password in keyvault
 .DESCRIPTION
  Generates, sets and stores the BIOS password in keyvault ensure you set the params
 .EXAMPLE
  PS C:\> Remediation.ps1
    BIOS Password SetW
 .OUTPUTS
  0 BIOS Password Set
  1 BIOS Password Not Set
 .PARAMETER TenantID
 Tenant ID for KeyVault
 .PARAMETER AppID
 KeyVault service principal AppID
 .PARAMETER Thumbprint
 Certificate Thumbprint to use
 .PARAMETER VaultName
 Keyvault Name
#>

[guid]$TenantID=""
[guid]$AppID=""
[string]$Thumbprint=""
[string]$VaultName=""

#Make sure you set the above variables before uploading to intune!!!!!!

if ($AppID -eq "" -or $TenantID -eq "" -or $Thumbprint -eq "" -or $VaultName -eq "") {
    Write-Error "Parameter(s) missing"
    exit 1
    throw "Parameter(s) missing"
}

function Write-Log {
    param(
        $MessageType,
        $Message
    )

    $MyDate = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    Write-Host  "$MyDate - $MessageType : $Message"
}

function Get-Random {
    $ascii=$NULL;
    For ($a=33;$a –le 126;$a++) {
        $ascii+=,[char][byte]$a 
    }
    
    $length = 9
    
    For ($loop=1; $loop –le $length; $loop++) {
        $TempPassword+=($sourcedata | Get-Random)
    }
    
    return $TempPassword
}
$Path_local = "$Env:Programfiles\_MEM"
Start-Transcript -Path "$Path_local\Log\BiosRemediation.log" -Force -Append

Write-Log -MessageType "INFO" -Message "Checking to see if the cert is installed"
try {
    Get-ChildItem -Path "cert://localmachine/my/$Thumbprint"
    Write-Log -MessageType "SUCCESS" -Message "Certificate with Thumbprint $Thumbprint is on this device"
} catch {
    Write-Log -MessageType "ERROR" -Message "Certificate not installed"
    Stop-Transcript
    EXIT 1
}

if (!(Get-PackageProvider | Where-Object Name -eq "Nuget")) {			
    Write-Log -MessageType "INFO" -Message "The package Nuget is not installed"							
    try {
        Write-Log -MessageType "INFO" -Message "The package Nuget is being installed"						
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Force -Confirm:$False | out-null								
        Write-Log -MessageType "SUCCESS" -Message "The package Nuget has been successfully installed"	
    } catch {
        Write-Log -MessageType "ERROR" -Message "An issue occured while installing package Nuget"
        Write-Error "Error installing nuget package provider"
        Exit 1
    }
}

$Modules = @("Az.accounts", "Az.KeyVault")
foreach ($Module_Name in $Modules) {
    if (!(Get-InstalledModule $Module_Name)) { 
        Write-Log -MessageType "INFO" -Message "The module $Module_Name has not been found"
        try {
            Write-Log -MessageType "INFO" -Message "The module $Module_Name is being installed"
            Install-Module $Module_Name -Force -Confirm:$False -AllowClobber -ErrorAction SilentlyContinue | out-null
            Write-Log -MessageType "SUCCESS" -Message "The module $Module_Name has been installed"
            Write-Log -MessageType "INFO" -Message "AZ.Accounts version $Module_Version"
        } catch {
            Write-Log -MessageType "ERROR" -Message "The module $Module_Name has not been installed"
            Stop-Transcript
            EXIT 1
        }
    } else {
        try {
            Write-Log -MessageType "INFO" -Message "The module $Module_Name has been found"
            Import-Module $Module_Name -Force -ErrorAction SilentlyContinue
            Write-Log -MessageType "INFO" -Message "The module $Module_Name has been imported"
        } catch {
            Write-Log -MessageType "ERROR" -Message "The module $Module_Name has not been imported"
            Write-Host "The module $Module_Name has not been imported"
            Stop-Transcript
            EXIT 1
        }
    }
}

if ((Get-Module "Az.accounts" -listavailable) -and (Get-Module "Az.KeyVault" -listavailable)) {
    Write-Log -MessageType "INFO" -Message "Both modules are there"
}

try {
    Write-Log -MessageType "INFO" -Message "Connecting to your Azure application"
    Connect-AzAccount -tenantid $TenantID.ToString() -ApplicationId $AppID.ToString() -CertificateThumbprint $Thumbprint | Out-null
    Write-Log -MessageType "SUCCESS" -Message "Connection OK to your Azure application"
} catch {
    Write-Log -MessageType "ERROR" -Message "Connection to to your Azure application"
    Write-Error "FAILED to connect to your Azure application"
    Stop-Transcript
    EXIT 1
}

$Get_Manufacturer_Info = (gwmi win32_computersystem).Manufacturer
$Get_Device_Name = (gwmi win32_computersystem).Name
Write-Log -MessageType "INFO" -Message "Manufacturer is: $Get_Manufacturer_Info"

if (($Get_Manufacturer_Info -notlike "*HP*") -and ($Get_Manufacturer_Info -notlike "*Lenovo*") -and ($Get_Manufacturer_Info -notlike "*Dell*")) {
    Write-Log -MessageType "ERROR" -Message "Device manufacturer not supported"
    Break
    Write-Error "Device manufacturer not supported"
    Stop-Transcript
    EXIT 1
}

if ($Get_Manufacturer_Info -like "*Lenovo*") {
    $IsPasswordSet = (gwmi -Class Lenovo_BiosPasswordSettings -Namespace root\wmi).PasswordState
}
elseif ($Get_Manufacturer_Info -like "*HP*") {
    $IsPasswordSet = (Get-WmiObject -Namespace root/hp/instrumentedBIOS -Class HP_BIOSSetting | Where-Object Name -eq "Setup password").IsSet
} 
elseif ($Get_Manufacturer_Info -like "*Dell*") {
    $module_name = "DellBIOSProvider"
    if (Get-InstalledModule -Name DellBIOSProvider) { import-module DellBIOSProvider -Force }
    else { Install-Module -Name DellBIOSProvider -Force }
    $IsPasswordSet = (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).currentvalue
} 

if (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq "true") -or ($IsPasswordSet -eq 2)) {
    Write-Error -MessageType "ERROR" -Message "There is a current BIOS password"
    Stop-Transcript
    Exit 1
}

$password = Get-Random
$secretvalue = ConvertTo-SecureString $password -AsPlainText -Force

if ($Get_Manufacturer_Info -like "*HP*") {
    Write-Log -MessageType "INFO" -Message "Changing BIOS password for HP"
    try {
        $bios = Get-WmiObject -Namespace root/hp/instrumentedBIOS -Class HP_BIOSSettingInterface
        $bios.SetBIOSSetting("Setup Password", "<utf-16/>" + $password, "<utf-16/>")
        Write-Log -MessageType "SUCCESS" -Message "BIOS password has been changed"
        Set-AzKeyVaultSecret -VaultName $VaultName -Name $Get_Device_Name -SecretValue $secretvalue
        Write-Log -MessageType "SUCCESS" -Message "Password sync'd to keyvault"
        Stop-Transcript
        EXIT 0
    } catch {
        Write-Log -MessageType "ERROR" -Message "BIOS password has not been changed"
        Write-Error "Change password: Failed"
        Stop-Transcript
        EXIT 1
    }
} elseif ($Get_Manufacturer_Info -like "*Lenovo*") {
    Write-Log -MessageType "INFO" -Message "Changing BIOS password for Lenovo"
    try {
        $PasswordSet = Get-WmiObject -Namespace root\wmi -Class Lenovo_SetBiosPassword
        $PasswordSet.SetBiosPassword("pap,"",$password,ascii,us") | out-null
        Write-Log -MessageType "SUCCESS" -Message "BIOS password has been changed"
        Set-AzKeyVaultSecret -VaultName $VaultName -Name $Get_Device_Name -SecretValue $secretvalue
        Write-Log -MessageType "SUCCESS" -Message "Password sync'd to keyvault"
        Stop-Transcript
        EXIT 0
    } catch {
        Write-Log -MessageType "ERROR" -Message "BIOS password has not been changed"
        Write-Error "Change password: Failed"
        Stop-Transcript		
        EXIT 1
    }
} elseif ($Get_Manufacturer_Info -like "*Dell*") {
    Write-Log -MessageType "INFO" -Message "Changing BIOS password for HP"
    try {
        Set-Item -Path DellSmbios:\Security\AdminPassword "$AdminPwd"
        Write-Log -MessageType "SUCCESS" -Message "BIOS password has been changed"		
        Write-Host "Change password: Success"			
        Set-AzKeyVaultSecret -VaultName $VaultName -Name $Get_Device_Name -SecretValue $secretvalue
        Write-Host "Password saved to Keyvault"
        Stop-Transcript
        EXIT 0
    } catch {
        Write-Log -MessageType "ERROR" -Message "BIOS password has not been changed"
        Write-Error "Change password: Failed"
        Stop-Transcript
        EXIT 1
    }
}