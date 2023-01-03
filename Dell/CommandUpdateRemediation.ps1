<#
 .SYNOPSIS
  Gets Password fro KeyVault and triggers Dell Command Update
 .DESCRIPTION
  Gets Password fro KeyVault and triggers Dell Command Update
 .EXAMPLE
  PS C:\> CommandUpdateRemediation.ps1
 .OUTPUTS
  0 Ok
  1 Error
 .PARAMETER TenantID
 Tenant ID for KeyVault
 .PARAMETER AppID
 KeyVault service principal AppID
 .PARAMETER Thumbprint
 Certificate Thumbprint to use
 .PARAMETER VaultName
 Keyvault Name
#>

[guid]$TenantID = ""
[guid]$AppID = ""
[string]$Thumbprint = ""
[string]$VaultName = ""

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

function Check-DellReturn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        $return
    )
    if ($return.length -gt 0) {
        if ($return[$return.length - 1] -ilike "*code: 0") {
            Write-Log -MessageType "INFO" -Message $return[$return.length - 3]
            Write-Log -MessageType "INFO" -Message $return[$return.length - 2]
            return $true
        } else {
            return $false
        }
    } else {
        return $false
    }
}

$Path_local = "$Env:Programfiles\_MEM"
Start-Transcript -Path "$Path_local\Log\DellCommandUpdateRemediation.log" -Force -Append

$DCU = "$Env:Programfiles\Dell\CommandUpdate\dcu-cli.exe"
$foundDCU = $true
if (!Test-Path $DCU) {
    $DCU = "${Env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe"
    if (!Test-Path $DCU) {
        Write-Log -MessageType "ERROR" -Message "Dell Command | Update is not installed, cancelling"
        Write-Error "Command Update Missing"
        Stop-Transcript
        $foundDCU = $false
        Exit 1
    }
}

if ($foundDCU) {
    $Get_Manufacturer_Info = (Get-WmiObject win32_computersystem).Manufacturer
    $Get_Device_Name = (Get-WmiObject win32_computersystem).Name
    Write-Log -MessageType "INFO" -Message "Manufacturer is: $Get_Manufacturer_Info"

    if (($Get_Manufacturer_Info -notlike "*Dell*")) {
        Write-Log -MessageType "ERROR" -Message "Device manufacturer not supported"
        Break
        Write-Error "Device manufacturer not supported"
        Stop-Transcript
        EXIT 1
    }

    
    Write-Log -MessageType "INFO" -Message "Checking to see if the cert is installed"
    try {
        Get-ChildItem -Path "cert://localmachine/my/$Thumbprint"
        Write-Log -MessageType "SUCCESS" -Message "Certificate with Thumbprint $Thumbprint is on this device"
    }
    catch {
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
        }
        catch {
            Write-Log -MessageType "ERROR" -Message "An issue occured while installing package Nuget"
            Write-Error "Error installing nuget package provider"
            Exit 1
        }
    }

    $Modules = @("Az.accounts", "Az.KeyVault")
    $InstalledModules = Get-InstalledModule
    foreach ($Module_Name in $Modules) {
        if (($InstalledModules | Where-Object Name -eq $Module_Name).Length -eq 0) { 
            Write-Log -MessageType "INFO" -Message "The module $Module_Name has not been found"
            try {
                Write-Log -MessageType "INFO" -Message "The module $Module_Name is being installed"
                Install-Module $Module_Name -Force -Confirm:$False -AllowClobber -ErrorAction SilentlyContinue -Scope AllUsers | out-null
                Write-Log -MessageType "SUCCESS" -Message "The module $Module_Name has been installed"
                Write-Log -MessageType "INFO" -Message "AZ.Accounts version $Module_Version"
                Import-Module $Module_Name -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log -MessageType "ERROR" -Message "The module $Module_Name has not been installed"
                Stop-Transcript
                EXIT 1
            }
        }
        else {
            try {
                Write-Log -MessageType "INFO" -Message "The module $Module_Name has been found"
                Import-Module $Module_Name -Force -ErrorAction SilentlyContinue
                Write-Log -MessageType "INFO" -Message "The module $Module_Name has been imported"
            }
            catch {
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

    Write-Log -MessageType "INFO" -Message "Checking if password is set"
    $module_name = "DellBIOSProvider"
    if (($InstalledModules | Where-Object Name -eq $module_name).Length -gt 0) {
        Update-Module $Module_Name -Force -Confirm:$false -Scope AllUsers
        Import-Module $module_name -Force
        Write-Log -MessageType "INFO" -Message "Module $module_name imported"	
    }
    else {
        Write-Log -MessageType "INFO" -Message "Module $module_name not installed"
        try {
            Install-Module -Name $module_name -Force -Confirm:$false -Scope AllUsers
            Import-Module -Name $module_name -Force
            Write-Log -MessageType "INFO" -Message "Module $module_name has been installed"
        }
        catch {
            Write-Log -MessageType "ERROR" -Message "Error importing module $module_name"
            Write-Error $Error
            Stop-Transcript
            Exit 1
        }
    }

    $IsPasswordSet = (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).currentvalue 	

    if (($IsPasswordSet -eq 1) -or ($IsPasswordSet -eq "true") -or ($IsPasswordSet -eq 2)) {
        Write-Log -MessageType "INFO" -Message "BIOS Password is Set - getting current password from KeyVault"
   
        try {
            Write-Log -MessageType "INFO" -Message "Connecting to your Azure application"
            Connect-AzAccount -tenantid $TenantID.ToString() -ApplicationId $AppID.ToString() -CertificateThumbprint $Thumbprint
            Write-Log -MessageType "SUCCESS" -Message "Connection OK to your Azure application"
        }
        catch {
            Write-Log -MessageType "ERROR" -Message "Connection to to your Azure application"
            Write-Error "FAILED to connect to your Azure application"
            Stop-Transcript
            EXIT 1
        }
        try {
            Write-Log -MessageType "INFO" -Message "Getting BIOS Password from Vault"
            $key = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $Get_Device_Name -AsPlainText
        } catch {
            Write-Log -MessageType "ERROR" -Message "Getting BIOS Password from Vault"
            Write-Error "FAILED to get BIOS password from Vault"
            Stop-Transcript
            EXIT 1
        }
        Write-Log -MessageType "INFO" -Message "Setting Dell Command | Update to use BIOS Password"
        $return = & $DCU /configure -biosPassword "$key"
        if (!(Check-DellReturn -return $return)) {
            
        }

    } else {
        Write-Log -MessageType "ERROR" -Message "BIOS Password Not Set"
    }
    Write-Log -MessageType "INFO" -Message "SETTING Dell Command Update to Auto Updates"
    & $DCU /configure -scheduleAuto -scheduleAction=DownloadInstallAndNotify

    & $DCU /applyUpdates

    Write-Log -MessageType "SUCCESS" -Message "Triggerd Dell Command Update to apply updates"

    Exit 0
}