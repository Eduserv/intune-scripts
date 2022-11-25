<#PSScriptInfo
.VERSION 1.0.0
.GUID cbdf1a2d-b197-4014-bf6e-0330242932b7
.AUTHOR Nick Brown
.DESCRIPTION Creates PowerShell Module apps, AAD groups and Proactive Remediations to keep apps updated
.COMPANYNAME Jisc
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment PSModule win32
.PROJECTURI https://github.com/Eduserv/intune-scripts
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#Requires -Module Microsoft.Graph.DeviceManagement
#Requires -Module Microsoft.Graph.Groups
#Requires -Module Microsoft.Graph
#>
<#
.SYNOPSIS
  Creates and uploads an app from PSGallery
.DESCRIPTION
.Searches all PSGallery modules and displays GridView output
.Creates Intunewin
.Creates AAD Groups
.Creates Proactive Remediations (for auto updates)
.Uploads and assigns everything
.INPUTS
App ID and App name (from Gridview)
.OUTPUTS
In-Line Outputs
.EXAMPLE
N/A
#>
##########################################################################################

$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
$path = "$($env:TEMP)\intune"
Start-Transcript -Path "$path\intune-$date.log"

$intuneapputiloutput = "$path\IntuneWinAppUtil.exe"

if (!(Test-Path $intuneapputiloutput)) {
    Write-Host "Downloading IntuneWinAppUtil.exe"
    ##IntuneWinAppUtil
    $intuneapputilurl = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe"
    Invoke-WebRequest -Uri $intuneapputilurl -OutFile $intuneapputiloutput | Out-Null
}
###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################
function Add-MDMApplication() {

    <#
        .SYNOPSIS
        This function is used to add an MDM application using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds an MDM application from the itunes store
        .EXAMPLE
        Add-MDMApplication -JSON $JSON
        Adds an application into Intune
        .NOTES
        NAME: Add-MDMApplication
        #>
        
    [cmdletbinding()]
        
    param
    (
        $JSON
    )
        
    try {
        
        if (!$JSON) {
        
            Write-Error "No JSON was passed to the function, provide a JSON variable"
            break
        
        }
        
        Test-JSON -JSON $JSON

        New-MgDeviceAppManagementMobileApp -BodyParameter $JSON        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Debug "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"

        break
        
    }
        
}
        
####################################################
        
Function Add-ApplicationAssignment() {
        
    <#
        .SYNOPSIS
        This function is used to add an application assignment using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds a application assignment
        .EXAMPLE
        Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
        Adds an application assignment in Intune
        .NOTES
        NAME: Add-ApplicationAssignment
        #>
        
    [cmdletbinding()]
        
    param
    (
        $ApplicationId,
        $TargetGroupId,
        $InstallIntent
    )
            
    try {
        
        if (!$ApplicationId) {
        
            Write-Error "No Application Id specified, specify a valid Application Id"
            break
        
        }
        
        if (!$TargetGroupId) {
        
            Write-Error "No Target Group Id specified, specify a valid Target Group Id"
            break
        
        }
        
                
        if (!$InstallIntent) {
        
            Write-Error "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment"
            break
        
        }
        
        $JSON = @"
        {
            "mobileAppAssignments": [
            {
                "@odata.type": "#microsoft.graph.mobileAppAssignment",
                "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$TargetGroupId"
                },
                "intent": "$InstallIntent"
            }
            ]
        }
"@
        New-MgDeviceAppManagementMobileAppAssignment -BodyParameter $JSON
        
    }
            
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Debug "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        break
        
    }
        
}
        
        
function CloneObject($object) {
        
    $stream = New-Object IO.MemoryStream
    $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter
    $formatter.Serialize($stream, $object)
    $stream.Position = 0
    $formatter.Deserialize($stream)
}
        
####################################################
        
function UploadAzureStorageChunk($sasUri, $id, $body) {
        
    $uri = "$sasUri&comp=block&blockid=$id"
    $request = "PUT $uri"
        
    $iso = [System.Text.Encoding]::GetEncoding("iso-8859-1")
    $encodedBody = $iso.GetString($body)
    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    }
        
    if ($logRequestUris) { Write-Verbose $request }
    if ($logHeaders) { WriteHeaders $headers }
        
    try {
        Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody
    }
    catch {
        Write-Error $request
        Write-Error $_.Exception.Message
        throw
    }
        
}
        
####################################################
        
function FinalizeAzureStorageUpload($sasUri, $ids) {
        
    $uri = "$sasUri&comp=blocklist"
    $request = "PUT $uri"
        
    $xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
    foreach ($id in $ids) {
        $xml += "<Latest>$id</Latest>"
    }
    $xml += '</BlockList>'
        
    if ($logRequestUris) { Write-Verbose $request }
    if ($logContent) { Write-Verbose $xml }
        
    try {
        Invoke-RestMethod $uri -Method Put -Body $xml
    }
    catch {
        Write-Error $request
        Write-Error $_.Exception.Message
        throw
    }
}
        
####################################################
        
function UploadFileToAzureStorage($sasUri, $filepath, $fileUri) {
        
    try {
        
        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb
                
        # Start the timer for SAS URI renewal.
        $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
                
        # Find the file size and open the file.
        $fileSize = (Get-Item $filepath).length
        $chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes)
        $reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open))
        $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin)
                
        # Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
        $ids = @()
        
        for ($chunk = 0; $chunk -lt $chunks; $chunk++) {
        
            $id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")))
            $ids += $id
        
            $start = $chunk * $chunkSizeInBytes
            $length = [Math]::Min($chunkSizeInBytes, $fileSize - $start)
            $bytes = $reader.ReadBytes($length)
                    
            $currentChunk = $chunk + 1			
        
            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
                -percentComplete ($currentChunk / $chunks * 100)
        
            UploadAzureStorageChunk $sasUri $id $bytes
                    
            # Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
            if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000) {
        
                RenewAzureStorageUpload $fileUri
                $sasRenewalTimer.Restart()
                    
            }
        
        }
        
        Write-Progress -Completed -Activity "Uploading File to Azure Storage"
        
        $reader.Close()
        
    }
        
    finally {
        
        if ($null -ne $reader) { $reader.Dispose() }
            
    }
            
    # Finalize the upload.
    FinalizeAzureStorageUpload $sasUri $ids
        
}
        
####################################################
        
function RenewAzureStorageUpload($fileUri) {
        
    $renewalUri = "$fileUri/renewUpload"
    $actionBody = ""
    Invoke-MgGraphRequest -method POST -Uri $renewalUri -Body $actionBody
            
    Start-WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds
        
}
        
####################################################
        
function Start-WaitForFileProcessing($fileUri, $stage) {
    
    $attempts = 600
    $waitTimeInSeconds = 10
        
    $successState = "$($stage)Success"
    $pendingState = "$($stage)Pending"
        
    $file = $null
    while ($attempts -gt 0) {
        $file = Invoke-MgGraphRequest -Method GET -Uri $fileUri
        
        if ($file.uploadState -eq $successState) {
            break
        }
        elseif ($file.uploadState -ne $pendingState) {
            Write-Error $_.Exception.Message
            throw "File upload state is not success: $($file.uploadState)"
        }
        
        Start-Sleep $waitTimeInSeconds
        $attempts--
    }
        
    if ($null -eq $file -or $file.uploadState -ne $successState) {
        throw "File request did not complete in the allotted time."
    }
        
    $file
}
        
####################################################
        
function Get-Win32AppBody() {
        
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$publisher,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$description,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$filename,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,
        
        [parameter(Mandatory = $true)]
        [ValidateSet('system', 'user')]
        $installExperience,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $installCommandLine,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $uninstallCommandLine        
    )
    $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
    $body.description = $description
    $body.applicableArchitectures = "x64"
    $body.developer = ""
    $body.displayName = $displayName
    $body.fileName = $filename
    $body.installCommandLine = "$installCommandLine"
    $body.installExperience = @{"runAsAccount" = "$installExperience" }
    $body.informationUrl = $null
    $body.isFeatured = $false
    $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true }
    $body.notes = ""
    $body.owner = ""
    $body.privacyInformationUrl = $null
    $body.publisher = $publisher
    $body.runAs32bit = $false
    $body.setupFilePath = $SetupFileName
    $body.uninstallCommandLine = "$uninstallCommandLine"
        
    $body
}
        
####################################################
        
function GetAppFileBody($name, $size, $sizeEncrypted, $manifest) {
        
    $body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" }
    $body.name = $name
    $body.size = $size
    $body.sizeEncrypted = $sizeEncrypted
    $body.manifest = $manifest
    $body.isDependency = $false
        
    $body
}
        
####################################################
        
function GetAppCommitBody($contentVersionId, $LobType) {
        
    $body = @{ "@odata.type" = "#$LobType" }
    $body.committedContentVersion = $contentVersionId
        
    $body
        
}
        
####################################################
        
Function Test-SourceFile() {
        
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $SourceFile
    )
        
    try {
        
        if (!(test-path "$SourceFile")) {
        
            Write-Error "Source File '$sourceFile' doesn't exist..."
            throw
        
        }
        
    }
        
    catch {
        
        Write-Error $_.Exception.Message
        break
        
    }
        
}
        
####################################################
        
Function New-DetectionRule() {
        
    [cmdletbinding()]
        
    param
    (
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", Position = 1)]
        [Switch]$PowerShell,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [Switch]$MSI,
        
        [parameter(Mandatory = $true, ParameterSetName = "File", Position = 1)]
        [Switch]$File,
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry", Position = 1)]
        [Switch]$Registry,
        
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        [String]$ScriptFile,
        
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        $enforceSignatureCheck,
        
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        $runAs32Bit,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        [String]$MSIproductCode,
           
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
         
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolderName,
        
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("notConfigured", "exists", "modifiedDate", "createdDate", "version", "sizeInMB")]
        [string]$FileDetectionType,
        
        [parameter(Mandatory = $false, ParameterSetName = "File")]
        $FileDetectionValue = $null,
        
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("True", "False")]
        [string]$check32BitOn64System = "False",
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryKeyPath,
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("notConfigured", "exists", "doesNotExist", "string", "integer", "version")]
        [string]$RegistryDetectionType,
        
        [parameter(Mandatory = $false, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryValue,
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("True", "False")]
        [string]$check32BitRegOn64System = "False"
        
    )
        
    if ($PowerShell) {
        
        if (!(Test-Path "$ScriptFile")) {
                    
            Write-Error "Could not find file '$ScriptFile'..."
            Write-Error "Script can't continue..."
            break
        
        }
                
        $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$ScriptFile"))
                
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection" }
        $DR.enforceSignatureCheck = $false
        $DR.runAs32Bit = $false
        $DR.scriptContent = "$ScriptContent"
        
    }
            
    elseif ($MSI) {
            
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection" }
        $DR.productVersionOperator = "notConfigured"
        $DR.productCode = "$MsiProductCode"
        $DR.productVersion = $null
        
    }
        
    elseif ($File) {
            
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection" }
        $DR.check32BitOn64System = "$check32BitOn64System"
        $DR.detectionType = "$FileDetectionType"
        $DR.detectionValue = $FileDetectionValue
        $DR.fileOrFolderName = "$FileOrFolderName"
        $DR.operator = "notConfigured"
        $DR.path = "$Path"
        
    }
        
    elseif ($Registry) {
            
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection" }
        $DR.check32BitOn64System = "$check32BitRegOn64System"
        $DR.detectionType = "$RegistryDetectionType"
        $DR.detectionValue = ""
        $DR.keyPath = "$RegistryKeyPath"
        $DR.operator = "notConfigured"
        $DR.valueName = "$RegistryValue"
        
    }
        
    return $DR
        
}
        
####################################################
        
function Get-DefaultReturnCodes() {
        
    @{"returnCode" = 0; "type" = "success" }, `
    @{"returnCode" = 1707; "type" = "success" }, `
    @{"returnCode" = 3010; "type" = "softReboot" }, `
    @{"returnCode" = 1641; "type" = "hardReboot" }, `
    @{"returnCode" = 1618; "type" = "retry" }
        
}
        
####################################################
        
function New-ReturnCode() {
        
    param
    (
        [parameter(Mandatory = $true)]
        [int]$returnCode,
        [parameter(Mandatory = $true)]
        [ValidateSet('success', 'softReboot', 'hardReboot', 'retry')]
        $type
    )
        
    @{"returnCode" = $returnCode; "type" = "$type" }
        
}
        
####################################################
        
Function Get-IntuneWinXML() {
        
    param
    (
        [Parameter(Mandatory = $true)]
        $SourceFile,
        
        [Parameter(Mandatory = $true)]
        $fileName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("false", "true")]
        [string]$removeitem = "true"
    )
        
    Test-SourceFile "$SourceFile"
        
    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
        
    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        
    $zip.Entries | where-object { $_.Name -like "$filename" } | foreach-object {
        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)
        
    }
        
    $zip.Dispose()
        
    [xml]$IntuneWinXML = Get-Content "$Directory\$filename"
        
    return $IntuneWinXML
        
    if ($removeitem -eq "true") { remove-item "$Directory\$filename" }
        
}
        
####################################################
        
Function Get-IntuneWinFile() {
        
    param
    (
        [Parameter(Mandatory = $true)]
        $SourceFile,
        
        [Parameter(Mandatory = $true)]
        $fileName,
        
        [Parameter(Mandatory = $false)]
        [string]$Folder = "win32"
    )
        
    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
        
    if (!(Test-Path "$Directory\$folder")) {
        
        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null
        
    }
        
    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        
    $zip.Entries | Where-Object { $_.Name -like "$filename" } | ForEach-Object {
        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)
        
    }
        
    $zip.Dispose()
        
    return "$Directory\$folder\$filename"
        
    if ($removeitem -eq "true") { remove-item "$Directory\$filename" }
        
}
        
####################################################
        
function Invoke-UploadWin32Lob() {
        
    <#
        .SYNOPSIS
        This function is used to upload a Win32 Application to the Intune Service
        .DESCRIPTION
        This function is used to upload a Win32 Application to the Intune Service
        .EXAMPLE
        Invoke-UploadWin32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
        This example uses all parameters required to add an intunewin File into the Intune Service
        .NOTES
        NAME: Invoke-UploadWin32Lob
        #>
        
    [cmdletbinding()]
        
    param
    (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,
        
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$publisher,
        
        [parameter(Mandatory = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]$description,
        
        [parameter(Mandatory = $true, Position = 4)]
        [ValidateNotNullOrEmpty()]
        $detectionRules,
        
        [parameter(Mandatory = $true, Position = 5)]
        [ValidateNotNullOrEmpty()]
        $returnCodes,
        
        [parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullOrEmpty()]
        [string]$installCmdLine,
        
        [parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string]$uninstallCmdLine,
        
        [parameter(Mandatory = $false, Position = 8)]
        [ValidateSet('system', 'user')]
        $installExperience = "system"
    )
        
    try	{
        
        $LOBType = "microsoft.graph.win32LobApp"
        
        Write-Verbose "Testing if SourceFile '$SourceFile' Path is valid..."
        Test-SourceFile "$SourceFile"
                
        Write-Verbose "Creating JSON data to pass to the service..."
        
        # Funciton to read Win32LOB file
        $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"
        
        # If displayName input don't use Name from detection.xml file
        if ($displayName) { $DisplayName = $displayName }
        else { $DisplayName = $DetectionXML.ApplicationInfo.Name }
                
        $FileName = $DetectionXML.ApplicationInfo.FileName
        
        $SetupFileName = $DetectionXML.ApplicationInfo.SetupFile
               
        $mobileAppBody = Get-Win32AppBody -displayName "$DisplayName" -publisher "$publisher" `
            -description $description -filename $FileName -SetupFileName "$SetupFileName" `
            -installExperience $installExperience -installCommandLine $installCmdLine `
            -uninstallCommandLine $uninstallcmdline
        
        if ($DetectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($DetectionRules).'@odata.type'.Count -gt 1) {
            Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning "It can't include both..."
            break
        } else {
            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules
        }
        
        #ReturnCodes
        
        if ($returnCodes) {
            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)
        } else {
            Write-Warning "Intunewin file requires ReturnCodes to be specified"
            Write-Warning "If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
            break
        }
        
        Write-Verbose "Creating application in Intune..."
        $mobileApp = New-MgDeviceAppManagementMobileApp -BodyParameter ($mobileAppBody | ConvertTo-Json)
        
        # Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Verbose "Creating Content Version in the service for the application..."
        $appId = $mobileApp.id
        $contentVersionUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions"
        $contentVersion = Invoke-MgGraphRequest -method POST -Uri $contentVersionUri -Body "{}"
        
        # Encrypt file and Get File Information
        Write-Verbose "Getting Encryption Information for '$SourceFile'..."
        
        $encryptionInfo = @{}
        $encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = "ProfileVersion1"
        $encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
        
        $fileEncryptionInfo = @{}
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo
        
        # Extracting encrypted file
        $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"
        
        [int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
        $EncrySize = (Get-Item "$IntuneWinFile").Length
        
        # Create a new file for the app.
        Write-Verbose "Creating a new file entry in Azure for the upload..."
        $contentVersionId = $contentVersion.id
        $fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null
        $filesUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
        $file = Invoke-MgGraphRequest -Method POST -Uri $filesUri -Body ($fileBody | ConvertTo-Json)
            
        # Wait for the service to process the new file request.
        Write-Verbose "Waiting for the file entry URI to be created..."
        $fileId = $file.id
        $fileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
        $file = Start-WaitForFileProcessing $fileUri "AzureStorageUriRequest"
        
        # Upload the content to Azure Storage.
        Write-Verbose "Uploading file to Azure Storage..."
        
        UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri
        
        # Need to Add removal of IntuneWin file
        Remove-Item "$IntuneWinFile" -Force
        
        # Commit the file.
        Write-Verbose "Committing the file into Azure Storage..."
        $commitFileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"
        Invoke-MgGraphRequest -Uri $commitFileUri -Method POST -Body ($fileEncryptionInfo | ConvertTo-Json)
        
        # Wait for the service to process the commit file request.
        Write-Verbose "Waiting for the service to process the commit file request..."
        $file = Start-WaitForFileProcessing $fileUri "CommitFile"
        
        # Commit the app.
        Write-Verbose "Committing the file into Azure Storage..."
        $commitAppUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId"
        $commitAppBody = GetAppCommitBody $contentVersionId $LOBType
        Invoke-MgGraphRequest -Method PATCH -Uri $commitAppUri -Body ($commitAppBody | ConvertTo-Json)
        
        foreach ($i in 0..$sleep) {
            Write-Progress -Activity "Sleeping for $($sleep-$i) seconds" -PercentComplete ($i / $sleep * 100) -SecondsRemaining ($sleep - $i)
            Start-Sleep -s 1
        }            
    } catch {
        Write-Error "Aborting with exception: $($_.Exception.ToString())"  
    }
}
        
$logRequestUris = $true
$logHeaders = $false
$logContent = $true
        
$azureStorageUploadChunkSizeInMb = 6l
        
$sleep = 30
        
Function Get-IntuneApplication() {
        
    <#
        .SYNOPSIS
        This function is used to get applications from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any applications added
        .EXAMPLE
        Get-IntuneApplication
        Returns any applications configured in Intune
        .NOTES
        NAME: Get-IntuneApplication
        #>            
    try {

        return Get-MgDeviceAppManagementMobileApp -All | Where-Object { (!($_.AdditionalProperties['@odata.type']).Contains("managed")) }
        
    }
            
    catch {
        
        $ex = $_.Exception
        Write-Verbose "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        break
        
    }
        
}
filter Assert-WhiteSpaceIsNull {
    IF ([string]::IsNullOrWhiteSpace($_)) { $null }
    ELSE { $_ }
}

function new-detectionscript {
    param
    (
        $appid,
        $appname
    )
    $detect = @"
`$installedModules = Get-InstalledModule
`$module = `$installedModules | where-object Name -eq "$appid"
if (`$module.Length -eq 0) {
    exit 0
} else {
    `$availableVersion = (Find-Module -Name "$appid")

    if (`$module[0].Version -lt `$availableVersion[0].Version) {
        Write-Host "Update available for: SETAPPNAME"
        exit 1
    } else {
        Write-Host "No Upgrade available"
        exit 0
    }
}
"@
    return $detect
}

function new-remediationscript {
    param
    (
        $appid,
        $appname
    )
    $remediate = @"
    Param
    (
      [parameter(Mandatory=`$false)]
      [String[]]
      `$param
    )
    
    `$ModuleName = "$appid"
    `$Path_local = "`$Env:Programfiles\_MEM"
    Start-Transcript -Path "`$Path_local\Log\`$ProgramName.log" -Force -Append
    Update-Module -Name `$ModuleName -Force -Confirm:`$false -Scope AllUsers
    Stop-Transcript
"@
    return $remediate

}

function new-proac {
    param
    (
        $appid,
        $appname,
        $groupid
    )
    $detectscriptcontent = new-detectionscript -appid $appid -appname $appname
    $detect = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($detectscriptcontent))
    $remediatecriptcontent = new-remediationscript -appid $appid -appname $appname
    $remediate = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($remediatecriptcontent))

    $DisplayName = $appname + " Upgrade"
    $Description = "Upgrade $appname application"
    ##RunAs can be "system" or "user"
    $RunAs = "system"
    ##True for 32-bit, false for 64-bit
    $RunAs32 = $false
    ##Daily or Hourly
    #$ScheduleType = "Hourly"
    ##How Often
    ##Start Time (if daily)
    #$StartTime = "01:00"
    
    $proacparams = @{
        publisher                = "Microsoft"
        displayName              = $DisplayName
        description              = $Description
        detectionScriptContent   = $detect
        remediationScriptContent = $remediate
        runAs32Bit               = $RunAs32
        enforceSignatureCheck    = $false
        runAsAccount             = $RunAs
        roleScopeTagIds          = @(
            "0"
        )
        isGlobalScript           = "false"
    }
    $paramsjson = $proacparams | convertto-json
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceHealthScripts"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    Invoke-MgGraphRequest -Uri $uri -Method POST -Body $paramsjson -ContentType "application/json"

    return "Success"

}

function new-intunewinfile {
    param
    (
        $appid,
        $appname,
        $apppath,
        $setupfilename
    )
    . $intuneapputiloutput -c "$apppath" -s "$setupfilename" -o "$apppath" -q

}

function new-detectionscript {
    param
    (
        $appid,
        $appname
    )
    $detection = @"
Get-InstalledModule -Name "$appid"
"@
    return $detection

}


function new-installscript {
    param
    (
        $appid,
        $appname
    )
    $install = @"
    Param
    (
        [parameter(Mandatory=`$false)]
        [String[]]
        `$param
    )
    
    `$ModuleName = "$appid"
    `$Path_local = "`$Env:Programfiles\_MEM"
    Start-Transcript -Path "`$Path_local\Log\`$ModuleName-install.log" -Force -Append
    Write-Host "Updating PowerShellGet"
    Install-Module -Name "PowerShellGet" -Scope AllUsers -AllowClobber -Confirm:`$false -Force -Verbose
    Import-Module -Name "PowerShellGet" -Force -MinimumVersion 2.0.0
    Write-Host "Installing NuGet Provider"
    Install-PackageProvider -Name "NuGet" -Confirm:`$false -Force -Verbose
    Write-Host "Installing Module `$ModuleName"
    Install-Module -Name "`$ModuleName" -Force -AllowClobber -SkipPublisherCheck -Confirm:`$false -Scope AllUsers -Verbose
    Write-Host "Module `$ModuleName installed"
    Stop-Transcript
"@
    return $install

}

function new-uninstallscript {
    param
    (
        $appid,
        $appname
    )
    $uninstall = @"
    Param
    (
      [parameter(Mandatory=`$false)]
      [String[]]
      `$param
    )
    
    `$ModuleName = "$appid"
    `$Path_local = "`$Env:Programfiles\_MEM"
    Start-Transcript -Path "`$Path_local\Log\`$ModuleName-uninstall.log" -Force -Append

    Uninstall-Module -Name "`$ModuleName" -Force -AllVersions -Confirm:`$false -Verbose
    Write-Host "Module `$ModuleName uninstalled
    Stop-Transcript
"@
    return $uninstall
}

function new-win32app {
    [cmdletbinding()]
        
    param
    (
        $appid,
        $appname,
        $appfile,
        $installcmd,
        $uninstallcmd,
        $detectionfile,
        $publisher,
        $description
    )
    # Defining Intunewin32 detectionRules
    $PSRule = New-DetectionRule -PowerShell -ScriptFile $detectionfile -enforceSignatureCheck $false -runAs32Bit $false


    # Creating Array for detection Rule
    $DetectionRule = @($PSRule)

    $ReturnCodes = Get-DefaultReturnCodes

    # Win32 Application Upload
    $appupload = Invoke-UploadWin32Lob -SourceFile "$appfile" -DisplayName "$appname" -publisher $publisher `
        -description "$description PSModule Package" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
        -installCmdLine "$installcmd" -uninstallCmdLine "$uninstallcmd"

    return $appupload

}

############################################################################################################
######                          END FUNCTIONS SECTION                                               ########
############################################################################################################

$question = $host.UI.PromptForChoice("Verbose output?", "Do you want verbose output?", ([System.Management.Automation.Host.ChoiceDescription]"&Yes",[System.Management.Automation.Host.ChoiceDescription]"&No"), 1)

Write-Verbose "Connecting to Microsoft Graph"
Select-MgProfile -Name Beta
Connect-MgGraph -Scopes DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, openid, profile, email, offline_access
Write-Verbose "Graph connection established"

if ($question -eq 0) {
    $VerbosePreference="Continue"
}

Find-Module "*$(Read-Host "Inital Search query")*" | out-gridview -PassThru -Title "Available Modules" | ForEach-Object {

    $appid = $_.Name.Trim()
    $appname = $_.Name.Trim()

    Write-Verbose "Module $appid selected"

    ##Create Directory
    Write-Verbose "Creating Directory for $appname"
    $apppath = "$path\$appid"
    new-item -Path $apppath -ItemType Directory -Force
    Write-Host "Directory $apppath Created"

    ##Create Install Script
    Write-Verbose "Creating Install Script for $appname"
    $installscript = new-installscript -appid $appid -appname $appname
    $installfilename = "install$appid.ps1"
    $installscriptfile = $apppath + "\" + $installfilename
    $installscript | Out-File $installscriptfile
    Write-Host "Script created at $installscriptfile"

    ##Create Uninstall Script
    Write-Verbose "Creating Uninstall Script for $appname"
    $uninstallscript = new-uninstallscript -appid $appid -appname $appname
    $uninstallfilename = "uninstall$appid.ps1"
    $uninstallscriptfile = $apppath + "\" + $uninstallfilename
    $uninstallscript | Out-File $uninstallscriptfile
    Write-Host "Script created at $uninstallscriptfile"

    ##Create Detection Script
    Write-Verbose "Creating Detection Script for $appname"
    $detectionscript = new-detectionscript -appid $appid -appname $appname
    $detectionscriptfile = $apppath + "\detection$appid.ps1"
    $detectionscript | Out-File $detectionscriptfile
    Write-Host "Script created at $detectionscriptfile"


    ##Create Proac
    Write-Verbose "Creation Proactive Remediation for $appname"
    new-proac -appid $appid -appname $appname -groupid $installgroup
    Write-Host "Proactive Remediation Created and Assigned for $appname"

    ##Create IntuneWin
    Write-Verbose "Creating Intunewin File for $appname"
    $intunewinpath = $apppath + "\install$appid.intunewin"
    new-intunewinfile -appid $appid -appname $appname -apppath $apppath -setupfilename $installscriptfile
    Write-Host "Intunewin $intunewinpath Created"
    $sleep = 10
    foreach ($i in 0..$sleep) {
        Write-Progress -Activity "Sleeping for $($sleep-$i) seconds" -PercentComplete ($i / $sleep * 100) -SecondsRemaining ($sleep - $i)
        Start-Sleep -s 1
    }
    ##Create and upload Win32
    Write-Verbose "Uploading $appname to Intune"
    $installcmd = "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -command .\$installfilename"
    $uninstallcmd = "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -windowstyle hidden -executionpolicy bypass -command .\$uninstallfilename"

    new-win32app -appid $appid -appname $appname -appfile $intunewinpath -installcmd $installcmd -uninstallcmd $uninstallcmd -detectionfile $detectionscriptfile -publisher $_.Author -description $_.Description
    Write-Host "$appname Created and uploaded"

    ##Done
    Write-Host "$appname packaged and deployed"

}
Disconnect-MgGraph
if ($question -eq 0) {
    $VerbosePreference="SilentlyContinue"
}
Write-Host "👍 Selected apps have been deployed to Intune" -ForegroundColor Green
Stop-Transcript