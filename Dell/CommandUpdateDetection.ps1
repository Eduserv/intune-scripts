<#
 .SYNOPSIS
  Detects if the Dell Device has updates available
 .DESCRIPTION
  Detects if the Dell Device has updates available
 .EXAMPLE
  PS C:\> Detection.ps1
 .OUTPUTS
  0 No updates
  1 Updates
#>
$Path_local = "$Env:Programfiles\_MEM"
Start-Transcript -Path "$Path_local\Log\DellUpdates.log" -Force -Append
function Write-Log {
    param(
        $MessageType,
        $Message
    )

    $MyDate = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    Write-Host  "$MyDate - $MessageType : $Message"
}

$Get_Manufacturer_Info = (Get-WmiObject win32_computersystem).Manufacturer
Write-Log -MessageType "INFO" -Message "Detected $Get_Manufacturer_Info"
if ($Get_Manufacturer_Info -like "*Dell*") {
    $DCU = "$Env:Programfiles\Dell\CommandUpdate\dcu-cli.exe"
    $foundDCU = $true
    if (!Test-Path $DCU) {
        $DCU = "${Env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe"
        if (!Test-Path $DCU) {
            Write-Log -MessageType "ERROR" -Message "Dell Command | Update is not installed, cancelling"
            Stop-Transcript
            $foundDCU = $false
            Exit 0
        }
    }
    if ($foundDCU) {
        $code = & $DCU /scan
        if ($code.length -gt 0) {
            if ($code[$code.length - 1] -ilike "*500") {
                Write-Log -MessageType "SUCCESS" -Message "No Updates found"
                Write-Host "No Dell Command | Updates found"
            }
            else {
                Write-Log -MessageType "SUCCESS" -Message "Updates found"
                for ($i = 0; $i -lt $code.Length - 2; $i++) {
                    Write-Log -MessageType "INFO" -Message $code[$i]
                }
                Write-Error "Updates Needed"
                Stop-Transcript
                Exit 1
            }
        }
        else {
            Write-Log -MessageType "SUCCESS" -Message "Updates found"
            Write-Error "Updates Needed"
            Stop-Transcript
            Exit 1
        }
    } 
}

Stop-Transcript
Exit 0