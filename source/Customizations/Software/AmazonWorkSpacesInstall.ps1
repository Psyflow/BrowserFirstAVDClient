param (
    [switch]$Remove
)

$Script:FullName    = $MyInvocation.MyCommand.Path
$Script:File        = $MyInvocation.MyCommand.Name
$Script:Dir         = Split-Path $Script:FullName
$CmdletName         = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)

# Start Transcript Logging
$Script:LogDir = "$env:SystemRoot\Logs\Configuration"
If (-not (Test-Path -Path $Script:LogDir)) {New-Item -Path $Script:LogDir -ItemType Directory -Force}
$Script:LogName = "$($CmdletName).log"
$Script:LogFilePath = "$Script:LogDir\$Script:LogName"
If (Test-Path $Script:LogFilePath) {Remove-Item $Script:LogFilePath -Force}
Start-Transcript -Path $Script:LogFilePath

# Define the path to the Amazon WorkSpaces installer
$installerPath = "$Script:Dir\Amazon+WorkSpaces.msi"

# Define installation arguments for a silent install
$installArgs = "/quiet /norestart SHORTCUTINSTALL=0"

# Define uninstallation arguments
$uninstallArgs = "/quiet /norestart"

try {
    if ($Remove) {
        # Uninstall Amazon WorkSpaces app
        Write-Output "$($CmdletName): Starting silent uninstallation of Amazon WorkSpaces app..."
        if (-Not (Test-Path -Path $installerPath)) {
            Write-Error "$($CmdletName): ERROR: Amazon WorkSpaces installer not found at $installerPath. Cannot proceed with uninstallation. Please verify the path or download the installer."
            exit 1
        }
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x `"$installerPath`" $uninstallArgs" -Wait -NoNewWindow -PassThru
        $LASTEXITCODE = $process.ExitCode
        
        # Check the exit code of the uninstaller
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-Output "$($CmdletName): Amazon WorkSpaces app uninstalled successfully."
        } else {
            Write-Error "$($CmdletName): ERROR: Amazon WorkSpaces app uninstallation failed with exit code $LASTEXITCODE."
        }
    } else {
        # Install Amazon WorkSpaces app
        Write-Output "$($CmdletName): Starting silent installation of Amazon WorkSpaces app..."
        if (-Not (Test-Path -Path $installerPath)) {
            Write-Error "$($CmdletName): ERROR: Amazon WorkSpaces installer not found at $installerPath. Cannot proceed with installation. Please verify the path or download the installer."
            exit 1
        }
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" $installArgs" -Wait -NoNewWindow -PassThru
        $LASTEXITCODE = $process.ExitCode

        # Check the exit code of the installer
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
            Write-Output "$($CmdletName): Amazon WorkSpaces app installed successfully."
        } else {
            Write-Error "$($CmdletName): ERROR: Amazon WorkSpaces app installation failed with exit code $LASTEXITCODE."
        }
        # Remove desktop shortcut
        $publicDesktop = "$env:PUBLIC\Desktop\Amazon WorkSpaces.lnk"
        if (Test-Path $publicDesktop) { Remove-Item $publicDesktop -Force }


    }
} catch {
    Write-Error "$($CmdletName): ERROR: An unexpected error occurred: $_"
} finally {
    # Stop Transcript Logging
    Stop-Transcript
}

# Return the exit code
exit $LASTEXITCODE