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
$installerPath = "$Script:Dir\CitrixWorkspaceApp.exe"

# Define installation arguments for a silent install
$installArgs = "/silent /noreboot /enableHDXMediaStream /enableDynamicClientName"

# Define uninstallation arguments
$uninstallArgs = "/uninstall /silent"


try {
    if ($Remove) {
        # Uninstall Citrix Workspace app
        Write-Output "$($CmdletName): Starting silent uninstallation of Citrix Workspace app..."
        if (-Not (Test-Path -Path $installerPath)) {
            Write-Error "$($CmdletName): ERROR: Citrix Workspace installer not found at $installerPath. Cannot proceed with uninstallation. Please verify the path or download the installer."
            exit 1
        }
        $process = Start-Process -FilePath $installerPath -ArgumentList $uninstallArgs -Wait -NoNewWindow -PassThru
        $LASTEXITCODE = $process.ExitCode

        # Check the exit code of the uninstaller
        if ($LASTEXITCODE -eq 0) {
            Write-Output "$($CmdletName): Citrix Workspace app uninstalled successfully."
        } else {
            Write-Error "$($CmdletName): ERROR: Citrix Workspace app uninstallation failed with exit code $LASTEXITCODE."
        }
    } else {
        # Install Citrix Workspace app
        Write-Output "$($CmdletName): Starting silent installation of Citrix Workspace app..."
        if (-Not (Test-Path -Path $installerPath)) {
            Write-Error "$($CmdletName): ERROR: Citrix Workspace installer not found at $installerPath. Cannot proceed with installation. Please verify the path or download the installer."
            exit 1
        }
        # No wait as the citrix does not support it nor exit code check
        $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -NoNewWindow -PassThru
        $LASTEXITCODE = 0
        
        # Check the exit code of the installer
        if ($LASTEXITCODE -eq 0) {
            Write-Output "$($CmdletName): Citrix Workspace app installed successfully."
        } else {
            Write-Error "$($CmdletName): ERROR: Citrix Workspace app installation failed."
        }
    }
} catch {
    Write-Error "$($CmdletName): ERROR: An unexpected error occurred: $_"
} finally {
    # Stop Transcript Logging
    Stop-Transcript
}

# Return the exit code
exit $LASTEXITCODE