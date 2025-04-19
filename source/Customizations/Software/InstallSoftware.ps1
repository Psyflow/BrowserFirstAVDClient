param (
    [switch]$Uninstall
)

# Define the cmdlet name for logging
$CmdletName = "InstallSoftware"

# Start Transcript Logging
$Script:LogDir = "$env:SystemRoot\Logs\Configuration"
If (-not (Test-Path -Path $Script:LogDir)) {New-Item -Path $Script:LogDir -ItemType Directory -Force}
$Script:LogName = "$CmdletName.log"
$Script:LogFilePath = "$Script:LogDir\$Script:LogName"
If (Test-Path $Script:LogFilePath) {Remove-Item $Script:LogFilePath -Force}
Start-Transcript -Path $Script:LogFilePath

try {
    # Get all .ps1 files in the current directory
    $scripts = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" | Where-Object { $_.Name -ne "InstallSoftware.ps1" }

    if ($scripts.Count -eq 0) {
        Write-Output "$($CmdletName): No scripts found in $PSScriptRoot."
        exit 0
    }

    foreach ($script in $scripts) {
        Write-Output "$($CmdletName): Processing script $($script.FullName)..."

        try {
            if ($Uninstall) {
                # Run the script with the -Remove switch
                Write-Output "$($CmdletName): Running $($script.Name) with -Remove switch..."
                & "$($script.FullName)" -Remove
            } else {
                # Run the script normally
                Write-Output "$($CmdletName): Running $($script.Name)..."
                & "$($script.FullName)"
            }

            # Check the exit code of the script
            if ($LASTEXITCODE -eq 0) {
                Write-Output "$($CmdletName): $($script.Name) executed successfully."
            } else {
                Write-Error "$($CmdletName): ERROR: $($script.Name) failed with exit code $LASTEXITCODE."
            }
        } catch {
            Write-Error "$($CmdletName): ERROR: An error occurred while running $($script.Name): $_"
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