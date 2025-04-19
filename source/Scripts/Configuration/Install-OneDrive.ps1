param (
        [switch]$Remove
    )

    if ($Remove) {
        Write-Output "Uninstalling OneDrive..."

        # Attempt to uninstall for per-user installation
        $oneDriveUserUninstall = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
        if (Test-Path $oneDriveUserUninstall) {
            Start-Process -FilePath $oneDriveUserUninstall -ArgumentList "/uninstall" -NoNewWindow -Wait
        }

        # Attempt to uninstall per-machine installation (if present)
        $oneDriveMachineUninstall = "$env:ProgramFiles\Microsoft OneDrive\OneDriveSetup.exe"
        if (Test-Path $oneDriveMachineUninstall) {
            Start-Process -FilePath $oneDriveMachineUninstall -ArgumentList "/uninstall" -NoNewWindow -Wait
        }

        Write-Output "OneDrive uninstallation complete."
        return
    }

    Write-Output "Installing OneDrive silently..."

    $installerUrl = "https://go.microsoft.com/fwlink/?linkid=844652"
    $tempPath = "$env:TEMP\OneDriveSetup.exe"

    # Download the installer
    Invoke-WebRequest -Uri $installerUrl -OutFile $tempPath

    # Run the installer silently (per-machine preferred if supported)
    Start-Process -FilePath $tempPath -ArgumentList "/allusers", "/silent", "/install" -NoNewWindow -Wait

    # Cleanup
    Remove-Item $tempPath -Force

    Write-Output "OneDrive installation complete."