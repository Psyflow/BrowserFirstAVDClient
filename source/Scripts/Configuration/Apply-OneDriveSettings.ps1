
[CmdletBinding()]
param (
    [switch]$Remove
)

# Configures OneDrive settings for all users on the system. These settings can also be applied via Intune or Group Policy.
$oneDrivePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
$publicDesktop      = "C:\Users\Public\Desktop"
$defaultUserPath    = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
$shortcutPath       = Join-Path $publicDesktop "OneDrive.lnk"

$oneDrivePolicyKeys = @(
    "KFMSilentOptInDocuments",
    "KFMSilentOptInPictures",
    "SilentAccountConfig",
    "FilesOnDemandEnabled",
    "DisableFREAnimation",
    "DisableFRETutorial",
    "SharedContentDeleteConfirmation",
    "DisablePersonalSync",
    "EnableAutoStart",
    "DisableFirstDeleteDialog"
)

if ($Remove) {

    foreach ($key in $oneDrivePolicyKeys) {
        if (Get-ItemProperty -Path $oneDrivePolicyPath -Name $key -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $oneDrivePolicyPath -Name $key -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Resetting default user desktop path to '%USERPROFILE%\Desktop'..."
    if (Test-Path $defaultUserPath) {
        try {
            Set-ItemProperty -Path $defaultUserPath -Name "Desktop" -Value "%USERPROFILE%\Desktop" -Type ExpandString
        } catch {
            Write-Warning "Unable to reset Desktop value: $_"
        }
    }

    if (Test-Path $shortcutPath) {Remove-Item $shortcutPath -Force}

} else {

    if(!($oneDrivePolicyPath)){New-Item -Path $oneDrivePolicyPath -Force | Out-Null}
    
    foreach ($key in $oneDrivePolicyKeys) {
        New-ItemProperty -Path $oneDrivePolicyPath -Name $key -PropertyType DWord -Value 1 -Force
    }

    if (-not (Test-Path $defaultUserPath)) {
        New-Item -Path $defaultUserPath -Force | Out-Null
    }
    Set-ItemProperty -Path $defaultUserPath -Name "Desktop" -Value $publicDesktop -Type ExpandString

    $wshell = New-Object -ComObject WScript.Shell
    $shortcut = $wshell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "explorer.exe"
    $shortcut.Arguments = "shell:OneDrive"
    $shortcut.IconLocation = "$env:SystemRoot\System32\OneDrive.ico"
    $shortcut.Save()
}

