<#
.SYNOPSIS
    Provisions Windows App for all users from a local MSIX package.

.DESCRIPTION
    Windows App replaces the Remote Desktop client for Windows (MSI), which reached end of support on
    March 27, 2026 (September 28, 2026 for Azure Government) and can no longer be downloaded.

    Windows 11 IoT Enterprise LTSC has no Microsoft Store, so this script provisions Windows App from the
    standalone MSIX installer. Download the installer for your architecture from the 'Windows App' download
    links on Microsoft Learn (https://learn.microsoft.com/windows-app/whats-new) and place it in
    'Customizations\Software\WindowsApp'. Dependency packages, if you need any, go in a 'Dependencies' sub folder.

    Exit codes: 0 = provisioned or already present, 2 = no package found and Windows App is not installed,
    1 = provisioning failed.

.PARAMETER PackageFolder
    Folder that contains the Windows App .msix or .msixbundle file.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$PackageFolder
)

$PackageName = 'MicrosoftCorporationII.Windows365'
$LogDir = "$env:SystemRoot\Logs\Software"
If (-not (Test-Path -Path $LogDir)) { $null = New-Item -Path $LogDir -ItemType Directory -Force }
Start-Transcript -Path "$LogDir\Install-WindowsApp.log" -Force

$ExitCode = 0
Try {
    $Provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $PackageName }
    $Package = $null
    If (Test-Path -Path $PackageFolder) {
        $Package = Get-ChildItem -Path $PackageFolder -File | Where-Object { $_.Extension -in '.msix', '.msixbundle' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }

    If ($Package) {
        Write-Output "Provisioning Windows App from '$($Package.FullName)'."
        $Arguments = @{
            Online      = $true
            PackagePath = $Package.FullName
            SkipLicense = $true
        }
        $DependencyFolder = Join-Path -Path $PackageFolder -ChildPath 'Dependencies'
        If (Test-Path -Path $DependencyFolder) {
            $Dependencies = @(Get-ChildItem -Path $DependencyFolder -File | Where-Object { $_.Extension -in '.msix', '.appx' } | Select-Object -ExpandProperty FullName)
            If ($Dependencies.Count -gt 0) { $Arguments['DependencyPackagePath'] = $Dependencies }
        }
        $null = Add-AppxProvisionedPackage @Arguments -ErrorAction Stop
        Write-Output "Windows App provisioned for all users."
    }
    ElseIf ($Provisioned) {
        Write-Output "No package found in '$PackageFolder'. Windows App version $($Provisioned.Version) is already provisioned."
    }
    Else {
        Write-Warning "No Windows App .msix package found in '$PackageFolder' and Windows App is not provisioned. Download the standalone MSIX installer and place it in that folder, or deploy Windows App with your management tool."
        $ExitCode = 2
    }

    # Windows App needs the Microsoft Edge WebView2 runtime. It is part of Windows 11, but check anyway.
    $WebView2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue
    If (-not $WebView2) { Write-Warning "The Microsoft Edge WebView2 runtime was not detected. Windows App will not start without it." }
}
Catch {
    Write-Error "Provisioning Windows App failed: $($_.Exception.Message)" -ErrorAction Continue
    $ExitCode = 1
}
Finally {
    Stop-Transcript
}
exit $ExitCode
