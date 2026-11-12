<#
.SYNOPSIS
Configures or removes OneDrive Kiosk settings.

.DESCRIPTION
This script is used to configure or remove OneDrive Kiosk settings by applying or removing Local Group Policy Object (LGPO) configurations. 
It requires the path to the LGPO settings and optionally accepts a Tenant ID, which defaults to "AutoDiscover" if not provided.

.PARAMETER Remove
Specifies whether to remove the OneDrive Kiosk configuration. If this switch is provided, the configuration will be removed.

.PARAMETER LGPOexePath
The mandatory path to the LGPO.exe file. Defaults to "$env:windir\System32\LGPO.exe".

.PARAMETER RemoveSettingsPath
The mandatory path to the LGPO settings file used for removing configurations.

.PARAMETER TenantID
The Tenant ID to be used for the OneDrive configuration. Defaults to "AutoDiscover" if not specified.

.PARAMETER OneDriveInstallerPath
Optional path to the OneDrive installer. If not provided, the script will attempt to download and install the latest version.

.EXAMPLE
# Configure OneDrive Kiosk settings
Deploy-OneDriveKioskConfig -LGPOexePath "C:\Path\To\LGPO.exe" -TenantID "your-tenant-id"

.EXAMPLE
# Remove OneDrive Kiosk settings
Deploy-OneDriveKioskConfig -Remove -LGPOexePath "C:\Path\To\LGPO.exe" -RemoveSettingsPath "C:\Path\To\RemoveSettings"

.NOTES
Author: Psiflow
Date: 2025-04-2025
Version: 1.1
#>
param (
    [switch]$Remove,

    [ValidateScript({
        $fVI = (Get-Item $_ -ErrorAction Stop).VersionInfo
        if (-not $fVI) {throw "The specified LGPO.exe file '$_' does not exist or is invalid."}
        if ($fVI.ProductName -ieq "LGPO.exe" -and $fVI.ProductMajorPart -eq 3) {return $true}
        throw "LGPO.exe must be version 3.x."
    })]
    [string]$LGPOexePath = "$env:windir\System32\LGPO.exe",
    
    [Parameter(Mandatory=$true)]
    [string]$RemoveSettingsPath,
    [string]$TenantID = "AutoDiscover",
    [string]$OneDriveInstallerPath
)

#region Initialization

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File     = $MyInvocation.MyCommand.Name
$Script:Name     = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Dir      = Split-Path $Script:FullName

# Import modules
$ModulePath = Join-Path -Path $Script:Dir -ChildPath "OneDriveFunctions.psm1"
if (Test-Path -Path $ModulePath) {
    Import-Module -Name $ModulePath -Force
} else {
    Write-Host "Error: OneDriveFunctions.psm1 not found at $ModulePath. Exiting."
    exit 1
}

$ModulePath = Join-Path -Path $Script:Dir -ChildPath "LGPOFunctions.psm1"
if (Test-Path -Path $ModulePath) {
    Import-Module -Name $ModulePath -Force
} else {
    Write-Host "Error: LGPOFunctions.psm1 not found at $ModulePath. Exiting."
    exit 1
}

# Get Tenant ID from registry if not provided explicitly
if ($TenantID -eq "AutoDiscover") {
    $TenantID = Get-AzureADTenantId
    if (-not $TenantID) {
        Write-Host "No Tenant ID found. Exiting."
        exit 1
    }
}
$TenantID = $TenantID.ToLower()
#endregion Initialization

#region OneDrive installation
#Remove OneDrive to for a clean install
Invoke-OneDriveInstallMgmt -Remove:$true

#Preform a clean version of the OneDrive device application.
if ($OneDriveInstallerPath -ne $null) {
    Invoke-OneDriveInstallMgmt -LocalPath $OneDriveInstallerPath
} else {
    Invoke-OneDriveInstallMgmt
}

#Move Latest OneDrive ADMX and ADML files to C:\Windows\PolicyDefinitions
try {
    $versionPath = Get-ChildItem -Path "$env:ProgramFiles\Microsoft OneDrive" |
        Where-Object {$_.Name -match '\b\d+\.\d+\.\d+\.\d+\b' -and (Test-Path -Path "$($_.FullName)\adm")} |
        Sort-Object { [version]$_.Name } -Descending |
        Select-Object -First 1 -ExpandProperty FullName 
    if (-not $versionPath) {
        Write-Host "Error: Unable to locate OneDrive version directory. Ensure OneDrive is installed." -ForegroundColor Red
        exit 1
    }

    $admPath = Join-Path -Path $versionPath -ChildPath "adm"
    Get-ChildItem -Path $admPath -Filter *.ADMX | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "C:\Windows\PolicyDefinitions" -Force
        Write-Host "Copied: $($_.FullName)" -ForegroundColor Cyan
    }

     Get-ChildItem -Path $admPath -Filter *.ADML | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "C:\Windows\PolicyDefinitions\en-US" -Force
        Write-Host "Copied: $($_.FullName)" -ForegroundColor Cyan
    }

    Write-Host "ADMX and ADML files successfully copied." -ForegroundColor Green
} catch {
    Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

#endregion OneDrive installation

#region LGPO Configuration

# Check if LGPO.exe exists then run the commands to apply settings
if (-not (Test-Path -Path $LGPOexePath)) {
    Write-Error "Error: LGPO.exe not found at $LGPOexePath."
}else {
    Write-Host "LGPO.exe found at $LGPOexePath."

    #Install OneDrive User Settings
    $UserSettings = Join-Path $Script:Dir OneDrive_UserLGPO.txt
    Start-Process -FilePath $LGPOexePath -ArgumentList "/t $UserSettings" -NoNewWindow -Wait
    
    #Install OneDrive Computer Settings
    $ComputerSettings = Join-Path $Script:Dir OneDrive_ComputerLGPO.txt
    Edit-StringInFile -FilePath $ComputerSettings -SearchString "{TenantID}" -ReplaceWith $TenantID
    Start-Process -FilePath $LGPOexePath -ArgumentList "/t $ComputerSettings" -NoNewWindow -Wait

}
#endregion LGPO Configuration