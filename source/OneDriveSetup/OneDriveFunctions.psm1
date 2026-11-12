
function Confirm-LGPOPathandVersion {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        Write-Error "LGPO.exe not found at $Path. Exiting."
        exit 1
    }

    # Verify LGPO.exe version
    try {
        $LGPOVersion = (Get-Item $Path).VersionInfo.ProductVersion
        if (-not ($LGPOVersion -match "^3\.")) {
            Write-Error "LGPO.exe version is not 3.x. Found version: $LGPOVersion. Exiting."
            return $false
            exit 1
        }
        Write-Host "LGPO.exe version $LGPOVersion verified." -ForegroundColor Green
        return $true
        exit 0
    } catch {
        Write-Error "Unable to retrieve LGPO.exe version. $($_.Exception.Message)"
        return $false
        exit 1
    }
}

function Get-AzureADTenantId {
    $joinInfoPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'

    Write-Host "Checking for Azure AD join information in the registry..."

    if (Test-Path $joinInfoPath) {
        try {
            $subKeys = Get-ChildItem -Path $joinInfoPath
            foreach ($subKey in $subKeys) {
                try {
                    $tenantId = (Get-ItemProperty -Path $subKey.PSPath -Name 'TenantId' -ErrorAction Stop).TenantId
                    if ($tenantId) {
                        Write-Host "Tenant ID found: $tenantId"
                        return $tenantId
                    }
                } catch {
                    Write-Host "Error accessing subkey '$($subKey.Name)': $_"
                }
            }
            Write-Host "Tenant ID not found in any subkeys."
        } catch {
            Write-Host "Error accessing registry path '$joinInfoPath': $_"
        }
    } else {
        Write-Host "JoinInfo registry path not found: $joinInfoPath"
    }

    return $null
}

function Invoke-OneDriveInstallMgmt {
    param (
        [switch]$Remove,
        [string]$LocalPath
    )

    function Stop-OneDriveProcesses {
        Write-Host "Stopping any running OneDrive processes..."
        Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    function Uninstall-OneDrive {
        Write-Host "Uninstalling OneDrive..."

        Stop-OneDriveProcesses

        # Attempt to uninstall per-user installation
        $oneDriveUserUninstall = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
        if (Test-Path $oneDriveUserUninstall) {
            $ODUpresent = $true
            Write-Host "Found per-user OneDrive installation. Uninstalling..."
            Start-Process -FilePath $oneDriveUserUninstall -ArgumentList "/uninstall" -NoNewWindow -Wait
        } else {
            Write-Host "Per-user OneDrive installation not found."
            $ODUpresent = $false
        }

        # Attempt to uninstall per-machine installation. OneDriveSetup.exe lives in the version sub folder,
        # for example 'C:\Program Files\Microsoft OneDrive\25.100.0525.0001\OneDriveSetup.exe'.
        $oneDriveMachineRoot = "$env:ProgramFiles\Microsoft OneDrive"
        $oneDriveMachineUninstall = $null
        if (Test-Path $oneDriveMachineRoot) {
            $oneDriveMachineUninstall = Get-ChildItem -Path $oneDriveMachineRoot -Filter 'OneDriveSetup.exe' -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
        }
        if ($oneDriveMachineUninstall -and (Test-Path $oneDriveMachineUninstall)) {
            $ODMpresent = $true
            Write-Host "Found per-machine OneDrive installation. Uninstalling..."
            Start-Process -FilePath $oneDriveMachineUninstall -ArgumentList "/uninstall", "/allusers" -NoNewWindow -Wait
        } else {
            Write-Host "Per-machine OneDrive installation not found."
            $ODMpresent = $false
        }

        if (!($ODMpresent -or $ODUpresent)) {return $true}
        Else{ 
            if ((Test-Path $oneDriveUserUninstall) -or (Test-Path "$oneDriveMachineRoot\OneDrive.exe")) {
            Write-Error "OneDrive uninstallation failed. Some installations are still present."
            return $false
            }
            else {
                Write-Host "OneDrive uninstallation completed successfully."
                return $true
            }
        }       
    }

    function Install-OneDrive {
        Write-Host "Installing OneDrive silently..."

        $installerUrl = "https://go.microsoft.com/fwlink/?linkid=844652"
        $tempPath = Join-Path -Path $env:TEMP -ChildPath "OneDriveSetup.exe"

        if ($LocalPath -and (Test-Path $LocalPath)) {
            Write-Host "Using local installer at $LocalPath..."
            $installerPath = $LocalPath
        } else {
            Write-Host "Downloading OneDrive installer..."
            try {
                Invoke-WebRequest -Uri $installerUrl -OutFile $tempPath -UseBasicParsing
                $installerPath = $tempPath
            } catch {
                Write-Error "Failed to download OneDrive installer: $_"
                return $false
            }
        }

        try {
            # Run the installer silently (per-machine preferred if supported)
            Write-Host "Running OneDrive installer..."
            Start-Process -FilePath $installerPath -ArgumentList "/allusers", "/silent", "/install" -NoNewWindow -Wait
        } catch {
            Write-Error "Failed to install OneDrive: $_"
            return $false
        } finally {
            # Cleanup if the installer was downloaded
            if ($installerPath -eq $tempPath -and (Test-Path $tempPath)) {
                Remove-Item $tempPath -Force
                Write-Host "Cleaned up temporary installer file."
            }
        }

        Write-Host "OneDrive installation completed."
        return $true
    }

    # Main execution
    if ($Remove) {
        Uninstall-OneDrive
    } else {
        Install-OneDrive
    }
}

function Edit-StringInFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$filePath,

        [Parameter(Mandatory = $true)]
        [string]$searchString,

        [Parameter(Mandatory = $true)]
        [string]$replaceWith
    )

    try {
        if (-not (Test-Path -Path $filePath)) {
            Write-Error "The file '$filePath' does not exist."
            return
        }

        # Read the entire content of the file as a single string
        $content = Get-Content -Path $filePath -Raw

        # Replace all occurrences of the search string with the replacement string
        $updatedContent = $content -replace [regex]::Escape($searchString), $replaceWith

        # Write the updated content back to the file
        Set-Content -Path $filePath -Value $updatedContent

        Write-Host "Successfully replaced all occurrences of '$searchString' with '$replaceWith' in '$filePath'."
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}



