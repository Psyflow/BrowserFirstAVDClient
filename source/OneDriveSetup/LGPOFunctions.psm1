function Confirm-LGPOPathandVersion {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path = "$env:windir\System32\LGPO.exe"
    )

    try {
        # Check if the file exists
        if (-not (Test-Path -Path $Path)) {
            throw "LGPO.exe not found at $Path."
        }

        # Retrieve version information
        $LGPOVersion = $null
        $LGPOVersion = (Get-Item $Path).VersionInfo

        # Validate ProductName
        if (-not ($LGPOVersion.ProductName -ieq "LGPO.exe")) {
            throw "The specified file at $Path is not LGPO.exe."
        }

        # Validate version
        if (-not ($LGPOVersion.ProductMajorPart -eq 3)) {
            throw "LGPO.exe version is not 3.x. Found version: $($LGPOVersion.ProductMajorPart)."
        }

        # Success message
        Write-Host "LGPO.exe version $($LGPOVersion.ProductVersion) verified." -ForegroundColor Green

        # Return validation details
        return [pscustomobject]@{
            Path    = $Path
            Version = $LGPOVersion
            Valid   = $true
        }
    } catch {
        # Handle errors
        Write-Error "Validation failed: $($_.Exception.Message)"
        return [pscustomobject]@{
            Path    = $Path
            Version = $LGPOVersion
            Valid   = $false
        }
    }
}

Function Save-LocalGPOConfig {
    <#
    .SYNOPSIS
    Saves the current Local Group Policy Object (LGPO) configuration to a timestamped backup folder.

    .DESCRIPTION
    The `Save-LocalGPOConfig` function uses the LGPO.exe tool to capture the current Local Group Policy Object (LGPO) settings and saves them into a uniquely timestamped subfolder under the specified backup directory. It supports capturing machine-specific LGPO configurations as well as user-specific configurations for administrators and non-administrators.

    The function validates the provided paths, ensures required files exist, and collects backup metadata for each capture session. It generates a `Backup_data.json` file that records the details of each backed-up policy, including backup locations and capture time.

    Each capture operation includes:
    - Export of the Registry.pol contents to a readable text format
    - Backup of the associated `gpt.ini` file (if applicable)
    - Optional compression of the Scripts folder if `Scripts.ini` exists

    .PARAMETER LGPOexePath
    Specifies the full path to the LGPO.exe executable. This parameter is mandatory and must point to a valid LGPO.exe file.

    .PARAMETER backupFolder
    Specifies the root folder where the LGPO backup will be saved. A timestamped subfolder is created under this location for each backup operation. This parameter must point to an existing folder.

    .PARAMETER CaptureSet
    Specifies the types of LGPO configurations to capture. This parameter accepts an array of values, allowing multiple types to be captured in a single execution. Valid values are:
    - `m`: Captures the Machine Configuration.
    - `u`: Captures the User Configuration.
    - `ua`: Captures the User Configuration for Administrators.
    - `un`: Captures the User Configuration for Non-Administrators.

    If omitted, the default behavior is to capture both the Machine (`m`) and User (`u`) configurations.

    .OUTPUTS
    Returns an array of custom objects, each representing the backup status of a specific GPO configuration type.
    Writes backup progress and errors to the console.  
    Generates a `Backup_data.json` metadata file inside the backup folder, describing the captured policy files and their locations.

    .NOTES
    Author        : Psiflow
    Email         : Psiflow@outlook.com
    Version       : 1.0.0
    LastUpdate    : 2024-04-26
    Requirements  : LGPO.exe must be available at the specified path.
    Privacy       : No data collected or transmitted; local-only script.

    - The function temporarily sets `$ErrorActionPreference` to `SilentlyContinue` to manage LGPO.exe parsing cleanly without unnecessary error output.
    - Ensure the LGPO.exe tool exists at the specified path and that the script is run with appropriate permissions.
    - A `Backup_data.json` metadata file is generated in each timestamped backup folder.
    - Each backup operation saves into a distinct subfolder named `Settings_yyyyMMddHHmmss` under the specified backup folder.
    - Policy files are not automatically created by Windows and may be missing. Null values in data fields may be expected and reflect this.

    .EXAMPLE
    Save-LocalGPOConfig -LGPOexePath "C:\Tools\LGPO.exe" -backupFolder "C:\Backups\LGPO"

    Captures the current Machine and User configurations and saves them into a new timestamped folder under `C:\Backups\LGPO`.

    .EXAMPLE
    Save-LocalGPOConfig -LGPOexePath "C:\Tools\LGPO.exe" -backupFolder "C:\Backups\LGPO" -CaptureSet 'ua'

    Captures the User Configuration for Administrators and saves it into a new timestamped folder under `C:\Backups\LGPO`.

    .EXAMPLE
    Save-LocalGPOConfig -LGPOexePath "C:\Tools\LGPO.exe" -backupFolder "C:\Backups\LGPO" -CaptureSet 'un'

    Captures the User Configuration for Non-Administrators and saves it into a new timestamped folder under `C:\Backups\LGPO`.

    .EXAMPLE
    Save-LocalGPOConfig -LGPOexePath "C:\Tools\LGPO.exe" -backupFolder "C:\Backups\LGPO" -CaptureSet 'm','u','ua','un'

    Captures all available configurations (Machine, User, User-Admin, and User-NonAdmin) and saves them into a new timestamped folder under `C:\Backups\LGPO`.
  
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$LGPOexePath,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if (-not (Test-Path -Path $_ -PathType Container)) {
                throw "The specified backup folder '$_' does not exist or is not a folder."
            }
            $true
        })]
        [string]$backupFolder,

        [ValidateSet('m','u','ua','un')]
        [string[]]$scope = @('m','u')
    )

    #Set the paths for the Local Group Policy Object (LGPO) files. 
    #Test variables are not direcltly called rather they are used when setting $basePath.
    $mPath  = "$env:windir\System32\GroupPolicy\Machine\"
    $uPath  = "$env:windir\System32\GroupPolicy\User\"
    $uaPath = "$env:windir\System32\GroupPolicyUsers\s-1-5-32-544\User"
    $unPath = "$env:windir\System32\GroupPolicyUsers\s-1-5-32-545\User"
    
    $newFolder = "Settings_" + (Get-Date).ToString("yyyyMMddHHmmss")
    New-Item -Path $backupFolder -ItemType Directory -Name $NewFolder | Out-Null
    $settingsFolder = Join-Path -Path $backupFolder -ChildPath $newFolder

    # Set ErrorActionPreference to SilentlyContinue and clear the error variable to correct LGPO output.
    $ErrorDefault = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    $data = @()
    foreach ($target in @('m','u','ua', 'un')) {
        if ($scope -contains $target) {
            switch ($target) {
                'm'  {$name = 'Machine'}
                'u'  {$name = 'User'}
                'ua' {$name = 'User_Admin'}
                'un' {$name = 'User_NonAdmin'}
            }

            #Set variables for the target
            $basePath    = Get-Variable -Name ($target + 'Path') -ValueOnly
            $polPath     = "$basePath\Registry.pol"
            $ScriptPath  = "$basePath\Scripts"
            $gpt         = ($target -notin 'm', 'u')
            $parseFlag   = '/'+ $target
            if($gpt){
                $GPTPath = Split-Path $basePath -Parent
            }
            
            #Set the backup files
            $folder = Join-Path $settingsFolder $name
            $backupFile   = Join-Path $folder "${name}_Backup.txt"
            $gptBackup    = Join-Path $folder "${name}_gpt.ini"
            $scriptsZip   = Join-Path $folder "${name}_Scripts.zip"
    
            if (Test-Path $polPath) {
                
                Write-Host "Policy file exists: $polPath" -ForegroundColor Green
                
                # Create the backup folder
                New-Item -Path $folder -ItemType Directory | Out-Null
 
                # Parse the Registry.pol to text
                Start-Process -FilePath $LGPOexePath -ArgumentList "/parse $parseFlag $polPath" -RedirectStandardOutput $backupFile -NoNewWindow -Wait
                
                # Copy gpt.ini
                if ($gpt) {
                    Copy-Item (Join-Path $GPTPath 'gpt.ini') -Destination $gptBackup -Force
                    if (Test-Path $gptBackup) {
                        Write-Host "GPT file copied: $gptBackup" -ForegroundColor Green
                        $gpttest = $gptBackup
                    } else {
                        $gpttest = "Failed"
                        Write-Error "Failed to copy GPT file: $gptBackup"
                    }
                }
    
                # If Scripts.ini has real content, compress the Scripts folder
                if (Test-Path $ScriptPath) {
                    if ((Get-Content -Path (Join-Path $ScriptPath Scripts.ini) -ErrorAction SilentlyContinue).Trim().Length -gt 0) {
                        Compress-Archive -Path $ScriptPath -DestinationPath $scriptsZip -Force
                        If (Test-Path $scriptsZip) {
                            $scriptsTest = $true
                            Write-Host "Scripts folder compressed: $scriptsZip" -ForegroundColor Green
                        } else {
                            $scriptsTest = $false
                            Write-Error "Failed to compress Scripts folder: $scriptsZip"
                        }
                    }
                } else {
                    $scriptsTest = $true
                    $scriptsZip = "Not Applicable"
                    Write-Host "Scripts folder does not exist: $ScriptPath" -ForegroundColor Yellow
                }

                if (Test-Path $backupFile) {
                    $polTest = $true
                    Write-Host "Backup created: $backupFile" -ForegroundColor Green
                } else {
                    $polTest = $false
                    Write-Error "Backup not created: $backupFile"
                }
                          
                $targetInfo = [pscustomobject]@{
                    Name          = $name
                    PolPath       = $polPath
                    ScriptsPath   = $ScriptPath
                    PolBackup     = if($polTest){$backupFile} else {"Failed"}
                    GptBackup     = if($gpt){$gpttest}else{"Not Applicable"}
                    ScriptsBackup = if($scriptsTest){$scriptsZip} else {"Failed"}
                    CaptureTime   = (Get-Date).ToString("s")
                }
                write-host "$($targetInfo)" -ForegroundColor Green          
            }
            else {
                Write-Host "Policy file does not exist: $polPath\Registry.pol"
                $targetInfo = [pscustomobject]@{
                    Name          = $name
                    PolPath       = "$null"
                    ScriptsPath   = "$null"
                    PolBackup     = "$null"
                    GptBackup     = "$null"
                    ScriptsBackup = "$null"
                    CaptureTime   = (Get-Date).ToString("s")
                }  
            }
            $data += $targetInfo
        }
    }

    # Export the data to a JSON file
    $data | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $settingsfolder 'Backup_data.json') -Encoding UTF8
    return $data
    
    # Set ErrorActionPreference back to default
    $ErrorActionPreference = $ErrorDefault
}

Function Restore-LocalGPOConfig {
    [CmdletBinding()]
    param (
        # Reset is used to remove all policies within the local scope.
        [switch]$Reset,
    
        [Parameter(Mandatory)]
        [string]$LGPOexePath,
    
        [Parameter(Mandatory)]
        [ValidateScript({
            if (-not (Test-Path $_)) {
                throw "The specified backup folder '$_' does not exist."
            }
            $jsonFilePath = Join-Path $_ 'Backup_data.json'
            if (-not (Test-Path $jsonFilePath)) {
                throw "The backup folder '$_' does not contain a Backup_data.json file."
            }
            $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
    
            $requiredProperties = @('Name', 'PolPath', 'ScriptsPath', 'PolBackup', 'GptBackup', 'ScriptsBackup')
            foreach ($entry in $jsonContent) {
                foreach ($prop in $requiredProperties) {
                    if (-not ($entry.PSObject.Properties.Name -contains $prop)) {
                        throw "Backup_data.json entry is missing required property '$prop'."
                    }
                }
                if (-not ($entry.Name -in @('Machine', 'User', 'User_Admin', 'User_NonAdmin'))) {
                    throw "Backup_data.json entry 'Name' must be 'Machine', 'User', 'User_Admin', or 'User_NonAdmin'."
                }
            }
            $true
        })]
        [string]$BackupFolder,
    
        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($BackupFolder -and -not $UseBackupScope) {
                throw "The parameter '-UseBackupScope' is only valid when '-BackupFolder' is specified."
            }
            $true
        })]
        [switch]$UseBackupScope,
    
        [ValidateSet('m','u','ua','un')]
        [string[]]$Scope = @('m','u'),
    
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
            $requiredProperties = @('Name', 'PolBackup', 'GptBackup', 'ScriptsBackup')
            foreach ($prop in $requiredProperties) {
                if (-not ($_.PSObject.Properties.Name -contains $prop)) {
                    throw "InputData is missing required property '$prop'."
                }
            }
            if (-not ($_.Name -in @('Machine', 'User', 'User_Admin', 'User_NonAdmin'))) {
                throw "InputData 'Name' must be 'Machine', 'User', 'User_Admin', or 'User_NonAdmin'."
            }
            $true
        })]
        [pscustomobject]$PipelineData
    )

    $ErrorDefault = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    #Set the paths for the Local Group Policy Object (LGPO) files. 
    $mPath  = "$env:windir\System32\GroupPolicy\Machine\"
    $uPath  = "$env:windir\System32\GroupPolicy\User\"
    $uaPath = "$env:windir\System32\GroupPolicyUsers\s-1-5-32-544\User"
    $unPath = "$env:windir\System32\GroupPolicyUsers\s-1-5-32-545\User"

    If ($Reset) {
        foreach ($target in @('m','u','ua','un')) {
            if ($scope -contains $target) {
                $basePath = Get-Variable -Name ($target + 'Path') -ValueOnly
                Write-Host "Removing all policies in $basePath" -ForegroundColor Yellow
                Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue |
                ForEach-Object {Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction SilentlyContinue}
                Write-Host "Removed all policies in $basePath" -ForegroundColor Green
            }
        }
        Exit 0
    }Else {
        Write-Host "Restoring policies from backup..." -ForegroundColor Yellow
        foreach ($target in @('m','u','ua','un')) {
            if ($scope -contains $target) {
                switch ($target) {
                    'm'  {$name = 'Machine'}
                    'u'  {$name = 'User'}
                    'ua' {$name = 'User_Admin'}
                    'un' {$name = 'User_NonAdmin'}
                }

                #Set variables for the target
                $basePath    = Get-Variable -Name ($target + 'Path') -ValueOnly
                $polPath     = "$basePath\Registry.pol"
                $ScriptPath  = "$basePath\Scripts"
                $gpt         = ($target -notin 'm', 'u')
                $parseFlag   = '/'+ $target
                
                #Set the backup files
                $folder = Join-Path $backupFolder $name
                $backupFile   = Join-Path $folder "${name}_Backup.txt"
                $gptBackup    = Join-Path $folder "${name}_gpt.ini"
                $scriptsZip   = Join-Path $folder "${name}_Scripts.zip"

                if (Test-Path $backupFile) {
                    Write-Host "Restoring from backup: $backupFile" -ForegroundColor Green

                    # Restore the Registry.pol from text
                    & "$LGPOexePath" /r "$backupFile" /w "$polPath"

                    # Restore gpt.ini if applicable
                    if ($gpt) {
                        Copy-Item -Path "$gptBackup" -Destination "$env:windir\System32\GroupPolicy\gpt.ini" -Force
                        Write-Host "Restored gpt.ini from backup: $gptBackup" -ForegroundColor Green
                    }

                    # Restore Scripts folder if applicable and zip exists
                    if (Test-Path $scriptsZip) {
                        Expand-Archive -Path "$scriptsZip" -DestinationPath "$ScriptPath" -Force
                        Write-Host "Restored Scripts folder from backup: $scriptsZip" -ForegroundColor Green
                    } else {
                        Write-Host "No Scripts folder to restore." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "No backup file found for: $backupFile" -ForegroundColor Red
                }
            }

    if ($RestoreSet -contains 'm') {
        $machineBackup = Join-Path $backupFolder 'Machine_Backup.txt'
        if (Test-Path $machineBackup) {
            & "$LGPOexePath" /t "$machineBackup"
            Copy-Item (Join-Path $backupFolder 'Machine_gpt.ini') "$env:windir\System32\GroupPolicy\gpt.ini" -Force
            Write-Host "Machine policy restored from text." -ForegroundColor Green
        }
    }

    if ($RestoreSet -contains 'u') {
        $userBackup = Join-Path $backupFolder 'User_Backup.txt'
        if (Test-Path $userBackup) {
            & "$LGPOexePath" /t "$userBackup"
            Copy-Item (Join-Path $backupFolder 'User_gpt.ini') "$env:windir\System32\GroupPolicy\gpt.ini" -Force
            Write-Host "User policy restored from text." -ForegroundColor Green
        }
    }

    if ($RestoreSet -contains 'ua') {
        $adminBackup = Join-Path $backupFolder 'User_Admin_Backup.txt'
        if (Test-Path $adminBackup) {
            $adminPath = "$env:windir\System32\GroupPolicyUsers\S-1-5-32-544\User"
            if (-not (Test-Path $adminPath)) {
                New-Item -ItemType Directory -Path $adminPath | Out-Null
            }
            & "$LGPOexePath" /r "$adminBackup" /w "$adminPath\Registry.pol"
            Copy-Item (Join-Path $backupFolder 'User_Admin_gpt.ini') "$adminPath\gpt.ini" -Force
            Write-Host "User Admin policy restored from text." -ForegroundColor Green
        }
    }

    if ($RestoreSet -contains 'un') {
        $nonAdminBackup = Join-Path $backupFolder 'User_NonAdmin_Backup.txt'
        if (Test-Path $nonAdminBackup) {
            $nonAdminPath = "$env:windir\System32\GroupPolicyUsers\S-1-5-32-545\User"
            if (-not (Test-Path $nonAdminPath)) {
                New-Item -ItemType Directory -Path $nonAdminPath | Out-Null
            }
            & "$LGPOexePath" /r "$nonAdminBackup" /w "$nonAdminPath\Registry.pol"
            Copy-Item (Join-Path $backupFolder 'User_NonAdmin_gpt.ini') "$nonAdminPath\gpt.ini" -Force
            Write-Host "User Non-Admin policy restored from text." -ForegroundColor Green
        }
    }

    $ErrorActionPreference = $ErrorDefault

    Write-Host "Triggering gpupdate to refresh policies..." -ForegroundColor Yellow
    gpupdate /force
}}}

Function ConvertFrom-LGPO {
    <#
    .SYNOPSIS
    Parses LGPO settings from a text file or piped text input into a clean PowerShell object list.

    .DESCRIPTION
    Takes input from either a file path (-Path) or from pipeline content.  
    Skips comment lines and empty lines.  
    Every 4 lines are expected to define:
      - Hive
      - Registry Key Path
      - Value Name
      - Value Type and Data (split by ':')

    Returns a table of Hive, Path, Name, Type, and Data.

    .PARAMETER Path
    Path to the text file containing LGPO settings.

    .PARAMETER InputObject
    Lines of text input piped into the function.

    .EXAMPLE
    Parse-LGPOTextFile -Path "C:\Policies\settings.txt"

    .EXAMPLE
    Get-Content "C:\Policies\settings.txt" | Parse-LGPOTextFile

    #>

    [CmdletBinding(DefaultParameterSetName="Path")]
    param (
        [Parameter(ParameterSetName="Path", Mandatory=$true, Position=0)]
        [ValidateScript({Test-Path $_})]
        [string]$Path,

        [Parameter(ParameterSetName="InputObject", ValueFromPipeline=$true, Mandatory=$true)]
        [string[]]$InputObject
    )

    begin {
        $lines = @()
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $lines = Get-Content -Path $Path
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'InputObject') {
            $lines += $InputObject
        }
    }

    end {
        # Filter out empty and comment lines
        $lines = $lines | Where-Object { $_.Trim() -and -not ($_ -match '^\s*;') }

        if ($lines.Count % 4 -ne 0) {
            throw "Input does not contain a complete set of records (4 lines per record expected)."
        }

        $settings = @()

        for ($i = 0; $i -lt $lines.Count; $i += 4) {
            $hiveLine = $lines[$i].Trim()
            $pathLine = $lines[$i + 1].Trim()
            $nameLine = $lines[$i + 2].Trim()
            $typeDataLine = $lines[$i + 3].Trim()

            $type, $data = $typeDataLine -split ":", 2

            $settings += [pscustomobject]@{
                Hive = $hiveLine
                Path = $pathLine
                Name = $nameLine
                Type = $type.Trim()
                Data = $data.Trim()
            }
        }

        return $settings
    }
}

Function ConvertTo-LGPO {
    <#
    .SYNOPSIS
    Converts parsed LGPO settings into a flat text format.

    .DESCRIPTION
    Takes an array of objects (with Hive, Path, Name, Type, Data) and converts them into  
    a text format where each setting is expanded into multiple lines:  
    Hive, Path, Name, Type:Data, with a blank line separating entries.

    .PARAMETER InputObject
    The parsed LGPO settings objects to convert.

    .OUTPUTS
    A string array representing the text format.

    .EXAMPLE
    $parsed = Parse-LGPOTextFile -Path "settings.txt"
    $text = $parsed | ConvertTo-LGPO
    $text | Set-Content -Path "LGPOExport.txt"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [pscustomobject[]]$InputObject
    )

    begin {
        $LGPOData = @()
    }
    process {
        foreach ($setting in $InputObject) {
            $LGPOData += $setting.Hive
            $LGPOData += $setting.Path
            $LGPOData += $setting.Name
            $LGPOData += "$($setting.Type):$($setting.Data)"
            $LGPOData += ""  # Blank line between entries
        }
    }
    end {
        return $LGPOData
    }
}

Function Compare-LGPO {
    <#
    .SYNOPSIS
    Compares two LGPO settings files and outputs the differences.

    .DESCRIPTION
    Takes two LGPO settings files, parses them, and compares the settings.  
    Outputs the differences in a readable format.

    .PARAMETER File1
    The first LGPO settings file to compare.

    .PARAMETER File2
    The second LGPO settings file to compare.

    .EXAMPLE
    Compare-LGPO -File1 "C:\Policies\settings1.txt" -File2 "C:\Policies\settings2.txt"

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$File1,

        [Parameter(Mandatory=$true)]
        [string]$File2
    )

    begin {
        $file1Settings = Parse-LGPOTextFile -Path $File1
        $file2Settings = Parse-LGPOTextFile -Path $File2
    }

}

Function Test-LocalPolicy {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [pscustomobject[]]$InputObject
    )





    $mPath  = "$env:windir\System32\GroupPolicy\Machine\Registry.pol"
    $uPath  = "$env:windir\System32\GroupPolicy\User\Registry.pol"
    $uaPath = "$env:windir\System32\GroupPolicyUsers\s-1-5-32-544\User\Registry.pol"
    $unPath = "$env:windir\System32\GroupPolicyUsers\s-1-5-32-545\User\Registry.pol"

    

    

}