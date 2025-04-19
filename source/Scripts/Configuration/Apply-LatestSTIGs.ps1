<#
.SYNOPSIS
    Applies DISA STIG Group Policy Objects (GPOs) and related configurations from local or remote packages.

.DESCRIPTION
    This script automates the deployment of STIG-compliant GPOs using LGPO.exe. It supports retrieving GPO packages from 
    the public DoD STIG site or from local or network sources. It handles copying ADMX/ADML templates, executing LGPO.exe 
    to apply each policy, and optionally applying application-specific STIG templates.

    The script also supports delta GPO packages that are applied after the baseline STIGs. These GPOs are sorted by their 
    full path to allow for controlled application order. In the example below, the STIGs in C:\STIGs\Delta\2\ would be 
    applied after those in C:\STIGs\Delta\1\:

        - C:\STIGs\Delta\1\GPOs\Complicated_Stuff.GPO
        - C:\STIGs\Delta\2\GPOs\Important_Stuff.GPO

    The script also performs additional Windows hardening, including DEP enforcement, 
    disabling legacy features (e.g., PowerShell v2, Secondary Logon), and applying registry-based mitigations.

.PARAMETER LocalPkg
    If specified, uses a local or network ZIP package of STIG GPOs instead of downloading from the DoD site.

.PARAMETER LocalZipPath
    The full path to the STIG ZIP package. Required when -LocalPkg is specified.

.PARAMETER LocalLGPO
    If specified, uses a local or network LGPO.exe executable instead of downloading it from Microsoft.

.PARAMETER LGPOPath
    The full path to a local LGPO.exe executable. Required if -LocalLGPO is used and LGPO.exe is not present in System32.

.PARAMETER ApplyAppSTIGs
    One or more application-specific STIG templates to apply. Options include:
        - Adobe Acrobat Pro DC
        - Adobe Acrobat Reader DC
        - Google Chrome
        - Mozilla Firefox
        - Office 2019-M365 Apps
        - Office System 2013
        - Office System 2016

.PARAMETER DeltaGPO
    If specified, applies delta GPOs from a separate folder to extend or override baseline STIG settings.

.PARAMETER DeltaPath
    The root folder that contains at least one subfolder named 'GPOs'. Required if -DeltaGPO is used.

.PARAMETER TestGPOInstall
    If specified, runs each LGPO command in test mode (using `/help` instead of applying policies).

.EXAMPLE
    .\Apply-STIGs.ps1 -LocalPkg -LocalZipPath "C:\STIGs\U_STIG_GPO_Package.zip"

.EXAMPLE
    .\Apply-STIGs.ps1 -ApplyAppSTIGs "Google Chrome", "Office 2019-M365 Apps"

.EXAMPLE
    .\Apply-STIGs.ps1 -LocalLGPO -LGPOPath "C:\Tools\LGPO.exe" -DeltaGPO -DeltaPath "C:\STIGs\Deltas"

.NOTES
    Author: SSF
    Original Scource: https://github.com/AVDClientKiosk
    Last Updated: 3/22/2025
    Tested On: Windows 11

.LINK
    https://public.cyber.mil/stigs/downloads
    https://www.microsoft.com/en-us/download/details.aspx?id=55319
#>




[CmdletBinding(SupportsShouldProcess = $true)]
param (
    # If this switch is specified, the function uses a local or network STIG package instead of parsing the DoD STIG website.
    [Parameter(Mandatory = $false)]
    [switch]$LocalPkg,

    # LocalPath is required when using -UseLocalPackage to point to the local STIG Zip package.
    [Parameter(Mandatory = $false)]
    [ValidateScript({If ($_ -notmatch "\.zip$") {Throw "FilePath must end in .zip"} $true })]
    [string]$LocalZipPath,

    # If this switch is specified, the function uses a local LGPO executable.
    [Parameter(Mandatory = $false)]
    [switch]$LocalLGPO,

    # LocalPath is required unless the file is in System32 when using -LocalLGPO to point to the local LGPO executable.
    [Parameter(Mandatory = $false)]
    [ValidateScript({If ($_ -notmatch "\.exe$") {Throw "LGPO must be an executable file"} $true })]
    [string]$LGPOPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet(
        "Adobe Acrobat Pro DC",
        "Adobe Acrobat Reader DC",
        "Google Chrome",
        "Mozilla Firefox",
        "Office 2019-M365 Apps",
        "Office System 2013",
        "Office System 2016"
    )]
    [string[]]$ApplyAppSTIGs,

    # If this switch is specified, delta GPOs in the corect format can be applied.
    [Parameter(Mandatory = $false)]
    [switch]$DeltaGPO,

    # DeltapPath is required when using -DeltaGPO.
    [Parameter(Mandatory = $false)]
    [ValidateScript({
    if (-not (Test-Path $_)) {throw "Path does not exist: $_"}

    $hasGPOFolder = Get-ChildItem -Path $_ -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'GPOs' }
    if (-not $hasGPOFolder) {throw "Path must contain at least one folder named 'GPOs'."}
    return $true
    })]
    [string]$DeltaPath,

    # If this switch is specified, the function uses a local or network STIG package instead of parsing the DoD STIG website.
    [Parameter(Mandatory = $false)]
    [switch]$TestGPOInstall

    )

#region Initialization

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name=[System.IO.Path]::GetFileNameWithoutExtension($Script:File)

# Check if running in a 32-bit process on a 64-bit OS
If (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    Try {
        # Convert bound parameters into a PowerShell-compatible argument list
        $Script:Args = @()
        foreach ($k in $MyInvocation.BoundParameters.Keys) {
            $paramValue = $MyInvocation.BoundParameters[$k]
            switch ($paramValue.GetType().Name) {
                "SwitchParameter" { if ($paramValue.IsPresent) { $Script:Args += "-$k" } }
                "String"          { $Script:Args += "-$k `"$paramValue`"" }
                "Int32"           { $Script:Args += "-$k $paramValue" }
                "Boolean"         { $Script:Args += "-$k `$$paramValue" }
            }
        }

        # Relaunch in 64-bit PowerShell
        $PowerShell64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
        $ScriptArgsString = $Script:Args -Join " "

        If ($ScriptArgsString) {
            Start-Process -FilePath $PowerShell64 -ArgumentList "-File `"$($Script:FullName)`" $ScriptArgsString" -Wait -NoNewWindow
        } 
        Else {
            Start-Process -FilePath $PowerShell64 -ArgumentList "-File `"$($Script:FullName)`"" -Wait -NoNewWindow
        }
    }
    Catch {
        Throw "Failed to start 64-bit PowerShell"
    }
    Exit
}

# Validate the Local variables
$LGPOInstaled = Test-Path -Path "$env:SystemRoot\System32\LGPO.exe"
If ($LocalPkg.IsPresent) {If (-not $LocalZipPath) {Throw "ERROR: -LocalZipPath is required when using -LocalPkg."}}
If ($LocalLGPO.IsPresent) {If ((!($LGPOPath)) -and (!($LGPOInstaled))){Throw "ERROR: -LGPOPath is required when using -LocalLGPO."}}

# Start Transcript Logging
$Script:LogDir = "$env:SystemRoot\Logs\Configuration"
If (-not (Test-Path -Path $Script:LogDir)) {New-Item -Path $Script:LogDir -ItemType Directory -Force}
$Script:LogName = "$Script:Name.log"
$Script:LogFilePath = "$Script:LogDir\$Script:LogName"
If (Test-Path $Script:LogFilePath) {Remove-Item $Script:LogFilePath -Force}
Start-Transcript -Path $Script:LogFilePath

#region Functions

Function Set-BluetoothRadioStatus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Off', 'On')]
        [string]$BluetoothStatus
    )

    # Ensure the Bluetooth service is running
    If ((Get-Service -Name 'bthserv').Status -eq 'Stopped') {Start-Service -Name 'bthserv'}

    Try {
        # Add required .NET types for working with WinRT
        Add-Type -AssemblyName System.Runtime.WindowsRuntime

        # Get the generic AsTask<T> method
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
            Where-Object {
                $_.Name -eq 'AsTask' -and
                $_.GetParameters().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType.Name -like 'IAsyncOperation`1'
            })[0]

        # Helper function to await a WinRT async method and return result
        function Await ($WinRtTask, $ResultType) {
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            return $netTask.Result
        }

        # Load necessary Windows Runtime types
        [Windows.Devices.Radios.Radio, Windows.System.Devices, ContentType = WindowsRuntime] | Out-Null
        [Windows.Devices.Radios.RadioAccessStatus, Windows.System.Devices, ContentType = WindowsRuntime] | Out-Null
        [Windows.Devices.Radios.RadioState, Windows.System.Devices, ContentType = WindowsRuntime] | Out-Null

        # Request access and get list of radios
        Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])

        # Locate the Bluetooth radio
        $bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' }

        # If found, set its state
        If ($bluetooth) {
            Await ($bluetooth.SetStateAsync($BluetoothStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        }
    } Catch {
        Write-Warning "Set-BluetoothRadioStatus function encountered an error: $_"
    }
}

Function Get-STIGLink {
    [CmdletBinding()]
    Param (
        
        # Default DoD STIG GPO URL
        [Parameter(Mandatory = $false)]
        [string]$Url = 'https://public.cyber.mil/stigs/gpo',

        [Parameter(Mandatory = $false)]
        [string]$searchstring = '*U_STIG_GPO_Package*'
    )

    Begin {
        # Capture the function name for consistent logging
        [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "$($CmdletName): Starting with parameters: $PSBoundParameters"
    }

    Process {
        try {
                    Write-Verbose "$($CmdletName): Checking DoD STIG site: $Url"
                    
                    $STIGLink = Invoke-WebRequest -Uri $Url -UseBasicParsing |
                                Select-Object -ExpandProperty Links |
                                Where-Object { $_.href -like "*U_STIG_GPO_Package*" } |
                                Select-Object -ExpandProperty href

                    # Return the single link if exactly one match; if multiple, return the first
                    if ($STIGLink.Count -eq 1) {
                        Write-Verbose "$($CmdletName): Found link: $STIGLink"
                        return $STIGLink
                    }
                    elseif ($STIGLink.Count -gt 1) {
                        Write-Verbose "$($CmdletName): Multiple matches found. Returning first: $($STIGLink[0])"
                        return $STIGLink[0]
                    }
                    else {
                        Write-Error "$($CmdletName): Could not find a link matching '$SearchString' on $Url"
                    }
                } catch {Write-Error "$($CmdletName): Error retrieving STIG settings. $_"}
        }

    End {Write-Verbose "$($CmdletName): Completed."}
}

Function Get-InternetFile {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [uri]$Url,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$OutputFileName,

        [Parameter(Mandatory = $false)]
        [switch]$ForceDownload,

        [Parameter(Mandatory = $false)]
        [string[]]$ValidExtensions = @(".zip", ".msi", ".exe", ".cab", ".tar", ".gz", ".ps1")
    )

    Begin {
        $CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "$($CmdletName): Starting with parameters: $PSBoundParameters"
    }

    Process {
        Try {
            # Ensure output directory exists
            If (-not (Test-Path $OutputDirectory)) {
                Write-Verbose "$($CmdletName): Creating output directory: $OutputDirectory"
                New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
            }

            # Extract file name from URL if not provided
            If (-not $OutputFileName) {
                $OutputFileName = [System.IO.Path]::GetFileName($Url.AbsolutePath)
                Write-Verbose "$($CmdletName): Extracted file name from URL: $OutputFileName"
            }

            # Define full output path
            $OutputFile = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

            # Extract file extension from the URL
            $FileExtension = [System.IO.Path]::GetExtension($OutputFileName)

            # Validate the file extension unless ForceDownload is enabled
            If (-not $ForceDownload) {
                If ($FileExtension -eq "" -or $ValidExtensions -notcontains $FileExtension.ToLower()) {
                    Throw "$($CmdletName): URL does not contain a valid file extension! (Found: '$FileExtension'). Use -ForceDownload to bypass."
                }
            }

            # Download the file
            Write-Verbose "$($CmdletName): Downloading $Url to $OutputFile"
            Invoke-WebRequest -Uri $Url -OutFile $OutputFile

            # Verify successful download
            If (Test-Path $OutputFile) {
                $FileSize = (Get-Item $OutputFile).Length / 1MB
                Write-Verbose "$($CmdletName): Download successful. File size: $FileSize MB"
                Return $OutputFile
            }
            Else {
                Throw "$($CmdletName): Download failed file not found after download attempt."
            }
        }
        Catch {
            Write-Error "$($CmdletName): Error downloading file: $_"
            Return $null
        }
    }
    End {
        Write-Verbose "$($CmdletName): Completed."
    }
}

Function Get-STIGOS {
    [CmdletBinding()]
    Param ()

    # Get OS Information
    $OSInfo = Get-CimInstance Win32_OperatingSystem
    $STIG_OS = $null

    Write-Verbose "Checking OS: $($OSInfo.Caption) (Version: $($OSInfo.Version), Build: $($OSInfo.BuildNumber))"

    # Detect Windows 10 or Windows 11
    If ($OSInfo.ProductType -eq 1 -and $OSInfo.Version -match "^10\.") {
        If ($OSInfo.BuildNumber -ge 22000) {
            $STIG_OS = "Windows 11"
        }
        Else {
            $STIG_OS = "Windows 10"
        }
    }

    # Detect Windows Server Versions
    ElseIf ($OSInfo.ProductType -gt 1) {
        If ($OSInfo.Caption -match "2022") {
            $STIG_OS = "WinSvr 2022"
        }
        ElseIf ($OSInfo.Caption -match "2016") {
            $STIG_OS = "WinSvr 2016"
        }
        ElseIf ($OSInfo.Caption -match "2012") {
            $STIG_OS = "WinSvr 2012 R2"
        }
    }

    # If no match is found, return Unknown OS
    If (-not $STIG_OS) {
        $STIG_OS = "Unknown OS ($($OSInfo.Caption))"
        Write-Error "ERROR: Unknown OS detected: $OSInfo.Caption"
    }

    Write-Verbose "OS Identified: $STIG_OS"
    Return $STIG_OS
}

Function Get-STIGs {
    [CmdletBinding()]
    Param (
        # Determines the source type
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Internet")]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Local")]
        [ValidateSet("Internet", "Local")]
        [string]$Source,

        # File path to STIG zip file on local or network storage (Only available when SourceType = "Internet")
        [Parameter(Mandatory = $true, ParameterSetName = "Internet")]
        [string]$DownloadURL,

         # File path to STIG zip file on local or network storage (Only available when SourceType = "Local")
        [Parameter(Mandatory = $true, ParameterSetName = "Local")]
        [ValidateScript({If ($_ -notmatch "\.zip$") {Throw "FilePath must end in .zip"} $true })]
        [string]$ZipPath,

        # Directory for temporary storage
        [Parameter(Mandatory = $false)]
        [string]$TempDir = "$env:TEMP",

        # Output directory for extracted GPOs
        [Parameter(Mandatory = $false)]
        [string]$OutputDir = "$env:TEMP\GPOs"
    )

    Begin {
        [string]$CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "$($CmdletName): Starting with parameters: $PSBoundParameters"
    }

    Process {
        Switch ($Source) {
            "Internet" {
                If (-not $DownloadURL) {
                    Write-Error "$($CmdletName): ERROR: No URL provided for STIG download!"
                    Return $false
                }

                Write-Verbose "$($CmdletName): Downloading STIGs from: $DownloadURL"
                $STIGZipPath = Get-InternetFile -Url $DownloadURL -OutputDirectory $TempDir
                Write-Verbose "$($CmdletName): Downloaded STIGs from: $DownloadURL"

                # Ensure the file was downloaded successfully
                If (-not (Test-Path $STIGZipPath)) {
                    Write-Error "$($CmdletName): ERROR: Download failed or file not found: $STIGZipPath"
                    Return $false
                }
            }

            "Local" {
                If (-not $ZipPath) {
                    Write-Error "$($CmdletName): ERROR: No file path provided for STIG ZIP!"
                    Return $false
                }
                If (-not (Test-Path $ZipPath)) {
                    Write-Error "$($CmdletName): ERROR: STIG ZIP not found at: $ZipPath"
                    Return $false
                }

                Copy-Item -Path $ZipPath -Destination $TempDir -Force
                Write-Verbose "$($CmdletName): Copyed STIGs from: $ZipPath"
                $STIGZipPath = Join-Path -Path $TempDir -ChildPath ([System.IO.Path]::GetFileName($ZipPath))
            }
        }

        # Ensure the STIG ZIP exists before proceeding
        If (-not (Test-Path $STIGZipPath)) {
            Write-Error "$($CmdletName): ERROR: STIG ZIP missing after attempted download/copy: $STIGZipPath"
            Return $false
        }
        # Remove existing extracted GPOs
        If (Test-Path $OutputDir) {
            Write-Verbose "$($CmdletName): Removing existing GPO directory: $OutputDir"
            Remove-Item -Path $OutputDir -Recurse -Force
        }

        # Extract the ZIP file
        Expand-Archive -Path $STIGZipPath -DestinationPath $OutputDir -Force
        Write-Verbose "$($CmdletName): Extracted STIG GPOs from $STIGZipPath"

        # Cleanup: Remove the ZIP file after extraction
        Write-Verbose "$($CmdletName): Removing ZIP file: $STIGZipPath"
        Remove-Item -Path $STIGZipPath -Force -ErrorAction SilentlyContinue

        # Verify extraction success
        If (Test-Path $OutputDir) {
            Write-Verbose "$($CmdletName): STIG GPOs successfully extracted to: $OutputDir"
            Return $OutputDir
            }
        Else {
            Write-Error "$($CmdletName): ERROR: Extraction failed!"
            Return $false
        }
    }
}
Function Set-GPOBackups {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$Folder,

        [Parameter(Mandatory = $false)]
        [switch]$Test
    )

    Begin {
        $CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "$($CmdletName): Starting GPO application for folders..."
        $GPOFolders = @()
    }

    Process {
        foreach ($path in $Folder) {
            Write-Verbose " - $path"

            $gpoFolder = Get-ChildItem -Recurse -Path $path -Filter 'GPOs' -Directory -ErrorAction SilentlyContinue | Sort-Object FullName
            if ($gpoFolder) {
                $GPOFolders += $gpoFolder.FullName
            } else {
                Write-Warning "$($CmdletName): No 'GPOs' folder found in '$path'. Skipping..."
            }
        }
    }

    End {
        foreach ($gpoFolder in $GPOFolders) {
            $command = "$env:SystemRoot\System32\lgpo.exe"
            if ($Test.IsPresent) {
                $output = & $command "/fake" 2>&1
                Write-Output "TEST MODE: LGPO.exe $args $gpoFolder "
            } else {
                Write-Output "$($CmdletName): Implementing GPOs in $gpoFolder"
                $ErrorActionPreference = 'SilentlyContinue'
                $output = & cmd.exe /c $command /g "$gpoFolder" 2>&1
                $ErrorActionPreference = 'SilentlyContinue'
                ForEach($line in $output){Write-Output "   $line"}
            }
        }
        Write-Verbose "$($CmdletName): Completed."
    }
}

#endregion

#region Main
$STIGdir = $null
If ($LocalPkg.IsPresent) {
    If (Test-Path $LocalZipPath){Write-Output "Using local STIG package: $LocalZipPath"}
    Else {Throw "ERROR: LocalPath '$LocalZipPath' not found."}
   
    $STIGdir = Get-STIGs -Source Local -ZipPath $LocalZipPath
}
Else {
    Write-Verbose "Downloading STIG package"
    #downloading and use remote package
    $Url = Get-STIGLink
    $STIGdir = Get-STIGs -Source Internet -DownloadURL $Url
}

#Download LGPO and copy it to System32
If (!(test-path "$env:SystemRoot\System32\LGPO.exe")) {
    $fileLGPO = $null
    $outputDir = $null
    If (($LocalLGPO.IsPresent) -and ($LGPOPath)) {
        
        If (Test-Path $LGPOPath){Write-Output "Using local LGPO.exe from $LGPOPath"}
        Else {Throw "ERROR: Local LGPO.exe '$LGPOPath' not found."}
        $fileLGPO = $LGPOPath
    }
    Else {
        Write-Output "Retrieving LGPO.exe package from Microsoft.com"
        # Logic for downloading and using remote package
        $urlLGPO = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip'
        $fileLGPODownload = Get-InternetFile -Url $urlLGPO -OutputDirectory $env:Temp
        Write-Verbose "LGPO.exe downloaded from $urlLGPO to $env:Temp"
        $outputDir = "$env:Temp\LGPO"
        Expand-Archive -Path $fileLGPODownload -DestinationPath $outputDir
        Remove-Item $fileLGPODownload -Force
        $fileLGPO = (Get-ChildItem -Path $outputDir -file -Filter 'lgpo.exe' -Recurse)[0].FullName
    }

    Copy-Item -Path $fileLGPO -Destination "$env:SystemRoot\System32" -Force
    Write-Output "Copied LGPO.exe to $env:SystemRoot\System32"
    if($outputDir){Remove-Item -Path $outputDir -Recurse -Force}
}

#Microsoft ADMX and ADML files are copied into the PolicyDefinitions folder
$A = Join-Path -Path $STIGdir -ChildPath "ADMX Templates\Microsoft"

# Copy all .admx files from Microsoft ADMX Templates
$null = Get-ChildItem -Path $A -File -Recurse -Filter '*.admx' |
    ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$env:WINDIR\PolicyDefinitions\" -Force
    }

# Copy all .adml files from en-us subfolders under Microsoft ADMX Templates
$null = Get-ChildItem -Path $A -Directory -Recurse |
    Where-Object { $_.Name -eq 'en-us' } |
    Get-ChildItem -File -Recurse -Filter '*.adml' |
    ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$env:WINDIR\PolicyDefinitions\en-us\" -Force
    }

Write-Output "Copied Microsoft ADMX and ADML files to $env:WINDIR\PolicyDefinitions\."

#Application ADMX and ADML files are copied into the PolicyDefinitions folder if -ApplyAppSTIGs is used
if($ApplyAppSTIGs){
    # Define PolicyDefinitions destination
    $ADMXDest = "$env:WINDIR\PolicyDefinitions"
    $ADMLDest = Join-Path -Path $ADMXDest -ChildPath "en-us"

    # Copy all .admx files, excluding those from the 'Microsoft' folder
    $admxFiles = Get-ChildItem -Path "$STIGdir\ADMX Templates" -Recurse -File -Filter '*.admx' | Where-Object { $_.FullName -notlike "*\Microsoft\*" }

    foreach ($file in $admxFiles) {Copy-Item -Path $file.FullName -Destination $ADMXDest -Force}

    # Copy all .adml files from 'en-us' subfolders, excluding those in 'Microsoft'
    $admlFolders = Get-ChildItem -Path "$STIGdir\ADMX Templates" -Directory -Recurse | Where-Object {$_.Name -eq 'en-us' -and $_.FullName -notlike "*\Microsoft\*"}
      foreach ($folder in $admlFolders) {
        $admlFiles = Get-ChildItem -Path $folder.FullName -Recurse -File -Filter '*.adml'
        foreach ($file in $admlFiles) {
            Copy-Item -Path $file.FullName -Destination $ADMLDest -Force
        }
    }

    Write-Output "Copied App ADMX and ADML files to $ADMXDest."
}

$OS = Get-STIGOS

Write-Verbose "Getting list of applicable Windows GPO folders..."

# Define patterns to match folder names
$matchPatterns = @()
$matchPatterns += @(
    $OS,
    "Edge",
    "Firewall",
    "Internet Explorer",
    "Defender Antivirus"
)

if($ApplyAppSTIGs){$matchPatterns += $ApplyAppSTIGs}

# Combine patterns into a single regex (escaped if needed)
$patternRegex = ($matchPatterns -join "|") -replace '\s+', ' '

# Filter GPO folders based on match
$ApplicableGPOs = Get-ChildItem -Path $STIGdir | Where-Object { $_.Name -match $patternRegex }

# Output for visibility (optional)
$ApplicableGPOs | ForEach-Object { Write-Verbose "Matched GPO: $($_.Name)" }

IF($TestInstall.IsPresent){$ApplicableGPOs.FullName | Set-GPOBackups -test}Else{$ApplicableGPOs.FullName | Set-GPOBackups}

#Apply Deltas to STIGs by alphabetical order numarical subfolders may be needed for corret precedence - Please Test
If($DeltaGPO.IsPresent){
    IF($TestInstall.IsPresent){$DeltaPath | Set-GPOBackups -test}Else{$ApplicableGPOs.FullName | Set-GPOBackups}
    }

#Set Aditional Windows 10 & 11 settings
If($OS -like "Windows 1*"){
    #Disable Windows PowerShell V2
    Write-Output "V-220728: Disabling the PowerShell V2."
    If ((Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -eq 'MicrosoftWindowsPowerShellV2Root'}).State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
    }

    #Disable Secondary Logon Service
    Write-Output "V-220732: Disabling the Secondary Logon Service."
    $Service = 'SecLogon'
    $Serviceobject = Get-Service | Where-Object {$_.Name -eq $Service}
    If ($Serviceobject) {
        $StartType = $ServiceObject.StartType
        If ($StartType -ne 'Disabled') {
            start-process -FilePath "reg.exe" -ArgumentList "ADD HKLM\System\CurrentControlSet\Services\SecLogon /v Start /d 4 /T REG_DWORD /f" -PassThru -Wait
        }
        If ($ServiceObject.Status -ne 'Stopped') {
            Try {
                Stop-Service $Service -Force
            }
            Catch {
            }
        }
    }

    <# Enables DEP. If there are bitlocker encrypted volumes, bitlocker is temporarily suspended for this operation
    Configure DEP to at least OptOut
    V-220726 Windows 10
    V-253283 Windows 11
    #>

    Write-Output "V-220726: Checking to see if DEP is enabled."
    $nxOutput = BCDEdit /enum '{current}' | Select-string nx
    if (-not($nxOutput -match "OptOut" -or $nxOutput -match "AlwaysOn")) {
        Write-Output "DEP is not enabled. Enabling."
        # Determines bitlocker encrypted volumes
        $encryptedVolumes = (Get-BitLockerVolume | Where-Object {$_.ProtectionStatus -eq 'On'}).MountPoint
        if ($encryptedVolumes.Count -gt 0) {
            Write-Log -EventId 1 -Message "Encrypted Drive Found. Suspending encryption temporarily."
            foreach ($volume in $encryptedVolumes) {
                Suspend-BitLocker -MountPoint $volume -RebootCount 0
            }
            Start-Process -Wait -FilePath 'C:\Windows\System32\bcdedit.exe' -ArgumentList '/set "{current}" nx OptOut'
            foreach ($volume in $encryptedVolumes) {
                Resume-BitLocker -MountPoint $volume
                Write-Output "Resumed Protection."
            }
        }
        else {
            Start-Process -Wait -FilePath 'C:\Windows\System32\bcdedit.exe' -ArgumentList '/set "{current}" nx OptOut'
        }
    } Else {
        Write-Output "DEP is already enabled."
    }

    # V-220734 Bluetooth
    Write-Output 'V-220734: Disabling Bluetooth Radios.'
    Set-BluetoothRadioStatus -BluetoothStatus Off

    #V-225238 - Disable TLS RC4 cipher in .Net
    Reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -v SchUseStrongCrypto -d 1 -t REG_DWORD -f
    Reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -v SchUseStrongCrypto -d 1 -t REG_DWORD -f

    Write-Output "Configuring Registry Keys that aren't policy objects."
    # WN10-CC-000039
    Reg.exe ADD "HKLM\SOFTWARE\Classes\batfile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f
    Reg.exe ADD "HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f
    Reg.exe ADD "HKLM\SOFTWARE\Classes\exefile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f
    Reg.exe ADD "HKLM\SOFTWARE\Classes\mscfile\shell\runasuser" -v SuppressionPolicy -d 4096 -t REG_DWORD -f

    # CVE-2013-3900
    Write-Output "CVE-2013-3900: Mitigating PE Installation risks."
    Reg.exe ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -v EnableCertPaddingCheck -d 1 -t REG_DWORD -f
    Reg.exe ADD "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -v EnableCertPaddingCheck -d 1 -t REG_DWORD -f
    }

Stop-Transcript