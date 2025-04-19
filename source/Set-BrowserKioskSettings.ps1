<# 
.SYNOPSIS
 
    
    Additionally, you can choose to

    * Install the latest Remote Desktop client for Windows and Visual C++ Redistributables directly from the web.
    * Apply the latest applicable Security Technical Implementation Guides (STIG) group policy settings into the local group policy object via the
      local group policy object tool. This also applies several delta settings to maintain operability as a kiosk.
    * The computer is setup as a shared PC where the account management process is enabled and all user profiles are automatically
      deleted on logoff.

.DESCRIPTION 
    This script completes a series of configuration tasks based on the parameters chosen. These tasks can include:

    * Applocker policy application to only allow Edge, Calc, and Notepad
    * Multi-Local Group Policy configuration to limit interface elements.
    * Built-in application removal.
    * Multi-App Kiosk configuration for Windows 11
    * Remote Desktop client for Windows install (If selected)
    * STIG application (If selected)
    * Start layout modification for the custom explorer shell options

.NOTES 
    The script will automatically remove older configurations by running 'Remove-KioskSettings.ps1' during the install process.    

.COMPONENT 
    No PowerShell modules required.

.LINK 
    https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-windows?tabs=subscribe
    https://learn.microsoft.com/en-us/azure/virtual-desktop/uri-scheme
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview
    https://learn.microsoft.com/en-us/windows/configuration/kiosk-shelllauncher
    https://public.cyber.mil/stigs/gpo/
 
.PARAMETER ApplySTIGs
This switch parameter determines If the latest DoD Security Technical Implementation Guide Group Policy Objects are automatically downloaded
from https://public.cyber.mil/stigs/gpo and applied via the Local Group Policy Object (LGPO) tool to the system. If they are, then several
delta settings are applied to allow the system to communicate with Azure Active Directory and complete autologon (If applicable).

.PARAMETER EnvironmentAVD
This value determines the Azure environment to which you are connecting. It ultimately determines the Url of the Remote Desktop Feed which
varies by environment by setting the $SubscribeUrl variable and replacing placeholders in several files during installation.
The list of Urls can be found at
https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-microsoft-store?source=recommendations#subscribe-to-a-workspace.

.PARAMETER InstallAVDClient
This switch parameter determines If the latest Remote Desktop client for Windows is automatically downloaded from the Internet and installed
on the system prior to configuration.

.PARAMETER SharedPC
This switch parameter determines If the computer is setup as a shared PC. The account management process is enabled and all user profiles are automatically
deleted on logoff.

.PARAMETER ShowDisplaySettings
This switch parameter determines If the Settings App and Control Panel are restricted to only allow access to the Display Settings page. If this value is not set,
then the Settings app and Control Panel are not displayed or accessible.

.PARAMETER Version
This version parameter allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of the registry value: HKLM\Software\Kiosk\version.

#>
[CmdletBinding()]
param (
    [switch]$ApplySTIGs,

    [ValidateSet('AzureCloud', 'AzureUSGovernment')]
    [string]$EnvironmentAVD = 'AzureCloud',

    [switch]$InstallAVDClient,

    [switch]$ShowDisplaySettings,
    
    [version]$Version = '1.0.0'
)

# Check if the OS is Windows IoT Enterprise
$OS = Get-WmiObject -Class Win32_OperatingSystem
If (-not ($OS.Caption -match "Windows 11 IoT Enterprise")) {
    Write-Log -EntryType Error -EventId 0 -Message "This script is only supported on Windows 11 IoT Enterprise. Exiting."
    Exit 1
}

# Restart in 64-Bit PowerShell if not already running in 64-bit mode
# primarily designed to support Microsoft Endpoint Manager application deployment

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

Write-Output "*********************************"
Write-Output "Setting Script Variables"
Write-Output "*********************************"

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name=[System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Dir = Split-Path $Script:FullName


# Set source directory and variables for supporting folders
$DirKiosk = "$env:SystemDrive\KioskSettings"

$Directories = @{
    "AppConfigs"            = "AppConfigs"
    "Customizations"        = "Customizations"
    "GPO"                   = "GPOSettings"
    "Provisioning"          = "Provisioning"
    "RegistryKeys"          = "RegistryKeys"
    "Tools"                 = "Tools"
    "Icons"                 = "Icons"
    "UserLogos"             = "UserLogos"
    "ConfigurationScripts"  = "Scripts\Configuration"
    "SchedTasksScripts"     = "Scripts\ScheduledTasks"
}

foreach ($Name in $Directories.Keys) {
    Set-Variable -Name "Dir$Name" -Value (Join-Path -Path $DirKiosk -ChildPath $Directories[$Name])
    Get-Variable -Name "Dir$Name"
}

$FileAppLockerClear = Join-Path -Path $DirAppConfigs -ChildPath "ClearAppLockerPolicy.xml"
$FileRegKeys = Join-Path -Path $DirRegistryKeys -ChildPath "RegKeys.csv"

Get-Variable -Name "Script*"
Get-Variable -Name "Dir*"
Get-Variable -Name "File*"

# Set AVD feed subscription Url.
If ($EnvironmentAVD -eq 'AzureUSGovernment') {$SubscribeUrl = 'https://rdweb.wvd.azure.us'}
Else {$SubscribeUrl = 'https://client.wvd.microsoft.com'}
Get-Variable -Name "SubscribeUrl"

Write-Log -EntryType Information -EventId 10 -Message "Using Subscribe URL: $SubscribeUrl"

# Set default exit code to 0
$ScriptExitCode = 0

#region Functions

Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Gets the pending reboot status on a local or remote computer.

    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
        Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
        CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
        and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
        
        CBServicing = Component Based Servicing (Windows 2008+)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
        PendFileRename = PendingFileRenameOperations (Windows 2003+)
        PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                        Virus leverage this key for def/dat removal, giving a false positive PendingReboot

    .EXAMPLE
        Get-PendingReboot
        
    .LINK

    .NOTES
    #>
    Try {
        $RebootPending = $false
        $CompPendRen = $false
        $PendFileRename = $false
        $SCCM = $false
        $CBSRebootPend = $null

        $HKLM = [UInt32] "0x80000002"
        $WMI_Reg = [WMIClass] "\\.\root\default:StdRegProv"

        # Check CBS Reboot Pending
        $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
        $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"
        
        # Check Windows Update Reboot Required
        $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
        $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
        
        # Check Pending File Rename Operations
        $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
        $RegValuePFRO = $RegSubKeySM.sValue
        If ($RegValuePFRO) {$PendFileRename = $true} else {$PendFileRename = $false}
        
        # Check Computer Rename or Domain Join
        $ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")
        $CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")
        $CompPendRen = ($ActCompNm -ne $CompNm)
        
        # Check SCCM Client Reboot Pending
        Try {
            $CCMClientSDK = Invoke-WmiMethod -Namespace 'ROOT\ccm\ClientSDK' -Class 'CCM_ClientUtilities' -Name DetermineIfRebootPending -ErrorAction Stop
            $SCCM = $CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending
        } Catch {
            $SCCM = $false
        }
        

        # Determine if a reboot is pending
        If ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename) {
            $RebootPending = $true
        }

        Return @{
            RebootPending = $RebootPending
            CBSRebootPend = $CBSRebootPend
            WUAURebootReq = $WUAURebootReq
            PendFileRename = $PendFileRename
            CompPendRen = $CompPendRen
            SCCM = $SCCM
        }
    }
    Catch {
        Write-Warning "Error checking pending reboot status: $_"
        Return $false
    }
}

function Update-ACL {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $Path,
        [Parameter(Mandatory = $true)]
        $Identity,
        [Parameter(Mandatory = $true)]
        $FileSystemRights,
        $InheritanceFlags = 'ContainerInherit,ObjectInherit',
        $PropagationFlags = 'None', 
        [Parameter(Mandatory)]
        [ValidateSet('Allow', 'Deny')]
        $Type
    )

    If (Test-Path $Path) {
        $NewAcl = Get-ACL -Path $Path
        $FileSystemAccessRuleArgumentList = $Identity, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $type
        $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $FileSystemAccessRuleArgumentList
        $NewAcl.SetAccessRule($FileSystemAccessRule)
        Set-Acl -Path "$Path" -AclObject $NewAcl
    }
}

function Update-ACLInheritance {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$Path,
        [Parameter(Mandatory = $false,
            Position = 1)]
        [bool]$DisableInheritance = $false,

        [Parameter(Mandatory = $true,
            Position = 2)]
        [bool]$PreserveInheritedACEs = $true
    )

    If (Test-Path $Path) {
        $NewACL = Get-Acl -Path $Path
        $NewACL.SetAccessRuleProtection($DisableInheritance, $PreserveInheritedACEs)
        Set-ACL -Path $Path -AclObject $NewACL
    }

}

function Write-Log {
    [CmdletBinding()]
    param (
        [string]$EventLog,
        [string]$EventSource,
        [ValidateSet('Information','Warning','Error')]
        [string]$EntryType = 'Information',
        [int]$EventId = 1000,
        [string]$Message,
        [switch]$WriteToConsole,
        [switch]$Initialize
    )

    # Use passed-in EventLog/Source or fall back to persisted ones
    if ($Initialize) {
        # Save to script-level variables so they persist across calls
        if ($EventLog)     { $script:PersistedEventLog = $EventLog }
        if ($EventSource)  { $script:PersistedEventSource = $EventSource }

        $LogFile = "C:\Logs\$($script:PersistedEventLog).log"
        $LogDir = Split-Path -Path $LogFile -Parent

        if (-not [System.Diagnostics.EventLog]::SourceExists($script:PersistedEventSource)) {
            try {
                New-EventLog -LogName $script:PersistedEventLog -Source $script:PersistedEventSource
            } catch {
                Write-Warning "Could not create event source '$script:PersistedEventSource': $_"
            }
        }

        if (-not (Test-Path -Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }

        if (-not (Test-Path -Path $LogFile)) {
            New-Item -Path $LogFile -ItemType File -Force | Out-Null
        }

        return
    }

    # Enforce Message requirement
    if (-not $Message) {
        throw "The -Message parameter is required unless -Initialize is specified."
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$EntryType] EventID=$($EventId): $Message"
    $LogFile = "C:\Logs\$($script:PersistedEventLog).log"

    try {
        Write-EventLog -LogName $script:PersistedEventLog -Source $script:PersistedEventSource -EntryType $EntryType -EventId $EventId -Message $Message -ErrorAction Stop
    } catch {
        "$timestamp [Error] Failed to write to EventLog: $($_.Exception.Message)`nOriginal message: $Message" | Out-File -FilePath $LogFile -Append
    }

    $logEntry | Out-File -FilePath $LogFile -Append

    if ($WriteToConsole) {
        Write-Host $logEntry
    }
}

#endregion Functions

#region Initialization

Write-Log -Initialize -EventLog "Browser First AVD Kiosk" -EventSource "Configuration Script"
Write-Log -EntryType Information -EventId 2 -Message "Executing '$Script:FullName'."
Write-Log -EntryType Information -EventId 3 -Message "Running on $($OS.Caption) version $($OS.Version)."

$Reboot = Get-PendingReboot

If ($Reboot.RebootPending) {
    Write-Log -EntryType Error -EventId 0 -Message "There is a reboot pending for $Reboot. This application cannot be installed when a reboot is pending.`nRebooting the computer in 15 seconds."
    Start-Process -FilePath 'shutdown.exe' -ArgumentList '/r /t 15'
    Exit 3010
}

# Copy lgpo to system32 for future use.
Copy-Item -Path "$DirTools\lgpo.exe" -Destination "$env:SystemRoot\System32" -Force

# Enable the Scheduled Task History by enabling the TaskScheduler operational log
$TaskschdLog = Get-WinEvent -ListLog Microsoft-Windows-TaskScheduler/Operational
$TaskschdLog.IsEnabled = $True
$TaskschdLog.SaveChanges()

#endregion Inistiialization

#region Remove Previous Versions

# Run Removal Script first in the event that a previous version is installed or in the event of a failed installation.
Write-Log -EntryType Information -EventId 4 -Message 'Running removal script in case of previous installs or failures.'
& "$Script:Dir\Remove-KioskSettings.ps1" -Reinstall

#endregion Previous Version Removal

#region Copy Files
# Create the KioskSettings directory if it doesn't exist
New-Item -Path $DirKiosk -ItemType Directory -Force | Out-Null

# Get all top-level items, exclude the .vs folder
Get-ChildItem -Path $Script:Dir -Directory -Exclude '.vs' | ForEach-Object {
    $sourceFolder = $_.FullName
    $targetFolder = Join-Path $DirKiosk $_.Name
    Copy-Item -Path $sourceFolder -Destination $targetFolder -Recurse
    Write-Log -EntryType Information -EventId 1 -Message "Copied $sourceFolder to $targetFolder "
}

#endregion Copy Files
Write-Output ""
Write-Output "*********************************"
Write-Output "Installing Applications"
Write-Output "*********************************"
#region Install AVD Client

If ($installAVDClient) {
    Write-Log -EntryType Information -EventID 30 -Message "Running Script to install or update Visual C++ Redistributables."
    & "$DirConfigurationScripts\Install-VisualC++Redistributables.ps1"
    Write-Log -EntryType Information -EventId 31 -Message "Running Script to install or update AVD Client."
    & "$DirConfigurationScripts\Install-AVDClient.ps1"
}

#endregion Install AVD Client

#region OneDrive 

# Remove Per-User installation of OneDrive
& "$DirConfigurationScripts\Install-OneDrive.ps1" -Remove

# Install system installation of OneDrive
& "$DirConfigurationScripts\Install-OneDrive.ps1"

 #endregion Remove Apps

#region STIGs

If ($ApplySTIGs) {
    Write-Log -EntryType Information -EventId 20 -Message "Running Script to apply the latest STIG group policy settings via LGPO for Windows 10, Internet Explorer, Microsoft Edge, Windows Firewall, and Defender AntiVirus."
    & "$DirConfigurationScripts\Apply-LatestSTIGs.ps1"
    
    Write-Log -EntryType Information -EventId 21 -Message "Running Script to allow PKU2U online identities required for AAD logon."
    & "$DirConfigurationScripts\Apply-STIGDirectSignOnExceptions.ps1"  
}

#endregion STIGs

#region KioskSettings Directory
# Set ACLs on Kiosk Settings Directory
# Purpose: Prevent Non-Administrators from changing files (Defense in Depth)
Write-Log -EntryType Information -EventId 30 -Message "Configuring Kiosk Directory ACLs"

# Set owner to Builtin\Administrators
$Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
$ACL = Get-ACL $DirKiosk
$ACL.SetOwner($Group)
Set-ACL -Path $DirKiosk -AclObject $ACL

# Apply ACLs to key identities
Update-ACL -Path $DirKiosk -Identity 'BuiltIn\Administrators' -FileSystemRights 'FullControl' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'BuiltIn\Users' -FileSystemRights 'ReadAndExecute' -Type 'Allow'
Update-ACL -Path $DirKiosk -Identity 'System' -FileSystemRights 'FullControl' -Type 'Allow'

# Disable inheritance and remove existing inherited ACEs
Update-ACLInheritance -Path $DirKiosk -DisableInheritance $true -PreserveInheritedACEs $false
#endregion KioskSettings Directory

#region Provisioning Package
Write-Output ""
Write-Output "*********************************"
Write-Output "Installing Provisioning Packages"
Write-Output "*********************************"

. "$DirConfigurationScripts\AssignedAccessWmiBridgeHelpers.ps1"

$ProvisioningPackages = @()
Write-Log -EntryType Information -EventId 44 -Message "Adding Provisioning Package to enable SharedPC mode"
$ProvisioningPackages += (Get-ChildItem -Path $DirProvisioning).FullName

ForEach ($Package in $ProvisioningPackages) {
    Write-Log -EntryType Information -EventID 46 -Message "Installing $($Package)."
    Install-ProvisioningPackage -PackagePath $Package -ForceInstall -QuietInstall |Select-Object Packagename, PackagePath, IsInstalled, InstallStatus
}
#endregion Provisioning Package

#region Applications

#Remove Built-in Apps
& "$DirConfigurationScripts\Remove-BuiltinApps.ps1"

#Remove Install Custom Apps
$ExitCode = & "$DirCustomizations\Software\InstallSoftware.ps1" -Uninstall:$false
Write-Log -EntryType Information -EventID 50 -Message "Software installed with exitcode $ExitCode."

& "$DirConfigurationScripts\Apply-UserShortcuts.ps1" -Iconpath "$DirKiosk\Icons" -Commercial
Write-Log -EntryType Information -EventID 51 -Message "Desktops Shortcuts applied"

#endregion Applications

#region Start Menu

Write-Log -EntryType Information -EventId 60 -Message "Disabling the Start Button Right Click Menu for all users."
# Set Default profile to hide Start Menu Right click
$Groups = @(
    "Group1",
    "Group2",
    "Group3"
)
$WinXRoot = "$env:SystemDrive\Users\Default\Appdata\local\Microsoft\Windows\WinX\{0}"
foreach ($grp in $Groups) { 
    $HideDir = Get-ItemProperty -Path ($WinXRoot -f $grp )
    $HideDir.Attributes = [System.IO.FileAttributes]::Hidden
}

#endregion Start Menu

#region User Logos

$null = cmd /c lgpo.exe /t "$DirGPO\computer-userlogos.txt" '2>&1'
Write-Log -EntryType Information -EventId 61 -Message "Configured User Logos to use default via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"
Write-Log -EntryType Information -EventId 62 -Message "Backing up current User Logo files to '$DirKiosk\UserLogos'."
Copy-Item -Path "$env:ProgramData\Microsoft\User Account Pictures" -Destination "$DirKiosk\UserLogos" -Force
Write-Log -EntryType Information -EventId 63 -Message "Copying User Logo files to '$env:ProgramData\Microsoft\User Account Pictures'."
Get-ChildItem -Path $DirUserLogos | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force

#endregion User Logos

#region Local GPO Settings

# Set Smartcard Removal Action to 1 (Lock Workstation)
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ScRemoveOption" -Value 1

# Apply Non-Admin GPO settings

$nonAdminsFile = 'nonadmins-MultiAppKiosk.txt'
$null = cmd /c lgpo.exe /t "$DirGPO\$nonAdminsFile" '2>&1'
Write-Log -EntryType Information -EventId 70 -Message "Configured basic Explorer settings for kiosk user via Non-Administrators Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"

# Configure Feed URL for all Users
$outfile = "$env:Temp\Users-AVDURL.txt"
$sourceFile = Join-Path -Path $DirGPO -ChildPath 'users-AutoSubscribe.txt'

(Get-Content -Path $sourceFile).Replace('<url>', $SubscribeUrl) | Out-File $outfile
$null = cmd /c lgpo.exe /t "$outfile" '2>&1'
Write-Log -EntryType Information -EventId 71 -Message "Configured AVD Feed URL for all users via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"

# Disable Cortana, Search, Feeds, and Logon Animations. These are computer settings only.
$null = cmd /c lgpo.exe /t "$DirGPO\Computer.txt" '2>&1'
Write-Log -EntryType Information -EventId 72 -Message "Disabled Cortana search, feeds, and login animations via Local Group Policy Object.`nlgpo.exe Exit Code: [$LastExitCode]"

#endregion Local GPO Settings

#region Registry Edits

# update the Default User Hive to Hide the search button and task view icons on the taskbar.
$null = cmd /c REG LOAD "HKLM\Default" "$env:SystemDrive\Users\default\ntuser.dat" '2>&1'
Write-Log -EntryType Information -EventId 73 -Message "Loaded Default User Hive Registry Keys via Reg.exe.`nReg.exe Exit Code: [$LastExitCode]"

# Import registry keys file
Write-Log -EntryType Information -EventId 74 -Message "Loading Registry Keys from CSV file for modification of default user hive."
$RegKeys = Import-Csv -Path $FileRegKeys

# create the reg key restore file if it doesn't exist, else load it to compare for appending new rows.
Write-Log -EntryType Information -EventId 75 -Message "Creating a Registry key restore file for Kiosk Mode uninstall."
$FileRestore = "$DirKiosk\RegKeyRestore.csv"
New-Item -Path $FileRestore -ItemType File -Force | Out-Null
Add-Content -Path $FileRestore -Value 'Key,Value,Type,Data,Description'

# Loop through the registry key file and perform actions.
ForEach ($Entry in $RegKeys) {
    #reset from previous values
    $Key = $null
    $Value = $null
    $Type = $null
    $Data = $null
    $Description = $Null
    #set values
    $Key = $Entry.Key
    $Value = $Entry.Value
    $Type = $Entry.Type
    $Data = $Entry.Data
    $Description = $Entry.Description
    Write-Log -EntryType Information -EventId 80 -Message "Processing Registry Value to '$Description'."

    If ($Key -like 'HKCU\*') {
        $Key = $Key.Replace("HKCU\", "HKLM\Default\")
    }
    
    If ($null -ne $Data -and $Data -ne '') {
        # Output the Registry Key and value name to the restore csv so it can be deleted on restore.
        Add-Content -Path $FileRestore -Value "$Key,$Value,,"        
        $null = cmd /c REG ADD "$Key" /v $Value /t $Type /d "$Data" /f '2>&1'
        Write-Log -EntryType Information -EventId 81 -Message "Added '$Type' Value '$Value' with Value '$Data' to '$Key' with reg.exe.`nReg.exe Exit Code: [$LastExitCode]"
    }
    Else {
        # This is a delete action
        # Get the current value so we can restore it later if needed.
        $keyTemp = $Key.Replace("HKLM\", "HKLM:\")
        If (Get-ItemProperty -Path "$keyTemp" -Name "$Value" -ErrorAction SilentlyContinue) {
            $CurrentRegValue = Get-ItemPropertyValue -Path "$keyTemp" -Name $Value
            If ($CurrentRegValue) {
                Add-Content -Path $FileRestore -Value "$Key,$Value,$type,$CurrentRegValue"        
                Write-Log -EntryType Information -EventId 82 -Message "Stored '$Type' Value '$Value' with value '$CurrentRegValue' to '$Key' to Restore CSV file."
                $null = cmd /c REG DELETE "$Key" /v $Value /f '2>&1'
                Write-Log -EntryType Information -EventId 83 -Message "REG command to delete '$Value' from '$Key' exited with exit code: [$LastExitCode]."
            }
        }        
    }
}
Write-Log -EntryType Information -EventId 84 -Message "Unloading default user hive."
$null = cmd /c REG UNLOAD "HKLM\Default" '2>&1'
If ($LastExitCode -ne 0) {
    # sometimes the registry doesn't unload properly so we have to perform powershell garbage collection first.
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 5
    $null = cmd /c REG UNLOAD "HKLM\Default" '2>&1'
    If ($LastExitCode -eq 0) {
        Write-Log -EntryType Information -EventId 85 -Message "Hive unloaded successfully."
    }
    Else {
        Write-Log -EntryType Error -EventId 86 -Message "Default User hive unloaded with exit code [$LastExitCode]."
    }
}
Else {
    Write-Log -EntryType Information -EventId 87 -Message "Hive unloaded successfully."
}

#endregion Registry Edits

#region Applocker Policy 

Write-Log -EntryType Information -EventId 90 -Message "Applying AppLocker Policy to disable unauthorized apps for the Kiosk User."
# If there is an existing applocker policy, back it up and store its XML for restore.
# Else, copy a blank policy to the restore location.
# Then apply the new AppLocker Policy
$FileAppLockerKiosk = Join-Path -Path $DirAppConfigs -ChildPath "BrowserKioskAppLockerPolicy.xml"

[xml]$Policy = Get-ApplockerPolicy -Local -XML
If ($Policy.AppLockerPolicy.RuleCollection) {Get-ApplockerPolicy -Local -XML | out-file "\ApplockerPolicy.xml" -force}
Else {Copy-Item "$FileAppLockerClear" -Destination "$DirKiosk\ApplockerPolicy.xml" -Force}

Set-AppLockerPolicy -XmlPolicy "$FileAppLockerKiosk"
Write-Log -EntryType Information -EventId 91 -Message "Enabling and Starting Application Identity Service"
Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
# Start the service if not already running
If ((Get-Service -Name AppIDSvc).Status -ne 'Running') {Start-Service -Name AppIDSvc}

#endregion Applocker Policy

#region Assigned Access

Write-Log -EntryType Information -EventId 92 -Message "Starting Multi-App Kiosk Configuration Section for Assigned Access."

$sourceFile = Join-Path -Path $DirAppConfigs -ChildPath "MultiAppKioskBrowserFirst.xml"

try {
    Set-MultiAppKioskConfiguration -FilePath $sourceFile
    $KioskConfig = Get-MultiAppKioskConfiguration
    If ($KioskConfig) {
        Write-Log -EntryType Information -EventId 94 -Message "Multi-App Kiosk configuration successfully applied from $sourceFile."
    }
    Else {
        Write-Log -EntryType Error -EventId 95 -Message "Multi-App Kiosk configuration failed."
        Exit 1        
    }
} catch {
    Write-Log -EntryType Error -EventId 96 -Message "An error occurred while applying Multi-App Kiosk configuration: $($_.Exception.Message)"
    Exit 1
}

#endregion Assigned Access

#region Keyboard Filter
Write-Log -EntryType Information -EventID 100 -Message "Enabling Keyboard filter."
Enable-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter -All -NoRestart

# === CONFIGURATION ===
$Eventlog              = "AVD Kiosk - Configure Keyboard Filter"
$TaskName              = "(AVD Client) - Configure Keyboard Filter"
$TaskScriptName        = "Set-KeyboardFilterConfiguration.ps1"
$TaskScriptEventSource = "Keyboard Filter Configuration"
$TaskDescription       = "Configures the Keyboard Filter"
$TaskScriptFullName    = Join-Path -Path $DirSchedTasksScripts -ChildPath $TaskScriptName

# === Logging ===
Write-Log -EntryType Information -EventId 101 -Message "Creating Scheduled Task: '$TaskName'."
New-EventLog -LogName $EventLog -Source $TaskScriptEventSource -ErrorAction SilentlyContinue     

# === Task Trigger ===
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup

# === Script Arguments ===
$TaskScriptArgs = "-TaskName `"$TaskName`" -EventLog `"$EventLog`" -EventSource `"$TaskScriptEventSource`""
if ($ShowDisplaySettings) {$TaskScriptArgs += " -ShowDisplaySettings"}

# === Task Action ===
$TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Bypass -File `"$TaskScriptFullName`" $TaskScriptArgs"

# === Task Security Principal ===
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

# === Task Settings ===
$TaskSettings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

# === Register the Task ===
Register-ScheduledTask -TaskName $TaskName `
    -Description $TaskDescription `
    -Action $TaskAction `
    -Settings $TaskSettings `
    -Principal $TaskPrincipal `
    -Trigger $TaskTrigger `
    -Force

# === Confirm Task Creation ===
if (Get-ScheduledTask | Where-Object { $_.TaskName -eq "$TaskName" }) {
    Write-Log -EntryType Information -EventId 102 -Message "Scheduled Task '$TaskName' created successfully."
} else {
    Write-Log -EntryType Error -EventId 103 -Message "Scheduled Task '$TaskName' not created."
    $ScriptExitCode = 1618
}
#endregion Keyboard Filter

Write-Log -EntryType Information -EventId 110 -Message "Updating Group Policy"
$gpupdate = Start-Process -FilePath 'GPUpdate' -ArgumentList '/force' -Wait -PassThru
Write-Log -EntryType Information -EventID 111 -Message "GPUpdate Exit Code: [$($GPUpdate.ExitCode)]"
$null = cmd /c reg add 'HKLM\Software\Kiosk' /v Version /d "$($version.ToString())" /t REG_SZ /f
Write-Log -EntryType Information -EventId 112 -Message "Ending Kiosk Mode Configuration version '$($version.ToString())' with Exit Code: $ScriptExitCode"
Pause
Exit $ScriptExitCode
