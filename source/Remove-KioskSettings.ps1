[CmdletBinding()]
param (
    # Reinstall Kiosk Settings. If called from Installation Script this will be chosen.
    [Parameter()]
    [switch]$Reinstall
)

#region Set Variables
$script:FullName = $MyInvocation.MyCommand.Path
$script:Dir = Split-Path $script:FullName
$Script:File = [string]$myInvocation.MyCommand.Name
[String]$Script:LogDir = Join-Path -Path $env:SystemRoot -ChildPath "Logs"
$date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"
$Script:LogName = [io.path]::GetFileNameWithoutExtension($Script:File) + "-$date.log"


$GPODir = "$Script:Dir\gposettings"
$ToolsDir = "$Script:Dir\Tools"
$DirConfigurationScripts = "$Script:Dir\Scripts\Configuration"
$DirCustomizations = "$Script:Dir\Customizations"
$KioskDir = "$env:SystemDrive\KioskSettings"
$RegKeysRestoreFile = "$KioskDir\RegKeyRestore.csv"
$AppLockerRestoreFile = "$KioskDir\ApplockerPolicy.xml"

foreach ($key in $Directories.Keys) {
    Set-Variable -Name "Dir$key" -Value (Join-Path -Path $Script:Dir -ChildPath $Directories[$key])
}


#endregion Set Variables

#region Restart Script in 64-bit powershell if necessary

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

#endregion Restart Script in 64-bit powershell if necessary

#region Functions

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

#region Initialization and Logging

Write-Log -Initialize -EventLog  'Browser First AVD Kiosk' -EventSource 'Remove Settings Script'

If (-not (Test-Path $Script:LogDir)) {
    $null = New-Item -Path $Script:LogDir -ItemType Directory -Force
}
Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
Write-Log -EntryType Information -EventId 5 -Message "Executing '$Script:FullName'."

#endregion Initialization and Logging

#region Main Script

# App uninstallation
& "$DirConfigurationScripts\Install-OneDrive.ps1" -Remove
& "$DirCustomizations\Software\InstallSoftware.ps1" -Uninstall:$false


# Removing Non-Administrators Local GPO.
$DirNonAdminsGPO = "$env:SystemRoot\System32\GroupPolicyUsers\S-1-5-32-545"
If (Test-Path -Path $DirNonAdminsGPO) {
    Write-Log -EventId 7 -EntryType Information -Message "Deleting Non-Administrators local group policy object and forcing GPUpdate."
    Remove-Item -Path $DirNonAdminsGPO -Recurse -Force -ErrorAction SilentlyContinue
    If (!(Test-Path -Path $DirNonAdminsGPO)) {
        Write-Log -EventId 8 -EntryType Information -Message "Non-Administrators Local GPO removed successfully."
        Start-Process -FilePath "gpupdate.exe" -ArgumentList "/Force" -Wait -ErrorAction SilentlyContinue
    }
    Else {
        Write-Log -EventId 9 -EntryType Error -Message "Non-Administrators Local GPO folder was not removed successfully."
        Exit 2
    }
}

If (Test-Path -Path $KioskDir) {
    # Removing changes to default user hive by reading the restore file and resetting all configured registry values to their previous values.
    If (Test-Path -Path $RegKeysRestoreFile) {
        $RegKeys = Import-Csv -Path $RegKeysRestoreFile

        Write-Log -EventId 10 -EntryType Information -Message "Restoring registry keys to default."
        Write-Log -EventId 11 -EntryType Information -Message "Loading Default User Hive and updated registry values."
        Start-Process -FilePath "REG.exe" -ArgumentList "LOAD", "HKLM\Default", "$env:SystemDrive\Users\default\ntuser.dat" -Wait

        ForEach ($entry in $RegKeys) {
            #reset from previous values
            $Key = $null
            $Value = $null
            $Type = $null
            $Data = $null
            #set values
            $Key = $Entry.Key
            $Value = $Entry.Value
            $Type = $Entry.Type
            $Data = $Entry.Data

            If ($Key -like 'HKCU\*') {
                $Key = $Key.Replace("HKCU\","HKLM\Default\")
            }

            If ($null -ne $Data -and $Data -ne '') {
                # Restore the value to the original
                Start-Process -FilePath "REG.exe" -ArgumentList "ADD `"$Key`" /v $Value /t $Type /d `"$Data`" /f" -wait
            }
            Else {
                # Delete the value since it didn't exist.
                Start-Process -FilePath "REG.exe" -ArgumentList "DELETE `"$Key`" /v $Value /f" -wait -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log -EventId 12 -EntryType Information -Message "Unloading Default User Hive."
        $HiveUnloadResult = Start-Process -FilePath "REG.exe" -ArgumentList "UNLOAD", "HKLM\Default" -Wait -PassThru -NoNewWindow
        $ExitCode = $HiveUnloadResult.ExitCode
        If ($ExitCode -ne 0) {
            # sometimes the registry doesn't unload properly so we have to perform powershell garbage collection first.
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 5
            $HiveUnloadResult = Start-Process -FilePath "REG.exe" -ArgumentList "UNLOAD", "HKLM\Default" -Wait
            $ExitCode = $HiveUnloadResult.ExitCode
        }
        If ($ExitCode -eq 0) {
            Write-Log -EventId 13 -EntryType Information -Message "Hive unloaded successfully."
        }
        Else {
            Write-Log -EventId 14 -EntryType Error -Message "Hive unloaded with exit code '$ExitCode'."
        }      
    }

    # Remove Applocker Configuration by clearing Applocker Policy.
    If (Test-Path -Path $AppLockerRestoreFile) {
        Write-Log -EventID 15 -EntryType Information -Message "Restoring AppLocker Policy to Default."
        Set-AppLockerPolicy -XmlPolicy $AppLockerRestoreFile
        Set-Service -Name AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
        Stop-Service -Name AppIDSvc -Force
        If ((Get-Service -Name AppIDSvc).Status -eq 'Running') {
            Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
        }
    }

    # Restore User Logos
    If (Test-Path -Path "$kioskDir\UserLogos") {
        Write-Log -EntryType Information -EventId 17 -Message "Restoring User Logo Files"
        Get-ChildItem -Path "$KioskDir\UserLogos" | Copy-Item -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
        $null = cmd /c "$ToolsDir\lgpo.exe" /t "$GPODir\Remove-computer-userlogos.txt" '2>&1'
    }

    # Remove Kiosk Settings Directory
    Write-Log -EventId 18 -EntryType Information -Message "Removing '$KioskDir' Directory"
    Remove-Item -Path $KioskDir -Recurse -Force 
}

# Remove Scheduled Tasks
Write-Log -EventId 19 -EntryType Information -Message "Removing Scheduled Tasks."
Get-ScheduledTask | Where-Object {$_.TaskName -like '(AVD Client)*'} | Unregister-ScheduledTask -Confirm:$false

# Remove Custom Start Menu Shortcut
Write-Log -EventId 20 -EntryType Information -Message "Removing Custom AVD Client Shortcuts."
$DirsShortcuts = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:SystemDrive\Users\Public\Desktop"
$linkAVD = "Azure Virtual Desktop.lnk"
ForEach ($DirShortcut in $DirsShortcuts) {
    $pathLinkAVD = Join-Path $DirShortcut -ChildPath $linkAVD
    If (Test-Path -Path $pathLinkAVD) {
        Remove-Item -Path $pathLinkAVD -Force
    }
}

# Remove Custom Start Menu
Get-ChildItem -Path "$env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Filter 'LayoutModification.*' | Remove-Item -Force

# Remove Version Registry Entry
Write-Log -EventId 21 -EntryType Information -Message "Removing Kiosk Registry Key to track install version."
If (Test-Path -Path 'HKLM:\Software\Kiosk') {
    Remove-Item -Path 'HKLM:\Software\Kiosk' -Recurse -Force
}

# Remove Keyboard Filter
If ((Get-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter).state -eq 'Enabled') {
    Write-Log -EventId 22 -EntryType Information -Message "Removing Keyboard Filter and configuration."
    & "$DirConfigurationScripts\Disable-KeyboardFilter.ps1"
    If (!$Reinstall) { Disable-WindowsOptionalFeature -Online -FeatureName Client-KeyboardFilter -NoRestart }
}

Write-Log -EventId 27 -EntryType Information -Message "**** Custom Kiosk Mode removed successfully ****"
Stop-Transcript