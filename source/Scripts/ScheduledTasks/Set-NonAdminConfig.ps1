
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$EventLog,

    [Parameter(Mandatory = $true)]
    [string]$EventSource,

    [Parameter(Mandatory = $true)]
    [string]$TaskName,

    [switch]$DryRun
)

function Set-RegistryValues {
    param (
        [string]$Path,
        [hashtable]$Settings,
        [switch]$DryRun
    )

    if (-not (Test-Path $Path)) {
        if ($DryRun) {
            Write-Output "[DryRun] Would create path: $Path"
        } else {
            New-Item -Path $Path -Force | Out-Null
            Write-Verbose "Created registry path: $Path"
        }
    }

    foreach ($name in $Settings.Keys) {
        $setting = $Settings[$name]
        $existing = $null

        try {
            $existing = Get-ItemProperty -Path $Path -Name $name -ErrorAction Stop
        } catch {
            Write-Verbose "Setting '$name' not present at $Path — will be created."
        }

        if ($existing -and $existing.$name -eq $setting.Value) {
            Write-Verbose "Setting '$name' at $Path already set to '$($setting.Value)'. Skipping."
        } else {
            if ($DryRun) {
                Write-Output "[DryRun] Would set '$name' = $($setting.Value) at $Path"
            } else {
                try {
                    New-ItemProperty -Path $Path -Name $name -PropertyType $setting.Type -Value $setting.Value -Force | Out-Null
                    Write-Verbose "Applied setting '$name' = $($setting.Value) at $Path"
                } catch {
                    Write-Warning "Failed to set $name at $($Path): $_"
                }
            }
        }
    }
}

# Ensure event source exists
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try {
        New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction Stop
    } catch {
        Write-Warning "Could not create event source '$EventSource': $_"
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1000 -EntryType Information -Message "[$TaskName] user is a standard user applying settings."

    $ExplorerSettings = @{
        "HideSCAHealth"              = @{ Value = 1;         Type = "Dword" }
        "HideSCAMeetNow"             = @{ Value = 1;         Type = "Dword" }
        "LockTaskbar"                = @{ Value = 1;         Type = "Dword" }
        "NoChangeStartMenu"          = @{ Value = 1;         Type = "Dword" }
        "NoDrives"                   = @{ Value = 67108863;  Type = "Dword" }
        "NoFileMenu"                 = @{ Value = 1;         Type = "Dword" }
        "NoNetConnectDisconnect"     = @{ Value = 1;         Type = "Dword" }
        "NoRecycleFiles"             = @{ Value = 1;         Type = "Dword" }
        "NoRun"                      = @{ Value = 1;         Type = "Dword" }
        "NoSetTaskbar"               = @{ Value = 1;         Type = "Dword" }
        "NoStartMenuMFUprogramsList" = @{ Value = 1;         Type = "Dword" }
        "NoStartMenuMorePrograms"    = @{ Value = 1;         Type = "Dword" }
        "NoStartMenuSubFolders"      = @{ Value = 1;         Type = "Dword" }
        "NoTrayContextMenu"          = @{ Value = 1;         Type = "Dword" }
        "NoViewContextMenu"          = @{ Value = 1;         Type = "Dword" }
        "NoViewOnDrive"              = @{ Value = 67108863;  Type = "Dword" }
    }

    $ExplorerPolicySettings = @{
        "AddSearchInternetLinkInStartMenu"  = @{ Value = 0;         Type = "Dword" }
        "DisableContextMenusInStart"        = @{ Value = 1;         Type = "Dword" }
        "DisableNotificationCenter"         = @{ Value = 1;         Type = "Dword" }
        "DisableSearchHistory"              = @{ Value = 1;         Type = "Dword" }
        "ForceStartSize"                    = @{ Value = 2;         Type = "Dword" }
        "HidePeopleBar"                     = @{ Value = 1;         Type = "Dword" }
        "LockedStartLayout"                 = @{ Value = 1;         Type = "Dword" }
        "NoBalloonFeatureAdvertisements"    = @{ Value = 1;         Type = "Dword" }
        "NoPinningToDestinations"           = @{ Value = 1;         Type = "Dword" }
        "NoPinningToTaskbar"                = @{ Value = 1;         Type = "Dword" }
        "NoRemoteDestinations"              = @{ Value = 1;         Type = "Dword" }
        "NoSearchInternetTryHarderButton"   = @{ Value = 1;         Type = "Dword" }
        "NoUninstallFromStart"              = @{ Value = 1;         Type = "Dword" }
        "ShowRunAsDifferentUserInStart"     = @{ Value = 0;         Type = "Dword" }
        "TaskbarNoPinnedList"               = @{ Value = 1;         Type = "Dword" }
    }

    Set-RegistryValues -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Settings $ExplorerSettings -DryRun:$DryRun
    Set-RegistryValues -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Settings $ExplorerPolicySettings -DryRun:$DryRun

    Set-RegistryValues -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Settings @{
        "{645FF040-5081-101B-9F08-00AA002F954E}" = @{ Value = 1; Type = "Dword" }
    } -DryRun:$DryRun

    Set-RegistryValues -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Settings @{
        "DisableRegistryTools" = @{ Value = 2; Type = "Dword" }
        "DisableTaskMgr"       = @{ Value = 1; Type = "Dword" }
    } -DryRun:$DryRun

    Set-RegistryValues -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Settings @{
        "ConfigureWindowsSpotlight"           = @{ Value = 2; Type = "Dword" }
        "DisableWindowsSpotlightOnActionCenter" = @{ Value = 1; Type = "Dword" }
        "IncludeEnterpriseSpotlight"          = @{ Value = 0; Type = "Dword" }
    } -DryRun:$DryRun

    Set-RegistryValues -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Settings @{
        "DisableCMD" = @{ Value = 2; Type = "Dword" }
    } -DryRun:$DryRun

    if (-not $DryRun) {
        gpupdate /force /target:user
    } else {
        Write-Output "[DryRun] Skipping 'gpupdate /force /target:user'"
    }

} else {
    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1000 -EntryType Information -Message "[$TaskName] user is an admin."
}
