
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$EventLog,

    [Parameter(Mandatory = $true)]
    [string]$EventSource,
    
    [Parameter(Mandatory = $true)]
    [string]$TaskName
)

# Ensure event source exists
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try {
        New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction Stop
    } catch {
        Write-Warning "Could not create event source '$EventSource': $_"
    }
}

try {
    $regPath     = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $noDrivesKey = "NoDrives"
    $isAdmin     = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

    # Ensure the registry path exists
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    if (-not $isAdmin) {
        Set-ItemProperty -Path $regPath -Name $noDrivesKey -Value 0x03ffffff -Type DWord -Force
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1001 -EntryType Information `
            -Message "[$TaskName] Applied 'NoDrives = 0x03ffffff' — drives hidden for standard user."
    } else {
        Set-ItemProperty -Path $regPath -Name $noDrivesKey -Value 0x00000000 -Type DWord -Force
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1002 -EntryType Information `
            -Message "[$TaskName] Reset 'NoDrives = 0x00000000' — drives visible for admin."
    }

} catch {
    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1099 -EntryType Error `
        -Message "[$TaskName] ERROR: Failed to set NoDrives. Exception: $($_.Exception.Message)"
    Write-Error "[$TaskName] Fatal error occurred: $_"
    exit 1
}