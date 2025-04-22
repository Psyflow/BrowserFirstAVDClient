[CmdletBinding()]
param (

    # Required parameter for the icon path
    [Parameter(Mandatory=$true)]
    [string]$IconPath,

    # Switch to create shortcuts for the commercial version
    [switch]$Commercial,

    # Switch to remove shortcuts
    [switch]$Remove
)

Write-Output "***************************************"
Write-Output "Building shortcuts for Office Web Apps"
Write-Output "***************************************"

# Paths for managing shortcuts
$publicDesktop = "C:\Users\Public\Desktop"

# Define shortcut paths
$shortcuts = @{
    "OneDrive"      = Join-Path $publicDesktop "OneDrive.lnk"
    "Outlook"       = Join-Path $publicDesktop "Outlook.lnk"
    "Excel"         = Join-Path $publicDesktop "Excel.lnk"
    "PowerPoint"    = Join-Path $publicDesktop "PowerPoint.lnk"
    "Teams"         = Join-Path $publicDesktop "Teams.lnk"
    "Word"          = Join-Path $publicDesktop "Word.lnk"
}

if ($Remove) {
    # Remove all shortcuts
    foreach ($shortcut in $shortcuts.GetEnumerator()) {
        if (Test-Path $shortcut.Value) {
            Remove-Item $shortcut.Value -Force
            Write-Host "Removed $($shortcut.Key) shortcut from public desktop."
        }
    }
} else {
    # Create shortcuts
    $wshell = New-Object -ComObject WScript.Shell

    try {
        Write-Host "Creating OneDrive shortcut..."
        $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut("$env:PUBLIC\Desktop\OneDrive.lnk")
        $shortcut.TargetPath = "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
        $shortcut.Description = "OneDrive"
        $shortcut.Hotkey = "Ctrl+Shift+O"
        $shortcut.Save()
        Write-Host "Shortcut created."
    } catch {
        Write-Host "Error creating OneDrive shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        # Outlook Shortcut
        Write-Host "Creating Outlook shortcut on public desktop..."
        $shortcut = $wshell.CreateShortcut($shortcuts["Outlook"])
        if ($Commercial) {
            $shortcut.Arguments = "--app=https://outlook.cloud.microsoft/ --profile-directory=Default"
        } else {
            $shortcut.Arguments = "--app=https://www.office365.us/launch/outlook?auth=2 --profile-directory=Default"
        }
        $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
        $shortcut.IconLocation = "$IconPath\Outlook.ico"
        $shortcut.Save()
        Write-Host "Outlook shortcut created successfully."
    } catch {
        Write-Host "Failed to create Outlook shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        # Excel Shortcut
        Write-Host "Creating Excel shortcut on public desktop..."
        $shortcut = $wshell.CreateShortcut($shortcuts["Excel"])
        if ($Commercial) {
            $shortcut.Arguments = "--app=https://excel.cloud.microsoft/ --profile-directory=Default"
        } else {
            $shortcut.Arguments = "--app=https://www.office365.us/launch/excel?auth=2 --profile-directory=Default"
        }
        $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
        $shortcut.IconLocation = "$IconPath\Excel.ico"
        $shortcut.Save()
        Write-Host "Excel shortcut created successfully."
    } catch {
        Write-Host "Failed to create Excel shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        # PowerPoint Shortcut
        Write-Host "Creating PowerPoint shortcut on public desktop..."
        $shortcut = $wshell.CreateShortcut($shortcuts["PowerPoint"])
        if ($Commercial) {
            $shortcut.Arguments = "--app=https://powerpoint.cloud.microsoft/ --profile-directory=Default"
        } else {
            $shortcut.Arguments = "--app=https://www.office365.us/launch/powerpoint?auth=2 --profile-directory=Default"
        }
        $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
        $shortcut.IconLocation = "$IconPath\PowerPoint.ico"
        $shortcut.Save()
        Write-Host "PowerPoint shortcut created successfully."
    } catch {
        Write-Host "Failed to create PowerPoint shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        # Teams Shortcut
        Write-Host "Creating Teams shortcut on public desktop..."
        $shortcut = $wshell.CreateShortcut($shortcuts["Teams"])
        if ($Commercial) {
            $shortcut.Arguments = "--app=https://teams.cloud.microsoft/ --profile-directory=Default"
        } else {
            $shortcut.Arguments = "--app=https://gov.teams.microsoft.us?auth=2 --profile-directory=Default"
        }
        $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
        $shortcut.IconLocation = "$IconPath\Teams.ico"
        $shortcut.Save()
        Write-Host "Teams shortcut created successfully."
    } catch {
        Write-Host "Failed to create Teams shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        # Word Shortcut
        Write-Host "Creating Word shortcut on public desktop..."
        $shortcut = $wshell.CreateShortcut($shortcuts["Word"])
        if ($Commercial) {
            $shortcut.Arguments = "--app=https://word.cloud.microsoft/ --profile-directory=Default"
        } else {
            $shortcut.Arguments = "--app=https://www.office365.us/launch/word?auth=2 --profile-directory=Default"
        }
        $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
        $shortcut.IconLocation = "$IconPath\Word.ico"
        $shortcut.Save()
        Write-Host "Word shortcut created successfully."
    } catch {
        Write-Host "Failed to create Word shortcut: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Output "*******************************************"
Write-Output "Building shortcuts for Ease of Access tools"
Write-Output "*******************************************"

# Define the folder path
$folderPath = "$env:PUBLIC\Desktop\Ease of Access"

# Create the folder if it doesn't exist
if ($Remove) {
    # Remove all shortcuts
    if (Test-Path -Path $folderPath) {
        try {
            Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Removed Ease of Access folder from public desktop."
        } catch {
            Write-Host "Failed to remove Ease of Access folder: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
} else {

    if (!(Test-Path -Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force
    }

    # Initialize the WScript.Shell COM object
    $WshShell = New-Object -ComObject WScript.Shell

    # Define the list of accessibility tools
    $accessibilityTools = @(
        @{
            Name = "Narrator"
            TargetPath = "$env:WINDIR\System32\Narrator.exe"
            IconLocation = "$env:WINDIR\System32\Narrator.exe,0"
        },
        @{
            Name = "Magnifier"
            TargetPath = "$env:WINDIR\System32\Magnify.exe"
            IconLocation = "$env:WINDIR\System32\Magnify.exe,0"
        },
        @{
            Name = "On-Screen Keyboard"
            TargetPath = "$env:WINDIR\System32\osk.exe"
            IconLocation = "$env:WINDIR\System32\osk.exe,0"
        },
        @{
            Name = "Voice Access"
            TargetPath = "$env:WINDIR\System32\VoiceAccess.exe"
            IconLocation = "$env:WINDIR\System32\VoiceAccess.exe,0"
        },
        @{
            Name = "Live Captions"
            TargetPath = "$env:WINDIR\System32\LiveCaptions.exe"
            IconLocation = "$env:WINDIR\System32\LiveCaptions.exe,0"
        }
    )

    Write-Host "Creating Shortcuts for Ease of Access tools..."

    # Create shortcuts for each tool
    foreach ($tool in $accessibilityTools) {
        try {
            $shortcutPath = Join-Path -Path $folderPath -ChildPath ("{0}.lnk" -f $tool.Name)
            $shortcut = $WshShell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = $tool.TargetPath
            $shortcut.IconLocation = $tool.IconLocation
            $shortcut.Save()
            Write-Host "Created shortcut for $($tool.Name) at $shortcutPath"
        } catch {
            Write-Host "Failed to create shortcut for $($tool.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host "Setting Custom Icons for Ease of Access Folder..."
    # Create desktop.ini to assign a custom icon to the folder
    $desktopIniPath = Join-Path -Path $folderPath -ChildPath "desktop.ini"
    $iconResource = "$env:WINDIR\System32\accessibilitycpl.dll,0"
    $desktopIniContent = "[.ShellClassInfo]`nIconResource=$iconResource"

    # Write the desktop.ini file with Unicode encoding
    Set-Content -Path $desktopIniPath -Value $desktopIniContent -Encoding Unicode

    # Set attributes for desktop.ini to Hidden and System
    $desktopIni = Get-Item -Path $desktopIniPath -Force
    $desktopIni.Attributes = 'Hidden, System'

    # Set the folder attributes to ReadOnly and System
    $folder = Get-Item -Path $folderPath -Force
    $folder.Attributes = $folder.Attributes -bor [System.IO.FileAttributes]::ReadOnly
    $folder.Attributes = $folder.Attributes -bor [System.IO.FileAttributes]::System

    Write-Host "Creating Master Shortcut for Ease of Access Folder for Kiosks..."
    
    $shortcutPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Ease of Access.lnk"

    # Create the shortcut
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $folderPath
    $shortcut.WorkingDirectory = $folderPath
    $shortcut.IconLocation = "$env:WINDIR\System32\accessibilitycpl.dll,0"
    $shortcut.Save()
}