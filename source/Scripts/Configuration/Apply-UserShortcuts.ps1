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

    # OneDrive Shortcut
    Write-Host "Creating OneDrive shortcut on public desktop..."
    $shortcut = $wshell.CreateShortcut($shortcuts["OneDrive"])
    $shortcut.TargetPath = "explorer.exe"
    $shortcut.Arguments = "shell:OneDrive"
    $shortcut.IconLocation = "$env:SystemRoot\System32\OneDrive.ico"
    $shortcut.Save()
    Write-Host "OneDrive shortcut created successfully."

    # Outlook Shortcut
    Write-Host "Creating Outlook shortcut on public desktop..."
    $shortcut = $wshell.CreateShortcut($shortcuts["Outlook"])
    if ($Commercial) {
        $shortcut.Arguments = "--app=https://outlook.office.com/owa/ --profile-directory=Default"
    } else {
        $shortcut.Arguments = "--app=https://outlook.office365.us/owa/ --profile-directory=Default"
    }
    $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    $shortcut.IconLocation = "$IconPath\Outlook.ico"
    $shortcut.Save()
    Write-Host "Outlook shortcut created successfully."

    # Excel Shortcut
    Write-Host "Creating Excel shortcut on public desktop..."
    $shortcut = $wshell.CreateShortcut($shortcuts["Excel"])
    if ($Commercial) {
        $shortcut.Arguments = "--app=https://www.office.com/launch/excel --profile-directory=Default"
    } else {
        $shortcut.Arguments = "--app=https://www.office365.us/launch/excel --profile-directory=Default"
    }
    $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    $shortcut.IconLocation = "$IconPath\Excel.ico"
    $shortcut.Save()
    Write-Host "Excel shortcut created successfully."

    # PowerPoint Shortcut
    Write-Host "Creating PowerPoint shortcut on public desktop..."
    $shortcut = $wshell.CreateShortcut($shortcuts["PowerPoint"])
    if ($Commercial) {
        $shortcut.Arguments = "--app=https://www.office.com/launch/powerpoint --profile-directory=Default"
    } else {
        $shortcut.Arguments = "--app=https://www.office365.us/launch/powerpoint --profile-directory=Default"
    }
    $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    $shortcut.IconLocation = "$IconPath\PowerPoint.ico"
    $shortcut.Save()
    Write-Host "PowerPoint shortcut created successfully."

    # Teams Shortcut
    Write-Host "Creating Teams shortcut on public desktop..."
    $shortcut = $wshell.CreateShortcut($shortcuts["Teams"])
    if ($Commercial) {
        $shortcut.Arguments = "--app=https://teams.microsoft.com --profile-directory=Default"
    } else {
        $shortcut.Arguments = "--app=https://gov.teams.microsoft.us --profile-directory=Default"
    }
    $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    $shortcut.IconLocation = "$IconPath\Teams.ico"
    $shortcut.Save()
    Write-Host "Teams shortcut created successfully."

    # Word Shortcut
    Write-Host "Creating Word shortcut on public desktop..."
    $shortcut = $wshell.CreateShortcut($shortcuts["Word"])
    if ($Commercial) {
        $shortcut.Arguments = "--app=https://www.office.com/launch/word --profile-directory=Default"
    } else {
        $shortcut.Arguments = "--app=https://www.office365.us/launch/word --profile-directory=Default"
    }
    $shortcut.TargetPath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    $shortcut.IconLocation = "$IconPath\Word.ico"
    $shortcut.Save()
    Write-Host "Word shortcut created successfully."
}