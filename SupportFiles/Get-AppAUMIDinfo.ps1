<#
.SYNOPSIS
Retrieves AppUserModelIDs (AUMIDs) and file paths for installed applications visible in the Start Menu.

.DESCRIPTION
The Get-AppAUMIDinfo function queries both UWP and Win32 applications that appear in the Start Menu.
It returns their AppUserModelID (AUMID), and for Win32 apps, the resolved target file path from the Start Menu shortcut.

- UWP apps will show AUMIDs but typically do not include a file path.
- Win32 apps will show the shortcut name, AUMID, and executable file path (resolved from .lnk files in the Start Menu).

.PARAMETER AppName
Optional. A string to filter application names by partial or full match.
If omitted, all Start Menu apps will be listed.

.EXAMPLE
Get-AppAUMIDinfo

Returns all Start Menu applications with their AUMIDs and (where applicable) Win32 file paths.

.EXAMPLE
Get-AppAUMIDinfo -AppName "Edge"

Returns any app from the Start Menu whose name contains "Edge", such as Microsoft Edge.

.OUTPUTS
[PSCustomObject] with the following properties:
- Name     : The display name of the application.
- AUMID    : The AppUserModelID (used for kiosk mode and shortcuts).
- FilePath : The file path to the Win32 executable (if available).

.NOTES
Author: You
Useful for creating Assigned Access (Kiosk) configurations or AppLocker rules.

#>

function Get-AppAUMIDinfo {
    param (
        [string]$AppName
    )

    $shellApp = New-Object -ComObject Shell.Application
    $folder = $shellApp.Namespace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}')
    $items = $folder.Items()
    $results = @()

    # Index all .lnk files in Start Menu for Win32 lookup
    $lnkIndex = @{}
    $startMenuPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    )

    foreach ($path in $startMenuPaths) {
        if (Test-Path $path) {
            $lnkFiles = Get-ChildItem -Path $path -Recurse -Filter *.lnk -ErrorAction SilentlyContinue
            foreach ($lnk in $lnkFiles) {
                try {
                    $wshShell = New-Object -ComObject WScript.Shell
                    $shortcut = $wshShell.CreateShortcut($lnk.FullName)
                    $targetPath = $shortcut.TargetPath
                    $lnkIndex[$lnk.BaseName] = [PSCustomObject]@{
                        ShortcutPath = $lnk.FullName
                        TargetPath   = $targetPath
                        Arguments    = $shortcut.Arguments
                        WorkingDir   = $shortcut.WorkingDirectory
                    }
                } catch {}
            }
        }
    }

    # Now enumerate all apps from the shell folder
    foreach ($item in $items) {
        $name = $item.Name
        $aumid = $item.Path
        $filePath = $null

        if ($AppName -and $name -notlike "*$AppName*") { continue }

        # Only attempt file path lookup if this matches a Win32 shortcut
        if ($lnkIndex.ContainsKey($name)) {
            $filePath = $lnkIndex[$name].TargetPath
        }

        $results += [PSCustomObject]@{
            Name     = $name
            AUMID    = $aumid
            FilePath = $filePath
        }
    }

    if ($results.Count -eq 0) {
        Write-Output "No apps found matching '$AppName'"
    } else {
        $results
    }
}