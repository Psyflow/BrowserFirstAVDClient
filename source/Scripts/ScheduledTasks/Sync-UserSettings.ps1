<#
.SYNOPSIS
    Saves and restores an allow-listed set of browser and assistive technology settings
    for the signed-in kiosk user, using the user's OneDrive as the transport.

.DESCRIPTION
    Runs as SYSTEM from a scheduled task (at logon, on workstation lock and every few minutes).
    Running as SYSTEM means powershell.exe does not have to be allowed for kiosk users.

    Only the items listed in the manifest (AppConfigs\SettingsRoamingManifest.json) are touched:

      * registry  - HKCU keys (accessibility settings), stored as JSON.
      * files     - individual files (for example the Edge 'Bookmarks' file).
      * jsonPrefs - selected keys inside a JSON preferences file (Edge 'Preferences').

    The roaming store is a hidden folder in the root of the user's OneDrive:

      <OneDrive>\KioskSettings\revision.json      revision id + SHA256 of every data file
      <OneDrive>\KioskSettings\registry.json
      <OneDrive>\KioskSettings\files\<item>\...
      <OneDrive>\KioskSettings\prefs\<item>.json

    Rules that protect the user's data:

      1. A device never SAVES until it has RESTORED the newest revision in the store.
      2. A revision is only restored when every data file matches the hash recorded in
         revision.json, so a half-synced store is never applied.
      3. When there is no store, the device waits for a grace period after OneDrive becomes
         available before it creates one, so a fresh profile cannot overwrite a store that
         OneDrive simply has not downloaded yet.
      4. Items that belong to a running application (Edge) are restored only while that
         application is closed.

    No passwords, cookies, history, cache or documents are saved.

.PARAMETER ManifestPath
    Path to the manifest JSON file.

.PARAMETER MaxWaitSeconds
    How long one run keeps retrying while a user is waiting for OneDrive or for Edge to close.

.NOTES
    Written for Windows PowerShell 5.1. Keep this file ASCII only.
#>
[CmdletBinding()]
param (
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\..\AppConfigs\SettingsRoamingManifest.json'),
    [string]$EventLog = 'Browser First AVD Kiosk',
    [string]$EventSource = 'Settings Roaming',
    [int]$MaxWaitSeconds = 240,
    [int]$RetrySeconds = 15
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$Script:ProfileToken = '%KIOSK_USERPROFILE%'
$Script:StateSubKey = 'Software\Kiosk\SettingsRoaming'
$Script:MaxFileBytes = 20MB
$Script:LogFile = Join-Path $env:SystemRoot 'Logs\Configuration\Sync-UserSettings.log'
$Script:IsCore = ($PSVersionTable.PSEdition -eq 'Core')
$Script:HasNative = $null

#region Logging

function Write-RoamLog {
    param (
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')][string]$EntryType = 'Information',
        [int]$EventId = 1200
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $EntryType, $Message
    try {
        $dir = Split-Path $Script:LogFile -Parent
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
        if ((Test-Path -LiteralPath $Script:LogFile) -and ((Get-Item -LiteralPath $Script:LogFile).Length -gt 1MB)) {
            Remove-Item -LiteralPath $Script:LogFile -Force
        }
        Add-Content -LiteralPath $Script:LogFile -Value $line
    }
    catch { }
    if ($EntryType -ne 'Information') {
        try { Write-EventLog -LogName $EventLog -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message }
        catch { }
    }
}

#endregion Logging

#region JSON helpers

function ConvertFrom-ForeignJson {
    # Parses JSON written by another program (Edge) into nested dictionaries.
    # ConvertFrom-Json in Windows PowerShell 5.1 fails on empty or case-variant property names,
    # which Chromium preference files contain, so JavaScriptSerializer is used there.
    param ([string]$Text)
    if ($Script:IsCore) {
        return (ConvertFrom-Json -InputObject $Text -AsHashtable)
    }
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $serializer.RecursionLimit = 200
    return $serializer.DeserializeObject($Text)
}

function ConvertTo-ForeignJson {
    param ($Object)
    if ($Script:IsCore) {
        return (ConvertTo-Json -InputObject $Object -Depth 100 -Compress)
    }
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $serializer.RecursionLimit = 200
    return $serializer.Serialize($Object)
}

function New-JsonDictionary {
    if ($Script:IsCore) {
        if ('System.Management.Automation.OrderedHashtable' -as [type]) { return (New-Object System.Management.Automation.OrderedHashtable) }
        return @{}
    }
    return (New-Object 'System.Collections.Generic.Dictionary[string,object]')
}

function Get-JsonPathValue {
    # Returns @{ Found = $bool; Value = <node> } for a dotted path such as 'settings.a11y'.
    param ($Root, [string]$Path)
    $node = $Root
    foreach ($part in $Path.Split('.')) {
        if (($node -is [System.Collections.IDictionary]) -and $node.ContainsKey($part)) {
            $node = $node[$part]
        }
        else {
            return @{ Found = $false; Value = $null }
        }
    }
    return @{ Found = $true; Value = $node }
}

function Set-JsonPathValue {
    param ($Root, [string]$Path, $Value)
    $parts = $Path.Split('.')
    $node = $Root
    for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
        $part = $parts[$i]
        if (-not ($node.ContainsKey($part) -and ($node[$part] -is [System.Collections.IDictionary]))) {
            $node[$part] = New-JsonDictionary
        }
        $node = $node[$part]
    }
    $node[$parts[$parts.Count - 1]] = $Value
}

function Remove-JsonPathValue {
    param ($Root, [string]$Path)
    $parts = $Path.Split('.')
    $node = $Root
    for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
        $part = $parts[$i]
        if (($node -is [System.Collections.IDictionary]) -and $node.ContainsKey($part)) { $node = $node[$part] }
        else { return }
    }
    if (($node -is [System.Collections.IDictionary]) -and $node.ContainsKey($parts[$parts.Count - 1])) {
        $null = $node.Remove($parts[$parts.Count - 1])
    }
}

function Get-PrefSubset {
    # Extracts only the allow-listed keys from a parsed preferences document.
    param ($Prefs, [string[]]$Keys)
    $subset = New-JsonDictionary
    foreach ($key in $Keys) {
        $hit = Get-JsonPathValue -Root $Prefs -Path $key
        if ($hit.Found) { $subset[$key] = $hit.Value }
    }
    return , $subset
}

function Merge-PrefSubset {
    # Applies a saved subset to a parsed preferences document. Allow-listed keys that are
    # missing from the subset are removed so the application falls back to its default.
    param ($Prefs, $Subset, [string[]]$Keys)
    foreach ($key in $Keys) {
        if ($Subset.ContainsKey($key)) { Set-JsonPathValue -Root $Prefs -Path $key -Value $Subset[$key] }
        else { Remove-JsonPathValue -Root $Prefs -Path $key }
    }
}

#endregion JSON helpers

#region General helpers

function Get-TextHash {
    param ([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-BytesHash {
    param ([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Read-AllBytesShared {
    # Reads a file that another process (Edge, OneDrive) may have open.
    param ([string]$Path)
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
    try {
        if ($stream.Length -gt $Script:MaxFileBytes) { throw "File '$Path' is larger than the $($Script:MaxFileBytes) byte limit." }
        $buffer = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $buffer.Length) {
            $read = $stream.Read($buffer, $offset, $buffer.Length - $offset)
            if ($read -le 0) { break }
            $offset += $read
        }
        return , $buffer
    }
    finally { $stream.Dispose() }
}

function ConvertFrom-Utf8Bytes {
    param ([byte[]]$Bytes)
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
    }
    return [System.Text.Encoding]::UTF8.GetString($Bytes)
}

function Write-Utf8File {
    param ([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Initialize-NativeMethods {
    # FindFirstFile returns the reparse tag, which tells a real link (junction / symbolic link)
    # apart from a OneDrive Files On-Demand placeholder. Both carry the ReparsePoint attribute.
    if ($null -ne $Script:HasNative) { return }
    $Script:HasNative = $false
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return }
    $source = @'
using System;
using System.Runtime.InteropServices;
public static class KioskReparse
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_DATA
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint dwReserved0;
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstFileW(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

    [DllImport("kernel32.dll")]
    private static extern bool FindClose(IntPtr hFindFile);

    // 0 = not a reparse point, 0xFFFFFFFF = could not be read, otherwise the reparse tag.
    public static uint GetTag(string path)
    {
        WIN32_FIND_DATA data;
        IntPtr handle = FindFirstFileW(path.TrimEnd('\\'), out data);
        if (handle == new IntPtr(-1)) { return 0xFFFFFFFF; }
        FindClose(handle);
        if ((data.dwFileAttributes & 0x400) == 0) { return 0; }
        return data.dwReserved0;
    }
}
'@
    try {
        if (-not ('KioskReparse' -as [type])) { Add-Type -TypeDefinition $source }
        $Script:HasNative = $true
    }
    catch { Write-RoamLog -EntryType Warning -EventId 1214 -Message "Could not load native link check, using LinkType instead: $($_.Exception.Message)" }
}

function Test-IsLink {
    # True when the item is a junction or symbolic link (or cannot be examined).
    param ([string]$Path)
    Initialize-NativeMethods
    if ($Script:HasNative) {
        $tag = [KioskReparse]::GetTag($Path)
        return ($tag -eq [uint32]2684354563 -or $tag -eq [uint32]2684354572 -or $tag -eq [uint32]4294967295)
    }
    $item = Get-Item -LiteralPath $Path -Force
    return ($item.LinkType -in @('Junction', 'SymbolicLink'))
}

function Test-SafePath {
    # Returns $false when any existing component of the path is a junction or symbolic link.
    # This script runs as SYSTEM and writes into folders the user controls, so it must never
    # follow a link that could redirect a write somewhere else.
    param ([string]$Path)
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($full)
        $current = $root
        foreach ($part in $full.Substring($root.Length).Split([char[]]'\', [System.StringSplitOptions]::RemoveEmptyEntries)) {
            $current = Join-Path $current $part
            if (Test-Path -LiteralPath $current) {
                if (Test-IsLink -Path $current) { return $false }
            }
        }
        return $true
    }
    catch { return $false }
}

function Test-ChildPath {
    # True when $Path is inside $Parent after normalisation (blocks '..' in manifest or store data).
    param ([string]$Parent, [string]$Path)
    $p = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    $c = [System.IO.Path]::GetFullPath($Path)
    return $c.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-WildcardMatch {
    param ([string]$Name, [string[]]$Patterns)
    foreach ($pattern in $Patterns) { if ($Name -like $pattern) { return $true } }
    return $false
}

#endregion General helpers

#region User context

function Get-InteractiveUsers {
    # One entry per signed-in user, identified by the owner of explorer.exe.
    $users = @{}
    foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'")) {
        try {
            $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid
            if ($owner.Sid -and ($owner.Sid -like 'S-1-5-21-*' -or $owner.Sid -like 'S-1-12-1-*') -and -not $users.ContainsKey($owner.Sid)) {
                $users[$owner.Sid] = [int]$proc.SessionId
            }
        }
        catch { }
    }
    return $users
}

function Test-UserProcess {
    param ([string]$Sid, [string]$ProcessName)
    foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$ProcessName'")) {
        try {
            $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid
            if ($owner.Sid -eq $Sid) { return $true }
        }
        catch { }
    }
    return $false
}

function Get-UserContext {
    param ([string]$Sid, [int]$SessionId)
    $hive = [Microsoft.Win32.Registry]::Users.OpenSubKey($Sid, $true)
    if (-not $hive) { return $null }

    $profilePath = $null
    $profileKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid")
    if ($profileKey) {
        $profilePath = [string]$profileKey.GetValue('ProfileImagePath')
        $profileKey.Close()
    }
    if (-not $profilePath -or -not (Test-Path -LiteralPath $profilePath)) { $hive.Close(); return $null }
    $profilePath = $profilePath.TrimEnd('\')

    $oneDrive = $null
    $odKey = $hive.OpenSubKey('Software\Microsoft\OneDrive\Accounts\Business1')
    if ($odKey) {
        $oneDrive = [string]$odKey.GetValue('UserFolder')
        $odKey.Close()
    }
    if ($oneDrive -and -not (Test-Path -LiteralPath $oneDrive)) { $oneDrive = $null }

    return @{
        Sid          = $Sid
        SessionId    = $SessionId
        Hive         = $hive
        ProfilePath  = $profilePath
        LocalAppData = (Join-Path $profilePath 'AppData\Local')
        AppData      = (Join-Path $profilePath 'AppData\Roaming')
        OneDrive     = $oneDrive
    }
}

function Get-State {
    param ($Context, [string]$Name)
    $key = $Context.Hive.OpenSubKey($Script:StateSubKey)
    if (-not $key) { return $null }
    try { return $key.GetValue($Name) } finally { $key.Close() }
}

function Set-State {
    param ($Context, [string]$Name, [string]$Value)
    $key = $Context.Hive.CreateSubKey($Script:StateSubKey)
    try { $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Close() }
}

function Resolve-BasePath {
    param ($Context, [string]$Base, [string]$RelativePath)
    switch ($Base) {
        'LocalAppData' { $root = $Context.LocalAppData }
        'AppData'      { $root = $Context.AppData }
        'UserProfile'  { $root = $Context.ProfilePath }
        default        { throw "Unknown base '$Base' in manifest. Use LocalAppData, AppData or UserProfile." }
    }
    $full = Join-Path $root $RelativePath
    if (-not (Test-ChildPath -Parent $Context.ProfilePath -Path $full)) { throw "Manifest path '$RelativePath' leaves the user profile." }
    return $full
}

function Send-UserMessage {
    param ($Context, [string]$Text)
    $msg = Join-Path $env:SystemRoot 'System32\msg.exe'
    if (Test-Path -LiteralPath $msg) {
        try { & $msg $Context.SessionId '/TIME:120' $Text 2>$null | Out-Null } catch { }
    }
}

#endregion User context

#region Registry snapshot

function ConvertTo-PortableText {
    param ($Context, [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return [regex]::Replace($Text, [regex]::Escape($Context.ProfilePath), $Script:ProfileToken, 'IgnoreCase')
}

function ConvertFrom-PortableText {
    param ($Context, [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return $Text.Replace($Script:ProfileToken, $Context.ProfilePath)
}

function Export-RegistryKey {
    # Appends one entry per key (recursively) to $List: @{ k = <path>; v = @( @{ n; t; d } ) }
    param ($Context, [string]$SubPath, [string[]]$Exclude, [System.Collections.ArrayList]$List)
    $key = $Context.Hive.OpenSubKey($SubPath)
    if (-not $key) { return }
    try {
        $values = New-Object System.Collections.ArrayList
        foreach ($name in ($key.GetValueNames() | Sort-Object)) {
            $kind = $key.GetValueKind($name)
            $raw = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $data = $null
            $supported = $true
            switch ($kind.ToString()) {
                'String'       { $data = ConvertTo-PortableText -Context $Context -Text ([string]$raw) }
                'ExpandString' { $data = ConvertTo-PortableText -Context $Context -Text ([string]$raw) }
                'DWord'        { $data = ([System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$raw), 0)).ToString() }
                'QWord'        { $data = ([System.BitConverter]::ToUInt64([System.BitConverter]::GetBytes([long]$raw), 0)).ToString() }
                'Binary'       { $data = [System.Convert]::ToBase64String([byte[]]$raw) }
                'MultiString'  { $data = @(foreach ($s in [string[]]$raw) { ConvertTo-PortableText -Context $Context -Text $s }) -join "`n" }
                default        { $supported = $false }
            }
            if ($supported) { $null = $values.Add([ordered]@{ n = $name; t = $kind.ToString(); d = [string]$data }) }
        }
        $null = $List.Add([ordered]@{ k = $SubPath; v = $values.ToArray() })
        foreach ($child in ($key.GetSubKeyNames() | Sort-Object)) {
            if ($Exclude -and ($Exclude -contains $child)) { continue }
            Export-RegistryKey -Context $Context -SubPath "$SubPath\$child" -Exclude $Exclude -List $List
        }
    }
    finally { $key.Close() }
}

function Get-RegistrySnapshot {
    param ($Context, $Manifest)
    $list = New-Object System.Collections.ArrayList
    foreach ($entry in @($Manifest.registry)) {
        $exclude = @()
        if ($entry.PSObject.Properties['excludeSubkeys']) { $exclude = @($entry.excludeSubkeys) }
        Export-RegistryKey -Context $Context -SubPath ([string]$entry.key).Trim('\') -Exclude $exclude -List $list
    }
    # ConvertTo-Json is safe here because this document has a fixed, known shape.
    return (ConvertTo-Json -InputObject ([ordered]@{ keys = $list.ToArray() }) -Depth 6 -Compress)
}

function Test-AllowedRegistryPath {
    param ($Manifest, [string]$Path)
    foreach ($entry in @($Manifest.registry)) {
        $allowed = ([string]$entry.key).Trim('\')
        if ($Path -eq $allowed -or $Path.StartsWith("$allowed\", [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($entry.PSObject.Properties['excludeSubkeys']) {
                foreach ($ex in @($entry.excludeSubkeys)) {
                    $blocked = "$allowed\$ex"
                    if ($Path -eq $blocked -or $Path.StartsWith("$blocked\", [System.StringComparison]::OrdinalIgnoreCase)) { return $false }
                }
            }
            return $true
        }
    }
    return $false
}

function Import-RegistrySnapshot {
    # Writes the saved values back. Only keys inside the manifest allow-list are written,
    # whatever the store contains. Values that are not in the snapshot are removed from the
    # keys that are in the snapshot.
    param ($Context, $Manifest, [string]$Json)
    $doc = ConvertFrom-Json -InputObject $Json
    foreach ($entry in @($doc.keys)) {
        $path = [string]$entry.k
        if (-not (Test-AllowedRegistryPath -Manifest $Manifest -Path $path)) { continue }
        $key = $Context.Hive.CreateSubKey($path)
        try {
            $wanted = @{}
            foreach ($value in @($entry.v)) {
                if ($null -eq $value) { continue }
                $name = [string]$value.n
                $wanted[$name.ToLowerInvariant()] = $true
                $text = [string]$value.d
                switch ([string]$value.t) {
                    'String'       { $key.SetValue($name, (ConvertFrom-PortableText -Context $Context -Text $text), [Microsoft.Win32.RegistryValueKind]::String) }
                    'ExpandString' { $key.SetValue($name, (ConvertFrom-PortableText -Context $Context -Text $text), [Microsoft.Win32.RegistryValueKind]::ExpandString) }
                    'DWord'        { $key.SetValue($name, [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]$text), 0), [Microsoft.Win32.RegistryValueKind]::DWord) }
                    'QWord'        { $key.SetValue($name, [System.BitConverter]::ToInt64([System.BitConverter]::GetBytes([uint64]$text), 0), [Microsoft.Win32.RegistryValueKind]::QWord) }
                    'Binary'       { $key.SetValue($name, [System.Convert]::FromBase64String($text), [Microsoft.Win32.RegistryValueKind]::Binary) }
                    'MultiString'  {
                        $items = @()
                        if ($text.Length -gt 0) { $items = @(foreach ($s in $text.Split("`n")) { ConvertFrom-PortableText -Context $Context -Text $s }) }
                        $key.SetValue($name, [string[]]$items, [Microsoft.Win32.RegistryValueKind]::MultiString)
                    }
                }
            }
            foreach ($existing in $key.GetValueNames()) {
                if (-not $wanted.ContainsKey($existing.ToLowerInvariant())) { $key.DeleteValue($existing, $false) }
            }
        }
        finally { $key.Close() }
    }
}

#endregion Registry snapshot

#region Snapshot (local -> memory)

function Get-FileSetItems {
    # Returns @{ <relative path> = <full path> } for the files a 'files' manifest entry covers.
    param ([string]$Root, $Entry)
    $result = @{}
    if (-not (Test-Path -LiteralPath $Root)) { return $result }
    if (-not (Test-SafePath -Path $Root)) { throw "Refusing to use '$Root' because the path contains a link." }
    $recurse = [bool]($Entry.PSObject.Properties['recurse'] -and $Entry.recurse)
    $files = @(Get-ChildItem -LiteralPath $Root -File -Force -Recurse:$recurse -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        if ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            if (Test-IsLink -Path $file.FullName) { continue }
        }
        if (-not (Test-WildcardMatch -Name $file.Name -Patterns @($Entry.include))) { continue }
        if ($file.Length -gt $Script:MaxFileBytes) { continue }
        $relative = $file.FullName.Substring($Root.TrimEnd('\').Length + 1)
        $result[$relative] = $file.FullName
    }
    return $result
}

function Get-LocalSnapshot {
    # Builds the complete set of data files the store would contain for the user's current
    # settings: @{ <store relative path> = [byte[]] }
    param ($Context, $Manifest)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $snapshot = @{}

    $snapshot['registry.json'] = $utf8.GetBytes((Get-RegistrySnapshot -Context $Context -Manifest $Manifest))

    foreach ($entry in @($Manifest.files)) {
        $root = Resolve-BasePath -Context $Context -Base $entry.base -RelativePath $entry.path
        $items = Get-FileSetItems -Root $root -Entry $entry
        foreach ($relative in $items.Keys) {
            $snapshot["files\$($entry.name)\$relative"] = Read-AllBytesShared -Path $items[$relative]
        }
    }

    foreach ($entry in @($Manifest.jsonPrefs)) {
        $path = Resolve-BasePath -Context $Context -Base $entry.base -RelativePath $entry.path
        if ((Test-Path -LiteralPath $path) -and (Test-SafePath -Path $path)) {
            $prefs = ConvertFrom-ForeignJson -Text (ConvertFrom-Utf8Bytes -Bytes (Read-AllBytesShared -Path $path))
            $subset = Get-PrefSubset -Prefs $prefs -Keys @($entry.keys)
            $snapshot["prefs\$($entry.name).json"] = $utf8.GetBytes((ConvertTo-ForeignJson -Object $subset))
        }
    }
    return $snapshot
}

function Get-SnapshotHashes {
    param ($Snapshot)
    $hashes = @{}
    foreach ($name in $Snapshot.Keys) { $hashes[$name] = Get-BytesHash -Bytes $Snapshot[$name] }
    return $hashes
}

function Get-SnapshotDigest {
    param ($Hashes)
    $lines = foreach ($name in ($Hashes.Keys | Sort-Object)) { '{0}={1}' -f $name.ToLowerInvariant(), $Hashes[$name] }
    return (Get-TextHash -Text ($lines -join '|'))
}

#endregion Snapshot

#region Store (OneDrive)

function Get-StorePath {
    param ($Context, $Manifest)
    $store = Join-Path $Context.OneDrive ([string]$Manifest.storeFolderName)
    if (-not (Test-ChildPath -Parent $Context.OneDrive -Path $store)) { throw 'storeFolderName must be a plain folder name.' }
    return $store
}

function Read-StoreRevision {
    # Returns $null when there is no store, or @{ Revision; Files = @{ name = hash } }.
    # Throws when the store exists but cannot be read yet (for example still downloading).
    param ([string]$Store)
    $path = Join-Path $Store 'revision.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    if (-not (Test-SafePath -Path $path)) { throw "Refusing to read '$path' because the path contains a link." }
    $doc = ConvertFrom-Json -InputObject (ConvertFrom-Utf8Bytes -Bytes (Read-AllBytesShared -Path $path))
    if (-not $doc.revision) { throw 'revision.json has no revision id.' }
    $files = @{}
    foreach ($file in @($doc.files)) {
        if ($null -ne $file) { $files[[string]$file.name] = [string]$file.sha256 }
    }
    return @{ Revision = [string]$doc.revision; Files = $files }
}

function Read-StoreData {
    # Reads every data file named in revision.json and verifies its hash.
    # Returns $null when anything is missing or does not match (store still syncing).
    param ([string]$Store, $RevisionInfo)
    $data = @{}
    foreach ($name in $RevisionInfo.Files.Keys) {
        $path = Join-Path $Store $name
        if (-not (Test-ChildPath -Parent $Store -Path $path)) { return $null }
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        if (-not (Test-SafePath -Path $path)) { return $null }
        $bytes = Read-AllBytesShared -Path $path
        if ((Get-BytesHash -Bytes $bytes) -ne $RevisionInfo.Files[$name]) { return $null }
        $data[$name] = $bytes
    }
    return $data
}

function Write-Store {
    param ($Context, [string]$Store, $Snapshot, $Hashes)
    if (-not (Test-SafePath -Path $Store)) { throw "Refusing to write '$Store' because the path contains a link." }
    if (-not (Test-Path -LiteralPath $Store)) {
        $folder = New-Item -Path $Store -ItemType Directory -Force
        $folder.Attributes = $folder.Attributes -bor [System.IO.FileAttributes]::Hidden
    }
    foreach ($name in $Snapshot.Keys) {
        $path = Join-Path $Store $name
        if (-not (Test-ChildPath -Parent $Store -Path $path)) { continue }
        $dir = Split-Path $path -Parent
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
        if (-not (Test-SafePath -Path $path)) { throw "Refusing to write '$path' because the path contains a link." }
        [System.IO.File]::WriteAllBytes($path, $Snapshot[$name])
    }
    # Remove data files that are no longer part of the snapshot (for example a deleted cursor file).
    foreach ($sub in @('files', 'prefs')) {
        $subPath = Join-Path $Store $sub
        if ((Test-Path -LiteralPath $subPath) -and (Test-SafePath -Path $subPath)) {
            foreach ($file in @(Get-ChildItem -LiteralPath $subPath -File -Recurse -Force -ErrorAction SilentlyContinue)) {
                $relative = $file.FullName.Substring($Store.TrimEnd('\').Length + 1)
                if (-not $Snapshot.ContainsKey($relative)) { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    $revision = [guid]::NewGuid().ToString()
    $fileList = @(foreach ($name in ($Hashes.Keys | Sort-Object)) { [ordered]@{ name = $name; sha256 = $Hashes[$name] } })
    $doc = [ordered]@{
        revision = $revision
        savedUtc = (Get-Date).ToUniversalTime().ToString('o')
        device   = $env:COMPUTERNAME
        files    = $fileList
    }
    # revision.json is written last: readers ignore the store until every hash in it matches.
    Write-Utf8File -Path (Join-Path $Store 'revision.json') -Text (ConvertTo-Json -InputObject $doc -Depth 4)
    return $revision
}

#endregion Store

#region Restore (store -> local)

function Get-ManifestItems {
    # Flat list of restorable items with the name used to track their restored revision.
    param ($Manifest)
    $items = New-Object System.Collections.ArrayList
    $null = $items.Add(@{ Id = 'registry'; Type = 'registry'; Entry = $null; Blocker = $null })
    foreach ($entry in @($Manifest.files)) {
        $blocker = $null
        if ($entry.PSObject.Properties['blockingProcess']) { $blocker = [string]$entry.blockingProcess }
        $null = $items.Add(@{ Id = "files:$($entry.name)"; Type = 'files'; Entry = $entry; Blocker = $blocker })
    }
    foreach ($entry in @($Manifest.jsonPrefs)) {
        $blocker = $null
        if ($entry.PSObject.Properties['blockingProcess']) { $blocker = [string]$entry.blockingProcess }
        $null = $items.Add(@{ Id = "prefs:$($entry.name)"; Type = 'jsonPrefs'; Entry = $entry; Blocker = $blocker })
    }
    return $items
}

function Restore-Item {
    # Returns $true when local data was changed.
    param ($Context, $Manifest, $Item, $StoreData)
    switch ($Item.Type) {
        'registry' {
            if (-not $StoreData.ContainsKey('registry.json')) { return $false }
            $incoming = ConvertFrom-Utf8Bytes -Bytes $StoreData['registry.json']
            $current = Get-RegistrySnapshot -Context $Context -Manifest $Manifest
            if ($incoming -eq $current) { return $false }
            Import-RegistrySnapshot -Context $Context -Manifest $Manifest -Json $incoming
            return $true
        }
        'files' {
            $entry = $Item.Entry
            $root = Resolve-BasePath -Context $Context -Base $entry.base -RelativePath $entry.path
            if (-not (Test-SafePath -Path $root)) { throw "Refusing to write '$root' because the path contains a link." }
            $prefix = "files\$($entry.name)\"
            $changed = $false
            foreach ($name in @($StoreData.Keys)) {
                if (-not $name.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
                $relative = $name.Substring($prefix.Length)
                if (-not (Test-WildcardMatch -Name (Split-Path $relative -Leaf) -Patterns @($entry.include))) { continue }
                $target = Join-Path $root $relative
                if (-not (Test-ChildPath -Parent $root -Path $target)) { continue }
                $dir = Split-Path $target -Parent
                if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
                if (-not (Test-SafePath -Path $target)) { throw "Refusing to write '$target' because the path contains a link." }
                if (Test-Path -LiteralPath $target) {
                    if ((Get-BytesHash -Bytes (Read-AllBytesShared -Path $target)) -eq (Get-BytesHash -Bytes $StoreData[$name])) { continue }
                }
                [System.IO.File]::WriteAllBytes($target, $StoreData[$name])
                $changed = $true
            }
            return $changed
        }
        'jsonPrefs' {
            $entry = $Item.Entry
            $name = "prefs\$($entry.name).json"
            if (-not $StoreData.ContainsKey($name)) { return $false }
            $path = Resolve-BasePath -Context $Context -Base $entry.base -RelativePath $entry.path
            $dir = Split-Path $path -Parent
            if (-not (Test-SafePath -Path $path)) { throw "Refusing to write '$path' because the path contains a link." }
            $subset = ConvertFrom-ForeignJson -Text (ConvertFrom-Utf8Bytes -Bytes $StoreData[$name])
            if (-not ($subset -is [System.Collections.IDictionary])) { return $false }
            if (Test-Path -LiteralPath $path) {
                $prefs = ConvertFrom-ForeignJson -Text (ConvertFrom-Utf8Bytes -Bytes (Read-AllBytesShared -Path $path))
                if (-not ($prefs -is [System.Collections.IDictionary])) { throw "'$path' is not a JSON object." }
                $before = ConvertTo-ForeignJson -Object (Get-PrefSubset -Prefs $prefs -Keys @($entry.keys))
                if ($before -eq (ConvertTo-ForeignJson -Object $subset)) { return $false }
                Copy-Item -LiteralPath $path -Destination "$path.kioskbak" -Force
            }
            else {
                if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
                $prefs = New-JsonDictionary
            }
            Merge-PrefSubset -Prefs $prefs -Subset $subset -Keys @($entry.keys)
            Write-Utf8File -Path $path -Text (ConvertTo-ForeignJson -Object $prefs)
            return $true
        }
    }
    return $false
}

#endregion Restore

#region Per-user pass

function Invoke-LegacyMigration {
    # Earlier builds kept the whole Edge profile in OneDrive (UserDataDir = Documents\Edge).
    # Carry the favorites over once so they are not lost when that policy is removed.
    param ($Context)
    if ((Get-State -Context $Context -Name 'LegacyMigrated') -eq '1') { return }
    try {
        $legacy = Join-Path $Context.OneDrive 'Documents\Edge\Default\Bookmarks'
        $target = Join-Path $Context.LocalAppData 'Microsoft\Edge\User Data\Default\Bookmarks'
        if ((Test-Path -LiteralPath $legacy) -and -not (Test-Path -LiteralPath $target) -and -not (Test-UserProcess -Sid $Context.Sid -ProcessName 'msedge.exe')) {
            if ((Test-SafePath -Path $legacy) -and (Test-SafePath -Path $target)) {
                $dir = Split-Path $target -Parent
                if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
                [System.IO.File]::WriteAllBytes($target, (Read-AllBytesShared -Path $legacy))
                Write-RoamLog -Message "[$($Context.Sid)] Copied favorites from the legacy OneDrive Edge profile."
            }
        }
        Set-State -Context $Context -Name 'LegacyMigrated' -Value '1'
    }
    catch { Write-RoamLog -EntryType Warning -EventId 1210 -Message "[$($Context.Sid)] Legacy favorites migration failed: $($_.Exception.Message)" }
}

function Invoke-UserPass {
    # Returns 'Done' when the user is in sync, 'Pending' when it is worth retrying shortly
    # (waiting for OneDrive or for Edge to close) and 'Failed' when a restore step raised an error.
    param ($Context, $Manifest)
    $sid = $Context.Sid

    if (-not $Context.OneDrive) { return 'Pending' }
    if (-not (Test-SafePath -Path $Context.OneDrive)) {
        Write-RoamLog -EntryType Warning -EventId 1211 -Message "[$sid] OneDrive folder path contains a link. Skipping."
        return 'Done'
    }
    if (-not (Get-State -Context $Context -Name 'OneDriveSeenUtc')) {
        Set-State -Context $Context -Name 'OneDriveSeenUtc' -Value ((Get-Date).ToUniversalTime().ToString('o'))
    }

    $store = Get-StorePath -Context $Context -Manifest $Manifest
    $items = Get-ManifestItems -Manifest $Manifest
    $notify = [bool]($Manifest.PSObject.Properties['notifyUser'] -and $Manifest.notifyUser)

    $revisionInfo = $null
    try { $revisionInfo = Read-StoreRevision -Store $store }
    catch {
        Write-RoamLog -Message "[$sid] Store is not readable yet: $($_.Exception.Message)"
        return 'Pending'
    }

    if (-not $revisionInfo) {
        # No store. Wait for the grace period in case OneDrive has not listed it yet.
        $seen = [datetime]::Parse((Get-State -Context $Context -Name 'OneDriveSeenUtc'), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $graceMinutes = 5
        if ($Manifest.PSObject.Properties['newStoreGraceMinutes']) { $graceMinutes = [int]$Manifest.newStoreGraceMinutes }
        if (((Get-Date).ToUniversalTime() - $seen.ToUniversalTime()).TotalMinutes -lt $graceMinutes) { return 'Pending' }

        Invoke-LegacyMigration -Context $Context
        $snapshot = Get-LocalSnapshot -Context $Context -Manifest $Manifest
        $hashes = Get-SnapshotHashes -Snapshot $snapshot
        $revision = Write-Store -Context $Context -Store $store -Snapshot $snapshot -Hashes $hashes
        foreach ($item in $items) { Set-State -Context $Context -Name "Rev:$($item.Id)" -Value $revision }
        Set-State -Context $Context -Name 'LastDigest' -Value (Get-SnapshotDigest -Hashes $hashes)
        Write-RoamLog -Message "[$sid] Created settings store, revision $revision."
        return 'Done'
    }

    $revision = $revisionInfo.Revision
    $outdated = @($items | Where-Object { (Get-State -Context $Context -Name "Rev:$($_.Id)") -ne $revision })

    if ($outdated.Count -gt 0) {
        $storeData = Read-StoreData -Store $store -RevisionInfo $revisionInfo
        if ($null -eq $storeData) {
            Write-RoamLog -Message "[$sid] Store revision $revision is still syncing. Will retry."
            return 'Pending'
        }
        $blocked = $false
        $failed = $false
        $registryChanged = $false
        foreach ($item in $outdated) {
            if ($item.Blocker -and (Test-UserProcess -Sid $sid -ProcessName $item.Blocker)) {
                $blocked = $true
                continue
            }
            try {
                $changed = Restore-Item -Context $Context -Manifest $Manifest -Item $item -StoreData $storeData
                Set-State -Context $Context -Name "Rev:$($item.Id)" -Value $revision
                if ($changed) {
                    Write-RoamLog -Message "[$sid] Restored '$($item.Id)' from revision $revision."
                    if ($item.Type -eq 'registry') { $registryChanged = $true }
                }
            }
            catch {
                Write-RoamLog -EntryType Warning -EventId 1212 -Message "[$sid] Restore of '$($item.Id)' failed: $($_.Exception.Message)"
                $failed = $true
            }
        }
        if ($notify -and $registryChanged) {
            Send-UserMessage -Context $Context -Text 'Your saved accessibility settings were restored on this device. Some of them (text size, pointer, contrast, colour filters, keyboard options) apply the next time you sign in.'
        }
        if ($failed) { return 'Failed' }
        if ($blocked) {
            if ($notify -and (Get-State -Context $Context -Name 'NotifiedRevision') -ne $revision) {
                Send-UserMessage -Context $Context -Text 'Your saved favorites and browser settings are ready. Close all Microsoft Edge windows for a few minutes to load them on this device.'
                Set-State -Context $Context -Name 'NotifiedRevision' -Value $revision
            }
            return 'Pending'
        }
        # Record what the device looks like now so the restore itself is not saved back as a change.
        $hashes = Get-SnapshotHashes -Snapshot (Get-LocalSnapshot -Context $Context -Manifest $Manifest)
        Set-State -Context $Context -Name 'LastDigest' -Value (Get-SnapshotDigest -Hashes $hashes)
    }

    # In sync with the store: save local changes, if any.
    $snapshot = Get-LocalSnapshot -Context $Context -Manifest $Manifest
    $hashes = Get-SnapshotHashes -Snapshot $snapshot
    $digest = Get-SnapshotDigest -Hashes $hashes
    if ($digest -ne (Get-State -Context $Context -Name 'LastDigest')) {
        # Re-check the store immediately before writing in case another device saved meanwhile.
        $latest = Read-StoreRevision -Store $store
        if ($latest -and $latest.Revision -ne $revision) { return 'Pending' }
        $newRevision = Write-Store -Context $Context -Store $store -Snapshot $snapshot -Hashes $hashes
        foreach ($item in $items) { Set-State -Context $Context -Name "Rev:$($item.Id)" -Value $newRevision }
        Set-State -Context $Context -Name 'LastDigest' -Value $digest
        Write-RoamLog -Message "[$sid] Saved settings, revision $newRevision."
    }
    return 'Done'
}

#endregion Per-user pass

#region Main

function Invoke-Main {
    if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "Manifest '$ManifestPath' not found." }
    $manifest = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $ManifestPath -Raw)
    foreach ($section in 'registry', 'files', 'jsonPrefs') {
        if (-not $manifest.PSObject.Properties[$section]) { Add-Member -InputObject $manifest -NotePropertyName $section -NotePropertyValue @() }
    }
    if (-not $manifest.PSObject.Properties['storeFolderName'] -or -not $manifest.storeFolderName) {
        Add-Member -InputObject $manifest -NotePropertyName storeFolderName -NotePropertyValue 'KioskSettings' -Force
    }

    $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
    do {
        $pending = $false
        $users = Get-InteractiveUsers
        foreach ($sid in @($users.Keys)) {
            $context = $null
            try {
                $context = Get-UserContext -Sid $sid -SessionId $users[$sid]
                if (-not $context) { continue }
                if ((Invoke-UserPass -Context $context -Manifest $manifest) -eq 'Pending') { $pending = $true }
            }
            catch {
                Write-RoamLog -EntryType Warning -EventId 1213 -Message "[$sid] Settings roaming pass failed: $($_.Exception.Message)"
            }
            finally {
                if ($context -and $context.Hive) { $context.Hive.Close() }
            }
        }
        if ($pending -and ((Get-Date) -lt $deadline)) { Start-Sleep -Seconds $RetrySeconds }
    } while ($pending -and ((Get-Date) -lt $deadline))
}

# Allow the functions to be dot-sourced for testing without running the task.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-Main }
    catch {
        Write-RoamLog -EntryType Error -EventId 1299 -Message "Settings roaming failed: $($_.Exception.Message)"
        exit 1
    }
}

#endregion Main
