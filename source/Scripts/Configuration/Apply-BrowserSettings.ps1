[CmdletBinding()]
param (
    [switch]$Remove
)

$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

# Edge policy settings and their types
$edgePolicySettings = @{
    "HideFirstRunExperience" = @{ Value = 1; Type = "DWord" }
    "UserDataDir"            = @{ Value = '${documents}\EdgeProfile'; Type = "String" }
    "DownloadDirectory"      = @{ Value = '${documents}\Downloads'; Type = "String" }
}

if ($Remove) {
    foreach ($name in $edgePolicySettings.Keys) {
        if (Get-ItemProperty -Path $edgePolicyPath -Name $name -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $edgePolicyPath -Name $name -Force -ErrorAction SilentlyContinue
        }
    }
}
else {
    New-Item -Path $edgePolicyPath -Force | Out-Null
    foreach ($name in $edgePolicySettings.Keys) {
        $setting = $edgePolicySettings[$name]
        New-ItemProperty -Path $edgePolicyPath -Name $name -PropertyType $setting.Type -Value $setting.Value -Force
    }
}

