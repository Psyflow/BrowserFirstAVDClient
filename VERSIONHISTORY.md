# Version History

## Browser First 2.0.0

This is a [Feature] and [Bug Fix] release of the Browser First fork. The entries below it are the upstream Azure/AVDClientKiosk history.

1. Added settings roaming (`-SettingsRoaming`): Edge favorites, selected Edge settings and Windows accessibility settings follow the user through OneDrive. Works in GCC High / DoD.
2. Replaced the retired Remote Desktop client (MSI) with Windows App in the installer, the allowed apps and the Start pins.
3. The Edge profile is no longer stored in OneDrive (`UserDataDir`). Favorites from that location are migrated once.
4. Fixed: non-administrator lockdown policy, STIGs, Settings page restriction, smart card removal lock, AppLocker backup, user logo backup, Start pins, taskbar pin, US Government shortcut URLs and the removal script were not being applied or did not work.

## 6.0 (Current Version)

This is a [feature] release.

1. Reintroduced support for the SessionDisconnect event trigger in the autologon scenario.
2. Introduced support for a inactivity timeout trigger.

## 5.0

This is a [Feature] release.

1. Introduced Support for Windows 11.

## 4.6.0

This is a [Feature] release.

1. This version is minor change with the addition of the -SharedPC switch parameter. The SharedPC parameter can only be enabled in the non-autologon scenario. It enables Shared PC mode on the system with the Account Management function. Account Management will automatically be enabled and configured to remove the user profile after logoff. SharedPC Mode is documented at https://learn.microsoft.com/en-us/windows/configuration/set-up-shared-or-guest-pc?tabs=ppkg.
2. Incorporated a new scheduled task in the autologon scenarios that automatically restarts the subscribe process to prevent a AAD.Broker timeout.

## 4.4.0

This is a [Feature] release.

1. This version uses a WMI Event Subscription to detect YUBIKEY (If desired) or Smart Card removal events and perform the appropriate Remote Desktop client for Windows reset or Lock Workstation actions based on signed-in user.
2. All scheduled tasks are removed. This version no longer monitors MSRDC connections.

## 3.0.0

This is a [Feature] and [Bug Fix] release.

1. Unified the code base between the AVD Custom and the Shell Launcher version for simpler maintenance and deployment.
2. Fixed a bug in the URI scheme used to pick the AVD feed url.

## 1.1.0

This is a [Feature] release.

1. Added the Keyboard Filter feature to block many well-known keyboard shortcuts/combinations that can cause confusion.
2. Fixed a bug where the AVD Client wasn't reset after a restart of the thin client. Reconfigured the Launch-AVDClient.vbs to reset if the client registry key was present.

## 1.0.1

This is a [Bug Fix] release.

1. Added the removal of OneDrive into the installer to prevent issues with the sync engine causing applocker pop-ups.

## 1.0.0

Initial Release
