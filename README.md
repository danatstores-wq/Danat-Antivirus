# Danat Anti-Virus

A Windows desktop controller with a premium black-and-metallic-gold identity.

## Current implementation — Preview 0.3

This build integrates with the **Microsoft Defender Antivirus installation already present on the Windows PC**:

- Reads Defender service, antivirus, real-time protection, operating mode, and security-intelligence age using Microsoft's `Get-MpComputerStatus` PowerShell cmdlet.
- Locates the newest installed `MpCmdRun.exe` platform version.
- Starts a real Microsoft Defender custom scan for a selected file or folder.
- Defaults to report-only custom scans using `-DisableRemediation`, so files are not changed by that scan request.
- Offers a separate, unchecked consent option to authorize Microsoft Defender's normal remediation actions. If selected and confirmed, Defender may quarantine or remove detections.
- Provides a shortcut to Windows Security Protection history, where users can review Defender-managed actions and available restore options.
- Reads the Windows Controlled Folder Access mode (disabled, enabled, audit, disk-modification-only block, or disk-modification-only audit) from Defender preferences and provides a shortcut to the Windows ransomware-protection settings page. Danat does not silently enable or modify this Windows setting.
- Reads redirected Defender status output asynchronously to avoid blocking if PowerShell writes more output than a pipe buffer can hold.
- Treats Defender exit code 2 as unresolved (malware may remain unremediated or a scan error occurred), never as a clean result.
- Requests administrator privileges because Microsoft's command-line tool requires an elevated command prompt.

**This is a controller for Microsoft Defender, not a new antivirus engine.** Defender must already be installed, enabled, and kept updated by Windows. Danat does not install Defender, replace it, or provide an independent real-time driver, ransomware behavior engine, quarantine system, or subscription backend.

## Supported platform scope

The supported platform is **Windows 10 and Windows 11 only**. The application uses the modern Microsoft Defender status and Windows Security interfaces; Windows 7 and Microsoft Security Essentials compatibility paths have been removed. The app targets .NET Framework 4.8.

## Optional ClamAV manual scanning

The preview can invoke an independently installed `clamscan.exe` for an additional on-demand scan. ClamAV is not bundled or automatically updated by Danat; install it separately and update its signature database first. The scan reports results only and does not quarantine or delete files. It is not real-time protection.

## Product requirements still pending

- Independent real-time protection and ransomware behavior monitoring; ClamAV's Windows command-line scan is on-demand only. Controlled Folder Access is a Windows Defender feature, not a Danat-owned ransomware engine.
- Safe quarantine/restore workflow and auditable event history.
- Secure engine/signature update strategy beyond the Windows-managed Defender service.
- 14-day trial and server-validated US$3/year licensing.
- Authentic Danat Coin warrior artwork.
- Runtime testing on clean Windows 10 and Windows 11 virtual machines, including EICAR test-file handling. Do not test live malware on a normal computer.

## Build

Open `DanatAntiVirus.sln` in Visual Studio 2022 with the .NET Framework 4.8 Developer Pack and WPF workload installed. Build the `Release` configuration.

The app requests administrator privileges at startup so it can invoke Microsoft's documented elevated scan utility and read local Defender status. Windows displays a UAC prompt.

## Safety

No antivirus can guarantee protection from every threat. Danat must not show a protected state unless the underlying engine's actual state has been verified. A successful custom scan is not a guarantee that a device is malware-free.
