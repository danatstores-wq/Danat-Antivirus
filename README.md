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
- Runs without administrator privileges; Windows elevation is requested only for the Microsoft Defender scan process that requires it.

**This is a controller for Microsoft Defender, not a new antivirus engine.** Defender must already be installed, enabled, and kept updated by Windows. Danat does not install Defender, replace it, or provide an independent real-time driver, ransomware behavior engine, quarantine system, or subscription backend.

## Supported platform scope

The supported platform is **Windows 10 and Windows 11 only**. The application uses the modern Microsoft Defender status and Windows Security interfaces; Windows 7 and Microsoft Security Essentials compatibility paths have been removed. The app targets .NET Framework 4.8.

## Optional ClamAV manual scanning

The preview can set up ClamAV from inside Danat using the `Cisco.ClamAV` package in the Windows Package Manager (WinGet) community source. The user initiates setup from **SET UP CLAMAV** and can review the installer/license prompts; Danat does not ask users to find or manually install a separate antivirus application. The community-maintained WinGet manifest points to installers hosted in the official Cisco-Talos ClamAV GitHub release and supplies SHA-256 hashes that WinGet checks after download. The manifest is not maintained by Cisco, and its presence does not imply Cisco endorsement of Danat. Danat installs ClamAV as a separate program; it does not bundle, modify, or link to ClamAV. ClamAV is GPL-2.0 licensed; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Danat creates a per-user FreshClam configuration and database directory, downloads ClamAV signatures, and checks signature freshness before every manual ClamAV scan, refreshing at least every four hours. The scanner reports results only and does not quarantine or delete files. Danat refuses to scan with ClamAV versions older than 1.5.5; that release fixes multiple security vulnerabilities affecting versions through 1.5.4. This minimum is a preview safeguard, not a guarantee that future releases have no vulnerabilities. It is not real-time protection. WinGet must be available on the Windows account; Danat reports a clear setup error if it is unavailable. If a future Danat release bundles or redistributes ClamAV binaries, that release must undergo a separate GPL compliance review before distribution.

## Product requirements still pending

- Independent real-time protection and ransomware behavior monitoring; ClamAV's Windows command-line scan is on-demand only. Controlled Folder Access is a Windows Defender feature, not a Danat-owned ransomware engine.
- Safe quarantine/restore workflow and auditable event history.
- Secure engine/signature update strategy beyond the Windows-managed Defender service.
- 14-day trial and server-validated US$3/year licensing.
- Authentic Danat Coin warrior artwork.
- Runtime testing on clean Windows 10 and Windows 11 virtual machines, including EICAR test-file handling. Do not test live malware on a normal computer.


## Windows maintenance center | مركز صيانة ويندوز

The Windows Tools & Optimization panel provides shortcuts and guarded actions for common maintenance:

- Clean files older than seven days from the signed-in user's TEMP folder and its subfolders. The cleanup does not follow junctions or symbolic links, skips files in use, and never targets personal folders, Downloads, browser profiles, or Windows system folders.
- Clear the current user's Windows thumbnail-cache database files; Windows rebuilds them and files in use are skipped.
- Flush the Windows DNS resolver cache (with Windows administrator approval).
- Run an online NTFS disk scan on the Windows system drive with CHKDSK /scan (no offline repair is scheduled).
- Run Microsoft's DISM /Online /Cleanup-Image /RestoreHealth and System File Checker /scannow with a Windows UAC prompt. Their own console output is authoritative; Danat does not report repairs as successful based only on process launch.
- Open Windows Storage, Startup Apps, Network settings, and Drive Optimization pages.

These tools are user-initiated and show confirmation before cleanup or repair. Registry cleaning and automatic registry deletion are intentionally not provided because generic registry cleaners can damage Windows or applications. This preview does not silently change network configuration, delete update databases, or modify protected system settings.

## Build

Open `DanatAntiVirus.sln` in Visual Studio 2022 with the .NET Framework 4.8 Developer Pack and WPF workload installed. Build the `Release` configuration.

The Danat interface runs at the signed-in user's normal privilege level. When a Microsoft Defender custom scan is requested, Danat launches only Microsoft's `MpCmdRun.exe` with Windows `runas`, so Windows displays a UAC prompt for that scan process. ClamAV setup and scanning remain in the unelevated Danat process; ClamAV does not inherit administrator privileges from the UI.

## Safety

No antivirus can guarantee protection from every threat. Danat must not show a protected state unless the underlying engine's actual state has been verified. A successful custom scan is not a guarantee that a device is malware-free.


### Arabic and English interface | الواجهة العربية والإنجليزية

The maintenance center displays tool names, confirmations, status messages, and safety notices in both English and Arabic. | يعرض مركز الصيانة أسماء الأدوات ورسائل التأكيد والحالة والتنبيهات باللغتين العربية والإنجليزية.
