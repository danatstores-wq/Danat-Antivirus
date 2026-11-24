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
- Reads redirected Defender status output asynchronously to avoid blocking if PowerShell writes more output than a pipe buffer can hold.
- Treats Defender exit code 2 as unresolved (malware may remain unremediated or a scan error occurred), never as a clean result.
- Requests administrator privileges because Microsoft's command-line tool requires an elevated command prompt.

**This is a controller for Microsoft Defender, not a new antivirus engine.** Defender must already be installed, enabled, and kept updated by Windows. Danat does not install Defender, replace it, or provide an independent real-time driver, ransomware behavior engine, quarantine system, or subscription backend.

## Supported platform scope

The desktop application is built on .NET Framework 4.8 and includes a Windows 7 SP1 compatibility mode. On Windows 7, modern Microsoft Defender PowerShell status APIs and the Windows Security settings URI are not available; the app therefore shows a clear legacy-mode notice and opens the Windows 7 Security Center instead. It can discover the legacy Microsoft Security Essentials command-line scanner if that product is already installed, but it does not install it or claim that it provides current protection. Microsoft Security Essentials and Windows 7 are out of support, so this legacy path is for compatibility/testing only and must not be treated as adequate current security. On Windows 10/11, the modern Microsoft Defender integration remains in use.

## Product requirements still pending

- Independent real-time protection and ransomware behavior monitoring, if a separately licensed engine can be selected.
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
