# Danat Anti-Virus

A Windows desktop security product with a premium black-and-metallic-gold identity.

## Product requirements
- 14-day free trial, followed by an annual subscription initially priced at **US$3/year**.
- Requested operating systems: Windows 7 SP1, Windows 10, and Windows 11. Windows 7 and Windows 10 are out of support; this app cannot remove the security risks of an unsupported OS.
- Planned protection: malware scanning, ransomware behavior monitoring, real-time file monitoring, USB scanning, quarantine, and security updates.
- The supplied Danat Coin warrior artwork is the intended application icon and scan-screen visual.

## Safety and honest status
No antivirus can guarantee protection from every threat. This repository currently contains only a desktop interface shell. It does **not** scan for malware or protect the computer yet. The UI must never show a false “protected” state.

## Development milestones
1. Windows desktop shell and black/gold dashboard.
2. Integrate a reputable, maintained detection engine; do not substitute filename rules or simulated progress for real detection.
3. Implement safe quarantine and scan reporting.
4. Add ransomware behavior monitoring and USB scanning with false-positive testing.
5. Add server-validated trial and annual licensing. Never embed private signing keys or billing secrets in the desktop binary.
6. Test in isolated virtual machines on each claimed Windows version before advertising compatibility or protection.

## Build
Open `DanatAntiVirus.sln` in Visual Studio 2022 with the .NET Framework 4.8 Developer Pack and WPF workload installed. Build the `Release` configuration.

## Current status
**Preview 0.2:** WPF desktop app with an optional manual ClamAV scan launcher. Users must separately install ClamAV, select `clamscan.exe`, select a local signature database folder, and choose a scan folder. The app checks for main/daily databases, blocks databases with old file timestamps, and asks ClamAV to reject databases older than 7 days. Scanner exit code 2 is treated as an error—not a clean scan. Detected files are reported but never automatically changed. This is not real-time protection, ransomware protection, quarantine, automatic signature updates, or subscription enforcement.
