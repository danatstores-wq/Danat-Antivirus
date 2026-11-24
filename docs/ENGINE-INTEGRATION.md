# Microsoft Defender integration

## What this integration does

Danat Anti-Virus 0.3 acts as a desktop controller for the Microsoft Defender Antivirus engine already installed by Windows. It does not bundle, download, or replace the Microsoft engine.

The application:
1. Calls the Defender PowerShell cmdlet `Get-MpComputerStatus` and displays running mode, service state, antivirus state, real-time protection state, and signature age.
2. Finds the newest versioned platform directory under `%ProgramData%\Microsoft\Windows Defender\Platform\`, falling back to `%ProgramFiles%\Windows Defender\MpCmdRun.exe`.
3. Starts a custom scan with `MpCmdRun.exe -Scan -ScanType 3 -File "<path>" -DisableRemediation`.
4. Captures command output in the application. It does not delete or move files.

## Why remediation is disabled

The default scan is report-only: `-DisableRemediation` prevents this scan request from applying actions. Microsoft documents that detections from this mode are shown in command output rather than the Windows Security UI, and that event-log entries are not written. Danat captures that output.

The UI also offers an explicit, unchecked consent option. If the user selects it and confirms a warning dialog, Danat omits `-DisableRemediation` and lets Microsoft Defender apply its normal remediation policy. Defender may quarantine or remove detected files. Danat does not implement its own quarantine store or restore mechanism; the Protection History shortcut opens Windows Security so the user can review Defender-managed actions and any available restore controls. This feature must be tested with EICAR in an isolated Windows VM before general distribution.

## Privileges

Microsoft documents MpCmdRun usage from an elevated Command Prompt. The WPF app manifest uses `asInvoker`, so Danat itself does not request administrator privileges. When the user starts a Defender scan, Danat launches only Microsoft's `MpCmdRun.exe` using the Windows `runas` verb; Windows displays a UAC prompt and elevates that process alone. ClamAV setup, signature updates, and scans run as children of the unelevated Danat UI and therefore do not inherit administrator privileges. Defender scan output is represented by the process exit code in Danat's log because ShellExecute elevation does not support redirected standard output.

## Result interpretation

Microsoft documents exit code 0 as no malware found or malware found and successfully remediated; code 2 can mean malware was found but not remediated, user action is required, or a scan error occurred. Since this app uses `-DisableRemediation`, code 2 is always reported as unresolved and never as clean. Any unexpected code is also unresolved.

## Platform boundaries

- This integration is intended for supported Windows 10/11 installations with Microsoft Defender Antivirus.
- It is not validated for Windows 7.
- Defender's own real-time protection and security-intelligence updates remain Windows responsibilities. Danat does not implement a file-system minifilter, ransomware behavior monitoring, or independent threat intelligence.
- If Defender is in passive mode or disabled, Danat reports that state rather than claiming the PC is protected.

## Microsoft references

- Command-line tool and scan exit codes: https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
- On-demand scan guidance: https://learn.microsoft.com/en-us/defender-endpoint/run-scan-microsoft-defender-antivirus
- Defender status cmdlet: https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus
- Defender operating modes: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows

## Optional ClamAV manual scanner

Danat provides an in-app **SET UP CLAMAV** action. After explicit user confirmation, it invokes Windows Package Manager with the exact package identifier `Cisco.ClamAV` from the `winget` source. The community-maintained WinGet manifest selects the Windows architecture, points to the official Cisco-Talos ClamAV GitHub release installer, and supplies the SHA-256 hash that WinGet checks after download. This is a community manifest, not a Cisco-maintained distribution channel or an endorsement of Danat by Cisco. Danat does not host, bundle, modify, or link against ClamAV binaries; WinGet installs ClamAV as a separate program. The ClamAV executable remains under GPL-2.0. See `THIRD-PARTY-NOTICES.md`. If ClamAV is already present, the action checks for an engine update instead.

After setup, Danat creates a per-user configuration under `%LOCALAPPDATA%\DanatAntiVirus\ClamAV` and stores signatures in its writable `Database` subfolder. It invokes the installed `freshclam.exe` with that configuration before each ClamAV scan, refreshing at least every four hours, and cancels the scan if a required signature update fails. ClamAV's own signed database verification remains enabled. Danat does not install a background on-access service or claim real-time protection. WinGet must be available; if it is not, setup stops with a clear error rather than downloading an unverified installer.

Before setup completion and before each scan, Danat runs `clamscan --version` and refuses to scan if the engine is older than 1.5.5. ClamAV 1.5.5 fixes multiple vulnerabilities affecting versions through 1.5.4 (including CVE-2026-76411, CVE-2026-76414, CVE-2026-76415, CVE-2026-76416, CVE-2026-76417, CVE-2026-76421, CVE-2026-76422, CVE-2026-76430, CVE-2026-76515, and CVE-2026-76516). This is a minimum-version guard for the current preview, not a substitute for ongoing security updates. Exit codes are interpreted as 0 = no infected files reported, 1 = infected file(s) reported, and 2 = scan error. Output is displayed in the scan log. Danat does not delete, move, or quarantine files. This is an on-demand scanner only, not on-access or real-time protection. See the ClamAV Windows FAQ: https://docs.clamav.net/faq/faq-win32.html

ClamAV is licensed under GPL-2.0. In this design, WinGet obtains the installer from the official Cisco-Talos GitHub release and installs ClamAV as a separate program; Danat does not distribute ClamAV binaries with its own application, modify them, or link to its libraries. The WinGet manifest is community-maintained and includes an installer SHA-256 value. See `THIRD-PARTY-NOTICES.md` for attribution and official licence/source links. Any future bundling, copying, or redistribution of ClamAV binaries must be reviewed for GPL compliance before release, including the applicable licence, notices, and corresponding-source requirements.
