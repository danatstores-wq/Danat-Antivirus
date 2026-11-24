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

Microsoft documents MpCmdRun usage from an elevated Command Prompt. The WPF app therefore declares `requireAdministrator`, causing Windows UAC to prompt at launch. This is an MVP tradeoff; a future architecture should move privileged work into a narrowly scoped, signed Windows service instead of keeping the entire UI elevated.

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
