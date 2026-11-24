# Microsoft Defender integration

## What this integration does

Danat Anti-Virus 0.3 acts as a desktop controller for the Microsoft Defender Antivirus engine already installed by Windows. It does not bundle, download, or replace the Microsoft engine.

The application:
1. Calls the Defender PowerShell cmdlet `Get-MpComputerStatus` and displays running mode, service state, antivirus state, real-time protection state, and signature age.
2. Finds the newest versioned platform directory under `%ProgramData%\Microsoft\Windows Defender\Platform\`, falling back to `%ProgramFiles%\Windows Defender\MpCmdRun.exe`.
3. Starts a custom scan with `MpCmdRun.exe -Scan -ScanType 3 -File "<path>" -DisableRemediation`.
4. Captures command output in the application. It does not delete or move files.

## Why remediation is disabled

The first integration is deliberately scan/report only. Microsoft's documentation states that `-DisableRemediation` is valid for custom scans and prevents actions from being applied after detection. It also notes that detections from such a custom scan are shown in command output rather than the Windows Security UI. The user should review Danat's scan output and Windows Security Protection history. Quarantine/restore will not be implemented until a safe, auditable workflow is designed.

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
