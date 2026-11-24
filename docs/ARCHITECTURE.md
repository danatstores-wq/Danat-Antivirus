# Architecture plan

## Desktop client
- WPF on .NET Framework 4.8 for the first Windows shell, chosen to keep a possible Windows 7 SP1 compatibility path.
- Keep UI state truthful: until the scanner service is installed and health-checked, status remains **Not protected**.
- UI and service communicate through a narrow, authenticated local IPC boundary.

## Detection engine
- Evaluate a maintained, reputable scanning engine and its redistribution/licensing terms before selecting it.
- Scan requests must report engine/version, signature timestamp, file result, and errors.
- Quarantine must preserve original path and metadata, store files in an access-restricted location, and support audited restore/delete actions.
- Never delete files solely because a filename or extension looks suspicious.

## Real-time and ransomware defense
- Start with a least-privilege user-mode service and file-system event monitoring.
- Use behavioral signals and engine verdicts together; rate-limit and log actions.
- Avoid custom kernel drivers in the initial release.
- Test with benign bulk file operations and safe, purpose-built test samples in disposable VMs.

## Licensing
- Trial and annual entitlement are verified by a server; the desktop binary contains no private signing secret.
- Price is configurable; initial product decision is US$3 per year after a 14-day trial.
- Do not block emergency restore/export of quarantined user files when a subscription expires.

## Platform caveats
Windows 7 and Windows 10 are out of support. Any compatibility target needs explicit VM testing, and users must be warned that an unsupported OS remains exposed to OS-level vulnerabilities.
