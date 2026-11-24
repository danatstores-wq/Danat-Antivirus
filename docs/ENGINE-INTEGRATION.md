# Detection engine integration plan

## Decision for the first prototype

Evaluate the official ClamAV Windows command-line scanner (`clamscan.exe`) as an **optional, manually launched scan engine**. Danat Anti-Virus must not pretend this provides full endpoint protection.

Official references:
- Windows FAQ: https://docs.clamav.net/faq/faq-win32.html
- ClamAV introduction, platforms and license: https://docs.clamav.net/
- ClamAV libclamav development/API license: https://docs.clamav.net/manual/Development/libclamav.html
- Official downloads: https://www.clamav.net/download.html

## Important constraints

1. ClamAV is GPLv2. The official documentation says applications linking against `libclamav` must be GPL-compliant. Before distributing ClamAV binaries with a closed-source commercial Danat product, obtain a licensing review and satisfy all applicable source, notice, and redistribution obligations. Launching a separately installed command-line program does not remove the need to review distribution and product-boundary questions.
2. ClamAV's Windows FAQ says Windows packages exist for Windows 7 and newer, but its current platform page lists Windows 10 and 11 among regularly tested platforms. Do not advertise Windows 7 compatibility based only on package availability.
3. ClamAV's Windows FAQ says its Windows build does not provide the Linux on-access scanning feature. A manual scanner is not real-time protection.
4. ClamAV describes itself as an anti-virus toolkit, not a complete modern endpoint security suite. It cannot alone deliver the requested ransomware protection, exploit prevention, web protection, or comprehensive endpoint response.
5. ClamAV's documented recommended memory for Windows 10/11 is 3 GiB or more, and the recommended disk space for the application is 5 GiB in addition to the operating system.

## Safe implementation sequence

- First prototype implemented: a manually started, user-selected folder scan invokes a user-installed `clamscan.exe` as a child process. The app checks the executable's version output, requires main and daily databases with recent file timestamps, and passes `--fail-if-cvd-older-than=7` so ClamAV validates database age itself. It also enables alerts for encrypted and scan-limit-exceeded files. Never download or execute an engine binary silently.
- Require a usable local signature database; report missing, unreadable, or stale definitions as **protection unavailable**, never as a clean result.
- Interpret scanner exit codes correctly: 0 = no detections reported, 1 = detections reported, 2 = scanner error. A scanner error is not a clean scan.
- Display detected file paths and signature names. Do not delete or quarantine files automatically in the first iteration.
- Add safe quarantine only after a separate design review covering atomic moves, permissions, restore, audit logging, and false positives.
- Add real-time/ransomware protection only through a separately evaluated, properly licensed endpoint engine or a rigorously tested Windows implementation. Do not claim protection until tested.
- Test with the harmless EICAR anti-malware test file and benign test corpora in isolated virtual machines. Never use live malware on a normal computer.

## Commercial product gate

The initial US$3/year price is a product requirement, not evidence that a suitable commercial engine is affordable. Before launch, compare engine licensing, signature-feed rights, update infrastructure, support, payment fees, and security testing costs. Do not ship a product that implies comprehensive protection when it only performs on-demand signature scanning.
