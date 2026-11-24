# Third-party software notices

## ClamAV

Danat Anti-Virus can optionally invoke Windows Package Manager (WinGet) to install the separate ClamAV program under the package identifier `Cisco.ClamAV`.

- Project: Cisco-Talos ClamAV
- Copyright: ClamAV contributors and applicable third-party copyright holders.
- Licence: GNU General Public License, version 2 (GPL-2.0).
- Official source repository: https://github.com/Cisco-Talos/clamav
- Official licence text: https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt
- Official Windows releases: https://github.com/Cisco-Talos/clamav/releases
- Official documentation: https://docs.clamav.net/

The current preview requires ClamAV 1.5.5 or later. The installer is obtained from the Cisco-Talos GitHub release through a community-maintained WinGet manifest in the Microsoft WinGet package repository. The manifest supplies the installer URL and SHA-256 hash used by WinGet for its package integrity check. The manifest is not maintained by Cisco. Cisco and the ClamAV project do not sponsor, certify, or endorse Danat Anti-Virus.

ClamAV is a separate program. Danat Anti-Virus does not bundle, modify, or link against ClamAV binaries or libraries. ClamAV remains subject to its own GPL-2.0 licence and notices. This notice is provided for attribution and transparency; it is not a substitute for the full licence.

If a future release of Danat copies, bundles, modifies, or redistributes ClamAV binaries or source, do not publish that release until the exact ClamAV version, complete applicable licence texts, copyright notices, and GPL corresponding-source obligations have been reviewed and satisfied.

## Microsoft Windows Package Manager

Danat invokes the Windows Package Manager (`winget.exe`) already provided by Microsoft's App Installer on supported Windows systems. WinGet is a Microsoft project; its terms and notices are separate from Danat's. Danat does not redistribute the WinGet client.
