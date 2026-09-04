# Disclaimer

CTyunTrim is an independent, unofficial open-source project. It is not affiliated with, supported, certified or endorsed by China Telecom, CTyun, ReviOS, AME, Cloudbase Solutions or any related party. Product names and trademarks are used only to identify compatibility targets.

The project classifies components from reproducible behavior observed inside a Windows guest. Terms such as management surface, self-repair chain and policy refill are technical descriptions and do not constitute a legal or factual allegation that any vendor software is malicious or a backdoor.

The tool performs high-risk system modifications. It may interrupt remote access, delete data, break networking or updates, disable device redirection, destabilize Windows or prevent boot. Use it only on systems you own or are explicitly authorized to administer. You are responsible for applicable contracts, organizational policies, licenses and laws.

Create a usable provider-side VM snapshot and an independent data backup before running Apply. Audit, quarantine and Restore do not replace a complete snapshot and do not guarantee recovery.

CTyunTrim can only reduce management surface visible inside the Windows guest. It cannot inspect or constrain the cloud provider's hypervisor, boot chain, virtual disks, snapshots, backups, virtual network, control plane, recovery console or server-side systems.

The project deliberately preserves selected vendor SYSTEM services, user-mode components and kernel drivers to retain interoperability. Those components may continue to provide management or data channels. Running CTyunTrim is not proof of provider isolation, confidentiality, integrity, absence of backdoors or a zero-trust boundary.

The software is provided under the MIT License on an “AS IS” basis without warranty.
