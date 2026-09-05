# Support tools

## Cloudbase profile occupancy

`Get-CTCloudbaseOccupancy.ps1` is a standalone, read-only support collector for a
Cloudbase Profile that remains loaded after restarting. Run it in 64-bit elevated
Windows PowerShell 5.1; it does not require a CTyunTrim RunId or change its journal.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-CTCloudbaseOccupancy.ps1
```

It prints JSON with account/Profile consistency, enabled/loaded/hive flags,
account-owned process summaries, WMI logon-session types, and service/task
references. Queries that cannot complete are reported explicitly. A zero process
count is not proof that another account's process does not hold a registry handle;
WMI logon-session records are not proof of an active interactive desktop.

The collector omits raw SIDs, account names, command lines, arbitrary paths and
event messages. Known component names use a fixed allowlist; unknown references
are counted. It does not write files, upload data, stop processes, disable accounts
or services, unload hives, or delete Profiles. Review its output before sharing it.

This helper is also included in the 0.1.5 release, under `tools`.
Do not repeat Apply solely because this collector completed; its output is
diagnostic evidence, not a deletion approval.

`PrincipalResolutionFailedCount` counts task or service principals that this
collector could not resolve; it is not a count of malicious tasks. Incomplete
task attribution does not invalidate independently completed process and service
queries. Use each section's completion flags when interpreting the result.

## LGPO.exe

CTyunTrim does not redistribute Microsoft `LGPO.exe`.

The current trust profile accepts only Microsoft's LGPO v3.0 binary from the Security Compliance Toolkit download:

```text
LGPO.exe version: 3.0.2004.13001
LGPO.exe SHA-256: 0C97F29543418B30340C4FF5D930D31E6196DD59C2CC74B6B890FA7B90C910C7
LGPO.zip SHA-256: CB7159D134A0A1E7B1ED2ADA9A3CE8CE8F4DE391D14403D55438AF824247CC55
Official page: https://www.microsoft.com/en-us/download/details.aspx?id=55319
```

A future Microsoft LGPO release intentionally requires a CTyunTrim code/profile update; signer display text alone is not a trust anchor.

If the reference CTyun copy at:

```text
C:\Program Files (x86)\ctyun\clink\Mirror\ScriptConfig\LGPO.exe
```

is unavailable, obtain LGPO from Microsoft's Security Compliance Toolkit and either:

- place it at `C:\ProgramData\LGPO\LGPO.exe`; or
- pass its path with `-LgpoPath`.

CTyunTrim requires the pinned binary hash, validates the candidate's Microsoft Authenticode signature and parent-directory ACLs, copies it into the ACL-hardened RunId directory, compares source and staged SHA-256 hashes, and validates the staged copy again before invoking it. It uses LGPO only to apply five `CLEAR` records for the observed fake-WSUS LocalGPO entries. It never deletes the complete `Registry.pol` file or GroupPolicy directory.
