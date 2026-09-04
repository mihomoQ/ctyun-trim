# LGPO.exe

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
