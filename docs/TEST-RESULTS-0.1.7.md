# 0.1.7 test results

Test date: 2026-09-05. Test system: Windows build 26200, Windows PowerShell
5.1.26100.7920 x64, ReviOS installed, original CTyun components present.
The owner supplied an initial snapshot and authorized destructive tests.
This is evidence for that image, not all CTyun images or versions.

## Source and scope

Tested module SHA-256:

`CF21B03015C2878FF9129EA6168D32A2B2E5D9CE7CCCE252130F8FF2E7607523`

The immutable removal manifest was unchanged. Preserved core: BalloonService,
clink_service, clipa 2.1.0.0, cloudshare_service, CLINKAC, ClinkMouseFilter and
WinDivertScanner. No existing run directories were present at the initial check.

## Local regression tests

All ten Windows PowerShell 5.1 suites passed: Static, CoreTrust, Diagnostic,
CloudbaseOccupancy, CloudbaseQuiesce, TaskBackup, QuarantineResume, TrimWorkflow,
ProcessStop and RuntimeData. The local Diagnostic suite covered the sanitizer
and non-elevated failure contract; elevated ZIP creation was then exercised by
the real remote Trim runs. Release staging and ZIP entries were checked against
an explicit file allowlist and source hashes.

## Real-system results

| Scenario | Observed result |
| --- | --- |
| Initial Trim WhatIf | 107 actions; no run created; core services unchanged |
| First `Trim -Force` | Prepared and quiesced automatically; PendingReboot; 153.6 s; 3 warnings |
| Same-boot repeat | PendingReboot in 1.8 s; still 36 operations and 3 warnings; no repeated changes |
| First reboot | SSH recovered automatically; four core services running; zero PnP errors |
| Second `Trim -Force` | Same run selected; component cleanup; PendingReboot; 126 s; no pending operations |
| Second reboot | Core services running; zero PnP errors |
| Third `Trim -Force` | Applied; no reboot required; 97 s; 4 cumulative warnings |
| Post-completion reboot | Verify passed; seven core services/drivers healthy; no retired services/drivers/certificates or Cloudbase Profile |
| Runtime metadata | Empty FileCrypto directory and one 266-byte recognized printer initialization log reported separately |
| Negative metadata test | One newly created inert TXT file caused Verify failure and process exit code 1 |
| Test cleanup/recheck | Only the test file was removed; Verify passed again; state file hash and operation count unchanged |

The final run contained 142 completed operations and no pending operations.
Runtime directories were not silently equated with executable component recovery.
An unknown file still failed verification.

## Test infrastructure

Tailscale unattended mode was enabled on the test machine for automatic reboot
recovery. Two remote stdin-reader sessions stalled before starting the second
Trim; an idle Trim mutex and unchanged state were confirmed, only the exact test
processes were stopped, and transport changed to short encoded commands or
hash-verified uploaded scripts. This was a test transport issue, not a cleanup
operation failure.

No snapshot restoration was needed during this run. The initial snapshot and
component backups were retained. Raw run backups, host identities, private keys
and diagnostic archives are not included in this repository.

## Manual acceptance and limits

The owner confirmed that official-client reconnect, keyboard/mouse,
bidirectional text clipboard and ordinary TXT/ZIP file transfer work normally
after cleanup. Audio, special device redirection and dynamic resolution were
not separately tested in this session.

These results cover the identified guest-side components and this tested image;
they do not establish the absence of every possible management capability in
the preserved core or the cloud platform.
