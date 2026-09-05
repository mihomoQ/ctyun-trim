# Changelog

## 0.1.5-Diagnostic - 2026-09-05

- Added a resume-only service quiesce stage for the observed loaded Cloudbase Profile with zero SID-owned processes and the exact stopped, automatic Cloudbase service. A protected write-ahead record and separate registry backup precede disabling only that service's startup; the invocation returns `PendingReboot` without entering removal.
- Kept Profile/account deletion behind the existing strict unloaded-profile checks. Same-boot replay cannot enter removal; a Profile still loaded after the quiesce reboot remains blocked.
- Preserved compatibility with 0.1.4 run contexts and the unchanged immutable component manifest.
- Prevented recreated scheduled tasks from overwriting XML backups bound to older journal entries; pending operations support both legacy and unique backup names.
- Included the independent read-only Cloudbase occupancy collector and its PowerShell 5.1 privacy/failure-path tests.
- Added service-quiesce and recreated-task backup regression tests.

## 0.1.4-Diagnostic - 2026-09-05

- Added a Prepare-only exception for the observed loaded Cloudbase profile when its sole holder is the exact, service-session `TaskAgentDetect.exe` scheduled-task image with matching owner SID, trusted signature, secure path and stable process identity.
- Kept `Special` profiles and every loaded or mounted-hive profile in Apply as hard failures; CTyunTrim never force-unloads the user hive.
- Added an immutable service/task-principal SID ownership anchor, full owner-SID process enumeration and same-SID Profile-path checks before accepting or deleting the Cloudbase identity.
- Reordered Cloudbase cleanup to journal and prove the account disabled, recheck owner processes at the Profile deletion boundary, remove the unloaded Profile, and only then remove the local account.
- Added sanitized loaded, Special, hive-mounted and identity-match profile counts to diagnostic output.
- Fixed negative messages containing `loaded` from being mislabeled as diagnostic `Success`.
- Added Prepare/Apply phase and unsafe-process regression tests.

## 0.1.3-Diagnostic - 2026-09-04

- Fixed Windows PowerShell 5.1 scalar unrolling of empty/single conditional collections in initial Cloudbase preflight and execution-guard resume checks.
- Added full preflight regression fixtures for a fresh empty context, one owned pending guard, one archived Cloudbase identity record and an unknown guard conflict.
- Confirmed the reported failure occurs before RunId creation or any Prepare system mutation.

## 0.1.2-Diagnostic - 2026-09-04

- Added an exact `PinnedHashAndSigner` trust policy for the observed VirtIO `BalloonService` binary whose Red Hat development certificate chains to an untrusted self-issued root.
- Pinned the Balloon executable SHA-256, embedded signer thumbprint, subject, issuer, service name and canonical image path; no certificate is installed or trusted system-wide.
- Kept `AuthenticodeValidAtBaseline` mandatory before cleanup for every other preserved service and driver; later runs require exact protected-baseline hash and signer continuity when deliberate certificate removal changes chain trust.
- Added locked double-hash core evidence collection, source ACL checks, signer continuity across the protected baseline, and fail-closed trust-policy tests.
- Phase-gated ordinary signature trust degradation on durable certificate-removal journal evidence; Prepare and pre-certificate resume still require `Valid`.
- Revalidated the newly written baseline against live core evidence before either Prepare or Apply can change the system.
- Added sanitized trust-policy Booleans to diagnostics without exposing file hashes or signer identities.
- Fixed localized Windows architecture values being reported as `Unknown` in diagnostic bundles.
- Made requested read-only/WhatIf diagnostic export failures return a failing exit status while preserving successful real Prepare/Apply status to prevent destructive replay.
- Added strict release source/staging/ZIP file-set and per-entry hash validation.

## 0.1.1-Diagnostic - 2026-09-04

- Added the opt-in `-Diagnostic` modifier without forking the destructive execution path.
- Added a four-entry, strict-allowlist support ZIP with an external SHA-256 sidecar.
- Added structured operation, preflight, journal, reboot and native-command event summaries.
- Added stateless and RunId-bound diagnostics while excluding raw run backups and sensitive host data.
- Added diagnostic success/failure JSON envelopes and preserved primary failure exit behavior.
- Added dedicated sanitization, archive-integrity, failure-path and read-only tests.

## 0.1.0 - 2026-09-04

- Added the `MinimalInterop` versioned component manifest.
- Added read-only `Audit`, `Plan`, and `Verify` modes.
- Added `Prepare` for pre-ReviOS self-repair blocking and fake-WSUS cleanup without removing components.
- Added guarded `Apply` with timestamped inventory, registry, policy, task and certificate backups.
- Added IFEO self-repair guards for the six verified CTyun executables.
- Added exact fake-WSUS LocalGPO cleanup through a Microsoft-signed `LGPO.exe`.
- Added full `cloudbase-init` service/account/Profile/program removal.
- Added same-volume path quarantine and evidence exports; automated `Restore` remains deliberately disabled.
- Added hard protection for Clink, cloudshare, clipa, Balloon, required WinDivert components and `dokan2.dll`.
- Added an immutable reference-manifest hash, exact scheduled-task actions, a `clipa 2.1.0.0` core fingerprint, hardened LGPO staging, fail-closed backups and write-ahead resume handling.
- Added SID-bound Cloudbase evidence, protected core-file hashes, transaction-abort confirmation semantics, strict task/firewall verification and reparse-safe release checksums.
