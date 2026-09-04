# Changelog

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
