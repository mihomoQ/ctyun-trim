# Changelog

## 0.1.0 - Unreleased

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
