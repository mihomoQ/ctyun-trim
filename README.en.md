<div align="center">
  <h1>CTyunTrim</h1>
  <p>A component-trimming tool for preinstalled CTyun Cloud PC images</p>
  <p>
    <a href="https://github.com/mihomoQ/ctyun-trim/releases">Download</a> ·
    <a href="#quick-start">Quick start</a> ·
    <a href="docs/USAGE.md">Usage guide (Chinese)</a> ·
    <a href="https://github.com/mihomoQ/ctyun-trim/issues">Report an issue</a>
  </p>
  <p>
    <a href="https://github.com/mihomoQ/ctyun-trim/actions/workflows/powershell.yml"><img src="https://github.com/mihomoQ/ctyun-trim/actions/workflows/powershell.yml/badge.svg?branch=main" alt="PowerShell checks"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-blue.svg" alt="GPL-3.0-only"></a>
  </p>
  <p><a href="README.md">简体中文</a> · <strong>English</strong></p>
</div>

CTyunTrim removes identified management, self-repair, and optional components from preinstalled Windows images used by CTyun Cloud PCs while retaining the core required for the official connection, keyboard and mouse input, text clipboard support, and ordinary file transfers. It is a standalone PowerShell tool that can be used alongside ReviOS; it is not a general-purpose Windows optimizer.

> [!WARNING]
> This project is still an experimental prerelease. Its operations can disrupt remote connectivity or prevent Windows from starting. Before running it, create and verify a restorable system snapshot, back up important data, and prepare an independent recovery path. Component backups are not a complete rollback, and automated Restore is not currently provided.

## Features

- **Trim preinstalled components:** Handles the manifest-listed AI assistant, app marketplace, cloud printing, self-repair and update chain, plus the `cloudbase-init` service, account, user profile, and program files.
- **Preserve required interoperability:** Retains the validated Clink, cloudshare, clipa, Balloon, and supporting drivers. It never deletes by a wildcard vendor name or directory match.
- **Resume with one command:** Automatically chains preparation and trimming, then resumes with the same command after a reboot. Running it again after completion performs verification only.
- **Inspect before modifying:** Supports read-only inventory and previews, backs up before changes, stops on identity mismatches, and can export a sanitized diagnostic bundle.
- **Restore the power menu:** Restores Shutdown and Restart options hidden by preinstalled policy, including through a standalone command on an already-trimmed system.

## Supported scope

CTyunTrim requires **Windows 11 x64, administrator privileges, and Windows PowerShell 5.1**. The `.cmd` launchers automatically select 64-bit Windows PowerShell. Do not use PowerShell 7 to run mutating operations directly.

The project is developed against CTyun's preinstalled **Windows 11 Enterprise LTSC (64-bit, Chinese)** image, identified as:

`Windows-11-企业版-LTSC-x64-Chinese-v26.0316`

Testing has covered this preinstalled image used together with ReviOS. The identifier above is an image version, not a Windows build number. The current profile still validates builds **26100 / 26200** and recorded component combinations including `clipa 2.1.0.0`. A matching image name or Windows build number alone does not establish compatibility: actual files and services must also pass validation. Audit other images first, and never bypass preflight checks. See the [reference baseline](docs/REFERENCE-BASELINE.md) and [real-system test record](docs/TEST-RESULTS-0.1.7.md).

## Quick start

### 1. Download and extract

From [Releases](https://github.com/mihomoQ/ctyun-trim/releases), download the selected version's `CTyunTrim-<version>-Diagnostic.zip` and matching `.sha256` file. Verify the archive, then extract it completely. Do not mix scripts from different versions or execute the project through a remote download-and-run pipeline. See the [Chinese usage guide](docs/USAGE.md#下载与校验) for checksum instructions.

When using ReviOS, the steps below apply to a system where ReviOS has already been installed and the CTyun components remain available for validation. If you must remove the preinstalled update policy before installing ReviOS, follow the [staged workflow (Chinese)](docs/USAGE.md#与-revios-分阶段使用).

### 2. Inspect the system and plan

Open an elevated terminal in the extracted directory and run:

```powershell
.\Start-CTyunTrim.cmd -Mode Audit
.\Trim.cmd -WhatIf
```

Review the output and confirm that a usable snapshot exists before continuing.

### 3. Run the trim workflow

```powershell
.\Trim.cmd -Force
```

If the result is `PendingReboot`, restart Windows and run the same command again. You do not need to enter a RunId, and the script never restarts Windows automatically. Once the task is complete, another run verifies the result without repeating removal.

After completion, use the official CTyun client to test reconnection, keyboard and mouse input, the bidirectional text clipboard, and ordinary file transfers. Automated verification cannot replace real interoperability checks.

<details>
<summary>Already trimmed: restore only the Shutdown and Restart options</summary>

Open an elevated terminal as the same account that operates the desktop:

```powershell
.\Restore-PowerMenu.cmd -Force
```

This does not rerun trimming and does not directly shut down or restart Windows. See the [power-menu guide (Chinese)](docs/POWER-MENU.md) for the exact scope and managed-policy restrictions.

</details>

## Documentation

| I want to learn… | Document |
| --- | --- |
| Parameters, staged operation, upgrades, and common blockers | [Full usage guide (Chinese)](docs/USAGE.md) |
| How to use CTyunTrim with ReviOS | [ReviOS coexistence](docs/REVIOS.md) |
| Which components are preserved or removed | [Component boundaries](docs/COMPONENTS.md) |
| How to provide diagnostic information | [Diagnostic bundles](docs/DIAGNOSTICS.md) · [Support tools](tools/README.md) |
| Where backups are stored and how recovery works | [Backup and recovery](docs/RECOVERY.md) |
| What has been validated and which limits remain | [Test record](docs/TEST-RESULTS-0.1.7.md) · [Threat model](docs/THREAT-MODEL.md) |

## Feedback and contributions

If you encounter a problem, open an [issue](https://github.com/mihomoQ/ctyun-trim/issues) and include the version, operation mode, and error message. You can use `-Diagnostic` to generate a support bundle, but review it before sharing. Never upload a complete run backup, quarantined files, account credentials, or private keys.

Component evidence, test feedback, and improvements are welcome. Read the [contribution guide](CONTRIBUTING.md) first, and report security issues according to [SECURITY.md](SECURITY.md).

## Disclaimer and license

This project is not affiliated with or endorsed by CTyun, ReviOS, AME, or related parties. Preserving vendor components means only that they are functionally required; it is not a statement that they are safe or trustworthy. This tool also cannot constrain the cloud platform's control over virtual machines, disks, snapshots, or networks. See the [disclaimer](DISCLAIMER.md).

Licensed under the [GNU General Public License v3.0](LICENSE), version 3 only (`GPL-3.0-only`). Historical release archives retain their included licenses.
