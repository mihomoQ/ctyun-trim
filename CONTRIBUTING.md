# Contributing

CTyunTrim modifies remote-access and kernel-level components. Evidence and safety requirements are intentionally strict.

## Component evidence

Every new removal rule must include:

- exact service, task, file or registry identity;
- normalized path and expected root;
- service `ImagePath` or task Action;
- signature, publisher and version when available;
- process/module/log evidence;
- before/after reboot tests;
- rollback limitations;
- tested Windows and CTyun image versions.

Rules based only on `*cloud*`, `*ctyun*`, display names, company names or broad directory fragments will not be accepted.

## PowerShell rules

- Remain compatible with 64-bit Windows PowerShell 5.1.
- Use `Set-StrictMode -Version 2.0`.
- Public destructive functions use `SupportsShouldProcess`.
- Use `-LiteralPath`; never pass wildcard paths to deletion/move operations.
- Reject reparse points and removal paths that equal or contain protected paths.
- Never use `Invoke-Expression` or `Win32_Product`.
- Do not download and execute code at runtime.
- Do not disable Defender, UAC, the firewall or signature validation globally.
- All unknown or conflicting state must produce `Blocked`, not fail open.
- Repeated Apply must be safe and idempotent.

## Required tests

1. `Audit` and `Apply -WhatIf` make no system changes.
2. Manifest and PowerShell 5.1 syntax tests pass.
3. Preserve and remove collections do not intersect.
4. Apply can be run twice without expanding its effects.
5. Unsupported builds refuse Apply.
6. At least two reboots are tested on a disposable CTyun snapshot.
7. Official reconnect, keyboard/mouse, display, text clipboard, ordinary file transfer, audio and network are manually verified.
8. Recovery limitations are documented for every new irreversible action; automated Restore is not available.
9. Diagnostic schema changes pass canary-leak, fixed-entry, size, hash, failure-path and read-only regression tests.

Test fixtures and Issues must not contain real credentials or unsanitized machine data.
