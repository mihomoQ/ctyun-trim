# Security policy

## Supported versions

Only the latest published release receives security fixes. The `main` branch is development code and must not be treated as a stable release.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting when available. Do not publish an Issue before maintainers have had a reasonable opportunity to investigate.

Useful reports include:

- affected CTyunTrim version and Windows build;
- a minimal reproduction;
- expected impact;
- sanitized Audit or journal excerpts.

Do not upload system images, complete registry exports, quarantined vendor files, credentials, tokens, cookies, private keys or user data.

Relevant security issues include path traversal, reparse-point escape, command injection, overbroad matching, preserve-list bypass, unsafe Restore behavior, logging leaks and release/update supply-chain weaknesses.

Vendor platform vulnerabilities and tests against infrastructure you do not own are outside this repository's scope. Report those through the appropriate vendor security channel.

## Release principles

- No runtime telemetry.
- No silent download or execution of remote code.
- Release archives should include SHA-256 checksums.
- Destructive actions require an explicit mode and `-Force`.
- Unknown environments fail closed.
