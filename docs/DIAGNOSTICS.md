# Diagnostics

`-Diagnostic` is an opt-in modifier for Audit, Plan, Prepare, Apply and Verify. It does not select a second implementation: the primary operation still runs through the same manifest validation, preflight, journal and verification code.

## Output contract

With `-Json -Diagnostic`, stdout contains one envelope:

```json
{
  "Result": {
    "Available": true,
    "ItemCount": 1,
    "RunId": null,
    "Status": null,
    "Passed": null,
    "RebootNeeded": null,
    "WarningCount": null,
    "NextAction": "None"
  },
  "PrimarySucceeded": true,
  "Diagnostic": {
    "Succeeded": true,
    "BundlePath": "[CommonApplicationData]\\CTyunTrim\\Diagnostics\\CTyunTrim-Diagnostic-....zip",
    "SHA256": "...",
    "Bytes": 0,
    "EntryCount": 4,
    "RunBound": false,
    "SanitizerSchema": "1.0",
    "ErrorCode": "None"
  }
}
```

Diagnostic export requires an elevated 64-bit Windows PowerShell 5.1 process. The displayed path uses `[CommonApplicationData]` instead of a user-controlled environment variable. Resolve that Windows Known Folder locally before opening the file.

For privacy, the envelope's `Result` is a reduced status summary rather than the ordinary raw Audit/Plan/Verify object. Run the same mode without `-Diagnostic` when the full local-only result is required; do not treat ordinary output as shareable.

The primary operation and diagnostic export have separate status fields. A failed Verify or failed primary operation remains a failure even when the support ZIP was generated successfully. If a primary Prepare/Apply succeeds but diagnostic export fails, the primary exit status is preserved and `Diagnostic.Succeeded=false` is reported; do not repeat destructive work merely to regenerate diagnostics. Run a later read-only `Audit -Diagnostic -RunId <RunId>` instead.

## Archive allowlist

Every archive contains exactly:

```text
summary.json
environment.json
events.jsonl
README.txt
```

`summary.json` contains stable component IDs, Boolean state, counts, preflight reason codes, journal status and a reduced result summary. `environment.json` contains only tool/runtime and Windows build information. `events.jsonl` contains bounded structured events with stable codes and allowlisted numeric/status fields.

The archive never copies files from the RunId directory. Specifically excluded are:

- `state.clixml` and raw before/after platform reports;
- registry exports, task XML, LocalGPO backups and certificate exports;
- firewall metadata and quarantine contents;
- command lines, task arguments, native stdout/stderr and WMI script bodies;
- usernames, computer names, SIDs, profile paths, IP/MAC/DNS/route data;
- certificate subjects, serials and thumbprints;
- passwords, tokens, cookies and authorization data.

Before compression, the complete staged text is checked against a forbidden-data policy. Archive entry names, count and total expanded size are revalidated after compression. Failure produces no final archive.

## Crash and resume use

Events are buffered only for the current invocation. Once a RunId exists, the diagnostic exporter can also reconstruct the durable operation state from the protected write-ahead journal without reading backup or quarantine contents.

After an abrupt process or machine failure, run a new read-only invocation with the exact RunId:

```powershell
.\Start-CTyunTrim.cmd -Mode Audit -RunId <RunId> -Diagnostic -Json
```

The exporter never guesses the newest RunId or scans unrelated run directories.

## Privacy and sharing

No diagnostic file is uploaded automatically. Review all four entries before attaching the ZIP to an issue. The sanitizer is a defense-in-depth boundary, not permission to share data you have not inspected.

The `.sha256` sidecar authenticates only the local ZIP bytes. It is not a digital signature and does not establish who created the bundle.
