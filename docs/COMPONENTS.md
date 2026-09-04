# Component boundaries

The default `MinimalInterop` profile encodes the component boundary established from one observed CTyun Windows image. Its normalized content hash is pinned in code. Every destructive match requires an exact object name and full canonical image path. Unknown versions fail closed.

Apply also authenticates the preserved core before making changes: four service ImagePaths, three driver ImagePaths, valid pre-cleanup Authenticode signatures, and the observed `clipa` numeric file version `2.1.0.0` must match the versioned fingerprint.
The first run archives each core file's SHA-256 in a hashed, ACL-protected baseline report. A Prepare-to-Apply resume must match those exact bytes, even if the current signature still validates.

## Preserved core

| Object | Reason |
|---|---|
| `clink_service` and `clink_agent*` | Official remote session and data plane |
| `clipa` | CloudLaptop infrastructure agent retained by the verified baseline |
| `cloudshare_service` and `cloudshare.exe` | Ordinary file and clipboard interoperability |
| `dokan2.dll` | Observed as a module loaded by `cloudshare.exe` |
| `BalloonService` | Virtual-machine memory cooperation |
| `CLINKAC` and `ClinkMouseFilter` | Loaded core drivers |
| `WinDivertProxy-Port.exe`, `WinDivertScanner`, `WinDivert64.sys` | Dynamically loaded Clink network/port path |
| `clink_dect.exe` | Small on-demand/periodic Clink helper |
| VirtIO, display and audio drivers | Underlying virtual hardware and media support |

Preservation is functional, not a statement of trust.

## Removed layers

- AI Assistant, AppMarket/AppManager and DesktopMaster.
- Cloud printer, cloud disk and cloud sync.
- FileCrypto: `clinkte_service`, `CLINKTE`, `CLINKTELOG`, `CLINKFS`, `cloudshareAC`.
- `cloudbase-init`, its account, Profile, scripts, configuration and program files.
- Mirror/Launch/CloudUpdate and the repair/update scheduled tasks.
- FirewallNetwork, CertUpdate and unused monitoring helpers.
- Screen recording, drawing, CAD and classroom integrations.
- The separate network-scanner `WinDivertProxy.exe` component.
- Six exact vendor certificates and dead inbound-Allow CloudUpdate JRE firewall rules observed in the reference image. Block rules are preserved.

## Critical distinctions

### cloudshare versus FileCrypto

`cloudshare_service` is required for ordinary file transfer. `clinkte_service` and the CLINKTE filter-driver family were an optional FileCrypto/control layer in the observed image. A `.lnk` shortcut transfer bug previously confused the diagnosis; test normal files separately.

### Dokan service versus DLL

The `dokan2` driver service and `dokan2.sys` are removal targets. `dokan2.dll` is protected because `cloudshare.exe` loaded it in the verified baseline.

### WinDivert components

`WinDivertProxy.exe` is the removable network-scanner proxy. `WinDivertProxy-Port.exe` and its `WinDivertScanner`/`WinDivert64.sys` path are protected. Wildcard matching is forbidden.

### FileCrypt versus FileCrypto

`FileCrypt.sys` is a Microsoft Windows critical filesystem filter. It is unrelated to the CTyun `FileCrypto` directory and is never a removal target.

## Known self-repair chain

```text
Cloudbase LocalScripts/ecloud_launch_external.py
                 └─ TaskAgentDetect.exe

ecloud_update_* scheduled tasks
                 └─ TaskAgentDetect / TaskLaunch
                    └─ detect missing optional packages
                       └─ start Launch
                          └─ repair\ecloud_Launch_FullSetup_103010306.exe
                             ├─ rebuild Mirror\Launch
                             ├─ recreate scheduled tasks
                             └─ ExternalLaunch.exe
                                ├─ CloudUpdate.exe
                                ├─ local-policy configuration
                                ├─ optional package reinstall
                                └─ Group Policy refresh
```

The reference system's file audit attributed 17 restored `Mirror\Launch` files to the repair installer. Process and Group Policy logs attributed machine/user policy refresh calls to `clink_agent_data.exe` and `ExternalLaunch.exe` running as SYSTEM.

Because `clink_agent_data.exe` is preserved, CTyunTrim retains six exact, marked IFEO execution guards. These are intentional persistent changes and can interfere with future vendor upgrades.
