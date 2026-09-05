# Component boundaries

The default `MinimalInterop` profile encodes the component boundary established from one observed CTyun Windows image. Its normalized content hash is pinned in code. Every destructive match requires an exact object name and full canonical image path. Unknown versions fail closed.

Apply also authenticates the preserved core before making changes: four service ImagePaths, three driver ImagePaths, source ACLs, per-entry signature policies, and the observed `clipa` numeric file version `2.1.0.0` must match the versioned fingerprint. Every core entry except `BalloonService` requires a valid pre-cleanup Authenticode chain.

The observed `BalloonService` binary is signed by a self-issued Red Hat virtio-win development certificate that Windows does not trust. CTyunTrim does not add that certificate to a trust store. Instead, only this exact service is accepted when its canonical path, file SHA-256, embedded signer thumbprint, signer subject and signer issuer all match the immutable profile and the signature status is exactly `Valid` or the observed untrusted-root `UnknownError`. A hash, signer, path or status change fails closed.

The first run archives each core file's SHA-256 and signer identity in a hashed, ACL-protected baseline report. A Prepare-to-Apply resume must match those exact bytes and signer. For `AuthenticodeValidAtBaseline` entries, current validity remains mandatory until the protected journal contains a completed removal operation for an immutable known-certificate target. Only after that durable boundary may `UnknownError` or `NotTrusted` be accepted, and then only with exact baseline byte and signer continuity. A merely pending write-ahead record or an unknown certificate target cannot relax trust. `HashMismatch`, `NotSigned`, `NotSupported`, `Incompatible`, a missing signer or an unsafe ACL always fails.

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

## Loaded Cloudbase profile boundary

The observed image can run the exact scheduled `TaskAgentDetect.exe` under the `cloudbase-init` account, which loads its user Profile. Prepare may proceed only when this is the sole account-owned process and its owner SID, session, immutable task image path, signature, source ACL, reparse state and process start identity all pass validation. The account SID must also be bound to an exact Cloudbase service `StartName` or an exact scheduled-task `Principal`; a same-name local account is not ownership evidence. Prepare then revalidates at the mutation boundary, installs the self-repair guards before stopping the process, removes the exact tasks, and proves no process remains under that SID. It does not unload the hive or remove the account/Profile.

Apply never enters component or identity removal with a loaded Profile or mounted user hive. In 0.1.5, a same-RunId resume whose only preflight failure is this loaded state may first quiesce the exact stopped, automatic `cloudbase-init` service. Protected baseline ownership, the live service account SID, signature/source ACL, core continuity, a non-Special/non-current exact Profile and zero SID-owned processes must all match. The only system change in that invocation is disabling this service's startup, after its separate backup and write-ahead record. It immediately returns `PendingReboot`; it does not change the account, Profile, hive, tasks or other services.

The following invocation must observe a new boot and natural Profile/hive unload before normal removal can continue. A Profile still loaded after this transition remains a failure. `Special=true`, an unknown owner process, an alternate same-SID Profile path, a path or signer mismatch or an unsafe SID is never excused by this transition. The identity deletion path also requires no unrelated service/task references: it writes its journal, disables and verifies the exact account, rechecks owner processes immediately before Profile deletion, removes the exact unloaded Profile, and only then deletes the disabled account.
