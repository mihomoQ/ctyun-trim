# Reference baseline

This file records the observations used for the first manifest. It is evidence for one image, not a universal CTyun specification.

## Source image

The project is based on CTyun's preinstalled **Windows 11 Enterprise LTSC, 64-bit, Chinese** image:

`Windows-11-企业版-LTSC-x64-Chinese-v26.0316`

This is the vendor image identifier, not a Windows build number. Testing also covered the image after applying ReviOS. Compatibility still depends on the supported live Windows builds and the exact component fingerprint; the image name alone is not sufficient.

## Tested final runtime

```text
BalloonService      Running / Automatic
clink_service       Running / Automatic
clipa               Running / Automatic
cloudshare_service  Running / Automatic
```

Observed Balloon service binary identity:

```text
Path                C:\Program Files (x86)\ctyun\clink\drivers\Balloon\blnsvr.exe
SHA-256             1B821F556FFC8F998196CDBFEE6D84846600D39EB1B584D182BFCC5AB6DFCD4E
Signer thumbprint   301C73596BAC4FE8EE33487687BD75FCC307FFC6
Signer              CN=Red Hat Inc., OU=Dev, O=virtio-win
Signature status    UnknownError (self-issued root is not trusted by Windows)
```

This tuple is pinned only to recognize the preserved binary. The signer certificate is not installed into a Windows trust store, and a future VirtIO binary requires an explicit profile update.

The versioned destructive fingerprint records `clipa.win.exe` numeric file version `2.1.0.0`. Core service and driver registrations must also resolve to the exact paths encoded in `config/CTyunTrim.psd1`; names alone are insufficient.

Observed process tree:

```text
clink_service.exe
└─ clink_agent.exe
   ├─ clink_agent_data.exe
   │  ├─ clink_cb_helper.exe
   │  └─ WinDivertProxy-Port.exe
   ├─ clink_agent_device.exe
   └─ clink_agent_display.exe

cloudshare_service.exe
└─ cloudshare.exe
```

Preserved vendor drivers:

```text
CLINKAC             Running / Manual
ClinkMouseFilter    Running / Manual
WinDivertScanner    Running / Disabled (dynamically loaded)
```

Observed local listeners:

```text
clink_agent_data  127.0.0.1:5011
clink_agent_data  127.0.0.1:6001
clink_agent_data  127.0.0.1:9002
clink_agent_data  127.0.0.1:49002
cloudshare        127.0.0.1:49201
```

The only captured established vendor TCP connection was the local `cloudshare` to `clink_agent_data` loopback pair. No vendor UDP endpoint was present in that point-in-time check.

## Final footprint

```text
clink        162.85 MB
cloudshare    27.82 MB
clipa          4.00 MB
dokan          0.52 MB
```

The initial directory sample totalled approximately 1.8 GB before optional components were removed.

## Self-repair evidence

- File audit event 4663 attributed 17 restored `Mirror\Launch` files to `C:\Users\Public\Documents\mirror\ClinkAgent\repair\ecloud_Launch_FullSetup_103010306.exe`.
- `TaskAgentDetect.log` reported failed checks for FileCrypto, CloudSync and CloudPrinterClient, followed by `start Launch`.
- the Launch installer log recorded creation of `ecloud_update_agent_detect` and `ecloud_update_task_launch`.
- Group Policy event 5321 attributed machine and user refresh requests to `clink_agent_data.exe` and `ExternalLaunch.exe` running as SYSTEM.
- `CloudUpdate.exe` launched a silent CloudPrinter installer in the captured boot.

## Exact fake-WSUS values

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
  WUServer                  = https://127.0.0.1
  WUStatusServer            = https://127.0.0.1
  UpdateServiceUrlAlternate = https://127.0.0.1

HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
  UseWUServer               = 1
  NoAutoUpdate              = 1
```

After cleanup the reference system retained `ExcludeWUDriversInQualityUpdate=1` and `UpdateNotificationLevel=2`.

## Exact certificates from the reference image

```text
LocalMachine\Root
458248412225BE670E2FE6025A45CD5A896BC81B
422B95B06119B2DA4CFEDBAA3FFFD3D3A3A92E6B

LocalMachine\TrustedPublisher
F8D045831F0AE192C9BFAF80BBD669040308C904
B8339737AFD37AB0F9AAB2FE2BC77F0D28C3D9EA
A7E9CECBDB719570BEFB5AF6D32948280738E598
4DA2321D9673218DFFDF44558873CC8D7762A37D
```

New image versions may use different certificates. Unknown candidates are reported, not removed.

## Known file-transfer edge case

Ordinary files worked after FileCrypto and the unused filter drivers were removed. Copying a Windows `.lnk` shortcut could create a zero-byte file and disrupt the cloudshare channel. Use TXT, ZIP, image and binary files for functional verification and treat `.lnk` separately.
