# Recovery

## Before Apply

Create and test a provider-side VM snapshot. Back up important data outside the cloud desktop and confirm that the recovery console does not depend on the Windows guest components being removed.

## Run backup

Apply creates:

```text
%ProgramData%\CTyunTrim\Runs\<RunId>\
  manifest.psd1
  state.clixml
  registry\
  tasks\
  certificates\
  firewall\
  policy\
  tools\
  quarantine\
  reports\
```

Files are moved to the same-volume quarantine when possible. Registry/service definitions, task XML, certificates and LocalGPO files are backed up before modification.

When Apply reports `PendingReboot`, reboot and resume with the same `RunId`. Starting an unrelated new Apply would split the restoration history across multiple runs.

Pass that same RunId to `Verify`; it binds the final account check to the Cloudbase SID captured before removal, so an account rename cannot hide a surviving identity.

## Automated Restore status

Automated Restore is disabled in 0.1.5. A safe recovery engine must compare every current object with the post-Apply state and restore exact values without overwriting newer tasks, services or policy. Until that is implemented and tested, CTyunTrim fails closed.

## Cloudbase service quiesce records

The 0.1.5 resume-only `ServiceQuiesce` stage records the exact Cloudbase service's
original automatic startup configuration in a separate registry backup before
disabling startup. It does not stop or delete the service and does not modify the
account, Profile, user hive or tasks. A successful quiesce returns `PendingReboot`;
continue with the same RunId and version after restarting.

This stage is reversible through evidence-led manual restoration of that exact
service's startup type while its identity is unchanged. It is not an automatic
Restore command. Its backup must remain distinct from a later service-deletion
backup, which will capture the disabled configuration. Restoring only that later
backup would leave startup disabled; restoring the original automatic startup is
a separate reviewed action that can re-enable Cloudbase management behavior.

Recreated scheduled tasks now receive unique XML backup filenames, retaining the
earlier Prepare snapshot and its hash. Legacy 0.1.4 pending task backups remain
supported; no earlier backup is overwritten during a repeat removal.

## Recovery limitations

Scripted Restore is deliberately described as partial:

- it cannot reconstruct the original `cloudbase-init` account password;
- a deleted Profile cannot be perfectly recreated;
- firewall metadata is recorded but rules are not automatically rebuilt;
- importing service registry keys does not restore third-party installer state;
- restoring an old `Registry.pol` can overwrite LocalGPO changes made after Apply;
- removed certificate private keys were never backed up; the observed certificates did not include private keys.

Use the VM snapshot for a complete rollback.

## Lost official connectivity

Do not continue deleting. Use the provider recovery console and either:

1. roll back the tested snapshot; or
2. perform evidence-led manual recovery from one exact RunId directory, then reboot and retest.

There is no automated execution-guard, task, service, certificate, account or LocalGPO restore command in 0.1.5.
