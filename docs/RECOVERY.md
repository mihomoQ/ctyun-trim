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

Automated Restore is disabled in 0.1.1. A safe recovery engine must compare every current object with the post-Apply state and restore exact values without overwriting newer tasks, services or policy. Until that is implemented and tested, CTyunTrim fails closed.

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

There is no automated execution-guard, task, service, certificate, account or LocalGPO restore command in 0.1.1.
