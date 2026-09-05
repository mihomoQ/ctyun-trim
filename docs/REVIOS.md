# ReviOS coexistence

CTyunTrim and ReviOS solve different problems:

- ReviOS modifies Windows components and preferences.
- CTyunTrim handles the CTyun-specific guest management and optional feature layers.

Keep them separate so that an update or failure can be attributed correctly.

If ReviOS is already applied and the original CTyun components remain verifiable, use the single-command quick start in [README](../README.en.md#quick-start). If you need to prepare the vendor image before applying ReviOS, follow the staged order below and keep the same RunId. Detailed commands are available in the [usage manual (Chinese)](USAGE.md#与-revios-分阶段使用).

Recommended order:

```text
Snapshot and external data backup
→ CTyunTrim Audit and Plan
→ neutralize the fake-WSUS policy and update Windows
→ apply the official ReviOS Playbook
→ reboot
→ CTyunTrim Apply
→ reboot
→ CTyunTrim Verify and manual interoperability tests
```

Do not fork and merge the CTyun actions into the official ReviOS Playbook. A new ReviOS release can then be applied independently, followed by CTyunTrim Audit/Verify to detect any changed state.

Compatibility means only that a specific combination was tested. It does not imply endorsement by either project.
