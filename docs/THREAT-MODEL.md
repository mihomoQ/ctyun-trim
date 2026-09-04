# Threat model

## In scope

CTyunTrim reduces known Windows guest-side management surface:

- services and processes;
- kernel/filter driver registrations;
- scheduled tasks and Run entries;
- known repair/update payloads;
- Cloudbase initialization and its local account;
- LocalGPO policy refill;
- exact known certificates and dead firewall rules;
- common WMI/startup persistence evidence reported by Audit.

## Out of scope

The tool cannot inspect or constrain the provider's:

- hypervisor and host memory access;
- virtual disk, snapshots, images or backup systems;
- virtual NIC, switching, routing and traffic observation;
- boot media, firmware or console injection;
- account/control plane and server-side remote protocol;
- future software delivered through components intentionally preserved for interoperability.

The `MinimalInterop` profile deliberately retains SYSTEM services and kernel drivers. It therefore reduces, but does not eliminate, vendor control or attack surface.

Passing `Verify` means that implemented checks matched at one point in time. It is not proof of confidentiality from the cloud provider, absence of malicious behavior, or absence of unobserved persistence.

## Adversarial inputs

The implementation treats service paths, task actions, manifests and filesystem objects as potentially unsafe:

- no wildcard removal;
- immutable reference-manifest hash and fixed root anchors;
- exact service, task path, task action and image identities;
- versioned core ImagePath/signature/version fingerprinting;
- protected-path ancestor checks;
- reparse-point rejection;
- an immutable official LGPO v3.0 binary hash, parent-ACL checks and Microsoft signature validation before invoking a protected staged copy;
- exact certificate thumbprints plus subject validation;
- refusal to overwrite existing unknown IFEO Debuggers.

## Appropriate use

Use only on systems you own or are explicitly authorized to administer. Do not use this project to scan, interfere with or bypass the provider's infrastructure, authentication, licensing or access controls.
