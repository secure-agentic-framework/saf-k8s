# SAF-K8S-0801-004 local demonstration

The workload policy checks exact synthetic vGPU profile and host/guest stack identifiers against an operator-owned review record. It demonstrates real admission enforcement and a CPU fixture Pod becoming Ready. There is no vGPU, hypervisor inventory, driver, licensing, or physical isolation observation.

## Adopter verification

1. Inventory host virtualization platform, physical accelerator, vendor vGPU type, guest image and drivers. Match the exact versions, profile and license to provider or vendor support evidence.
2. Verify confidentiality and sharing properties applicable to the selected hypervisor and vGPU profile. Preserve the source and version for each verified property.
3. Use a sanctioned test Guest and Kubernetes workload to observe profile assignment and an allowed representative operation. Verify an unapproved or superseded stack receives the intended admission refusal.
4. Retain the effective platform record, approving role, actual device assignment, policy decisions and evidence gaps. Revalidate after the platform or profiles change.
