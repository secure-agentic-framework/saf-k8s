# SAF-K8S-0802-001 Minimized driver rollout example

This case uses an actual Kubernetes DaemonSet to demonstrate version evidence, a controlled rollout, a readiness failure and recovery to the prior approved release. It observes the live process marker as well as Pod readiness. The release markers are synthetic. No vendor driver, kernel, GPU, vulnerability, or compatibility setting is exercised.

## Adopter verification

1. Inventory deployed node, GPU, kernel, runtime and driver versions. Trace each approved combination to tested vendor compatibility, security advisories and signed provenance.
2. On an owned canary node, record the installed module and userspace versions, driver health, allocatable device and approved workload smoke before and after the change.
3. Exercise an approved rollback and verify the original version, device allocation, workload continuity and relevant alerting. Include support-window exceptions and rollout ownership.
