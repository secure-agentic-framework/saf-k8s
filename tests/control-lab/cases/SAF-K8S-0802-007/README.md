# SAF-K8S-0802-007 Device-plugin deployment and telemetry reconciliation

The case confirms an ordinary pinned DaemonSet is ready and reconciles inert report records with its real Kubernetes ownership and node inventory. It reports missing, mismatched, duplicate and inconsistent records separately. The telemetry fields are synthetic. No GPU, device plugin, socket or registration request is used.

## Adopter verification

1. Inventory device plugin DaemonSets, node pools, target identities, sockets, advertised resources and the source of each health signal. Verify approved deployments, host access and placement rules.
2. On representative nodes, compare the real plugin registration, device health and Kubernetes advertised resources. Exercise an approved health or inventory failure and verify attributable detection and escalation with the correct node and identity.
3. Retain plugin and runtime versions, source integrity, registration, expected and observed inventory and alert records. Repeat after rollout, node replacement or device-profile changes.
