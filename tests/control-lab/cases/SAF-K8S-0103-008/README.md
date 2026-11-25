# SAF-K8S-0103-008 Controller execution and identity boundaries

A standalone fixture reconciler uses its own workload identity and updates only its public marker after permissions are narrowed. The native kube-controller-manager keeps its lease and reconciles a new Deployment after the fixture workload exits. The fixture does not use a cloud provider controller, cloud IAM or any external service. Verify deployed provider controller ownership, identity, migration and failure dependencies separately.

## Adopter verification

1. Identify the provider and exact Kubernetes and controller versions.
   Confirm whether an external controller is required, managed by the
   provider, self-managed, or inapplicable to the deployment.
2. Map each enabled cloud operation to its owning component. Verify the
   effective controller identity and both Kubernetes and provider grants.
   Document which identity owns node, Service, routing, and storage
   workflows and any remaining shared or transitional responsibility.
3. In a provider-supported rehearsal, verify expected reconciliation and
   failure behavior for each governed dependency. Collect controller
   observations, approved provider events, authorization decisions and
   the corresponding recovery evidence.
4. Before ownership changes, review migration ordering and continuity
   requirements. Record reviewed overlaps, exceptions, provider-owned
   visibility limits and the owner of any outstanding verification.

- [Kubernetes v1.36 Cloud Controller Manager](https://v1-36.docs.kubernetes.io/docs/concepts/architecture/cloud-controller/)
- [Kubernetes v1.36 Cloud Controller Manager Administration](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/)
