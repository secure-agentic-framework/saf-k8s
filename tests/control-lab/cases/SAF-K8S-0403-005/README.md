# SAF-K8S-0403-005 — Secret masking in deployment diffs

This subcase verifies a manifest-diff output control using kubectl v1.36.1 and
the pinned kind API server. It changes two public synthetic markers in a
case-owned Secret fixture and compares default masking with an explicitly
masking-disabled run. The default and explicitly masking-enabled runs retain
the marker change indicators and suppress both encoded values. The test records
booleans and checks that the stored object revision remains unchanged.

The case clears the external diff override and disables local kuberc defaults.
It keeps all object bodies and diff output out of the evidence files. An actual
pipeline needs equivalent control over client options, output paths, and log
retention. Training logs, checkpoints, images, and orchestrator metadata have
separate evidence requirements in Beads.

- [Kubernetes v1.36 kubectl diff](https://v1-36.docs.kubernetes.io/docs/reference/kubectl/generated/kubectl_diff/)
- [Kubernetes v1.36 changelog](https://github.com/kubernetes/kubernetes/blob/v1.36.0/CHANGELOG/CHANGELOG-1.36.md)
