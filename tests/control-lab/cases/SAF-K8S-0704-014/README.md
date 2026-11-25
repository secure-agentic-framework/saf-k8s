# SAF-K8S-0704-014 Audit retention and retrieval

This case configures the actual Kubernetes file audit backend in a disposable Kind cluster with a 1 MiB rotation threshold and one rotated backup. The policy records only patches to the fixture ConfigMap at RequestResponse level and the patches contain exclusively public test markers and padding. Assertions verify the first record, the eventual backup bound and removal of the oldest record, and continued retrieval from the active log. Evidence contains only observed flags, counts and marker-presence results.

This demonstrates size-triggered log rotation and immediate local retrieval. Managed-provider source coverage, time-based retention, authorized query and archive restore need separately observed destination evidence.

## Verify an adopting implementation

1. For every audit category and destination, capture the effective retention/rotation policy and the organization’s required retention period.
2. Query one benign event by its audit ID at the destination using an approved read-only principal; verify timestamp, source and event payload policy.
3. Exercise archived retrieval and authorized restoration under an approved maintenance procedure; capture observed search/retrieval times and integrity checks.
4. Compare effective retention against policy, and verify expiry/deletion and legal-hold exceptions without exporting sensitive event contents.

[Kubernetes v1.36 audit backends](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [Amazon EKS control plane log delivery](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html) and [Amazon CloudWatch log groups and retention](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html).
