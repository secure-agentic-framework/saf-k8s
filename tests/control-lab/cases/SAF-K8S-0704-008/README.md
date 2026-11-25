# Verify explicit cloud-to-Kubernetes event correlation on Kind

```sh
python3 lab.py test SAF-K8S-0704-008 --docker-context desktop-linux
```

The case generates two actual metadata-only Kubernetes audit events for a
public ConfigMap. It correlates those events with synthetic cloud rows using
an explicit fixture mapping. A time-only comparison offers false matches;
validated links preserve matched, ambiguous and unmatched outcomes.

No real cloud logs are used. Deployed source coverage, identity linkage,
audit retention and evidence of causation require separate verification.

## Verify an adopting implementation

1. Identify actual provider audit sources and Kubernetes audit sources, coverage gaps, event IDs, clock sources and retention.
2. Validate the deployed identity join keys from authoritative identity records; do not join on timestamp alone.
3. Confirm a benign approved test action is linked across both sources, then check unresolved/ambiguous cases remain unresolved rather than attributed.
4. Preserve source event IDs, join rule/version, timestamps, retention and evidence of an actual workload effect only when separately established.

[Kubernetes v1.36 audit backends](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [Amazon EKS control plane log delivery](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html) and [Amazon CloudWatch log groups and retention](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html).
