# SAF-K8S-0101-017 — Audit log age and count limits

```sh
python3 lab.py test SAF-K8S-0101-017
```

The disposable file-audit profiles use a 1 MiB rotation threshold and
synthetic backups. A harmless ConfigMap patch forces a backend write and
rotation. In one profile only the file just beyond the two-day bound
is removed. In the other, age pruning is disabled and the two-file cap
still removes newer files. Both profiles confirm the synthetic event
reaches the new active audit log. Only test outcomes enter the report.

File pruning bounds are local limits. A count cap can remove records before
the required minimum retention period. The collector, archive or SIEM must
independently preserve and expose records for the organization’s window.

- [Kubernetes v1.36 auditing and file rotation](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 API server audit flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes v1.36.1 audit source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/server/options/audit.go)


## Downstream retention comparison

The case copies only the selected Metadata audit event from the local API
server into a disposable downstream store. The retention comparison uses an
explicit clock and includes metadata fixtures immediately before, exactly at,
and immediately after a two-day cutoff. Only the expired fixture is removed.
The exact cutoff, recent fixtures, and real API audit event remain retrievable
after the policy commits its replacement store and the verifier reopens it.
The case retains counts and outcomes. Audit IDs and event records stay in the
temporary store.

The companion [PVC-backed audit webhook case](../SAF-K8S-1001-026/README.md)
verifies TLS ingestion and retained events after receiver replacement.
The cutoff above is the sample's policy. Verify the applicable downstream
store and retention rules separately.

## Adopter verification

1. Record the policy owner, evidence requirements, effective retention window
   and its time basis. Inventory capture, relay, storage, index and archive
   destinations with their applicable settings and responsible teams.
2. Trace an approved synthetic audit event by identifier from the API server
   to the intended retrieval interfaces. Verify retrieval after restart and
   near the end of the required retention window. Ensure a count/size cap,
   delayed ingestion or collector retry does not silently shorten the period.
3. Test boundary records and expiry behavior in an approved disposable
   environment. Verify any holds and exceptions before deletion, then retain
   the policy, expected and observed outcomes, timestamps and review owner.
4. For managed services, retain release-specific provider export and
   retention evidence alongside the observed customer-controlled settings.
   Mark uncovered paths or archive access conditions unverified.
