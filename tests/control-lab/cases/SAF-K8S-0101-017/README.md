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
