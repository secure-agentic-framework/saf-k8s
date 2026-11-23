# SAF-K8S-0201-009 Effective kubelet systemd hardening

In disposable Kind, apply a kubelet-only drop-in with no new privileges, a private temporary mount namespace and a reduced capability bound. Verify the running kubelet's kernel-exposed state and a fresh workload that reads its own ConfigMap. Actual production node capabilities, path rules and supported runtime dependencies require environment-specific verification.
