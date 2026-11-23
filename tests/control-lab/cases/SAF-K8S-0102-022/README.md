# SAF-K8S-0102-022 Backup repository least-privilege access

A disposable Kind Pod tests Linux filesystem authorization with three distinct non-root identities and a shared repository fixture. It verifies baseline access, denied unrelated access, read-only restore access and the intended writer. The file holds a public marker. This checks a native filesystem boundary under Kubernetes. Actual backup copies, remote storage policy, host and cluster administrators, key custody and exceptional access still require deployment evidence.
