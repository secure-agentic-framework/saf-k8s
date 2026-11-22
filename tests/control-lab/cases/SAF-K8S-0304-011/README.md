# SAF-K8S-0304-011 — Namespace LimitRange and ResourceQuota enforcement

The case exercises CPU, memory, and local ephemeral-storage admission in one
disposable Kubernetes v1.36.1 namespace. With neither policy present, the API
admits an omitted-resource Pod and the six individual or aggregate overage
candidates. The same omitted-resource specification picks up the configured
requests and limits once the LimitRange is installed. Each of the three
per-container overage probes is then rejected with the resource-specific
maximum diagnostic.

Two small Pods consume 50 millicores, 24 MiB memory, and 24 MiB ephemeral
storage in quota accounting. Three independent server dry-runs exceed one
aggregate request cap each. The API rejects each and names the matching
`requests.<resource>` key. A final list verifies the rejected candidates never
persisted. The test measures declared resource admission and quota accounting.
Accelerators, hardware-backed allocatable capacity, production namespace
coverage, policy governance, and utilization monitoring require separate
evidence.

From the repository root, run the case by ID.

```sh
python3 lab.py test SAF-K8S-0304-011 --docker-context desktop-linux
```

In the framework repository use `python3 tests/control-lab/lab.py` with the same
arguments. The runner prints the receipt and cluster cleanup outcome.

- [Pinned SAF-K8S control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0304-011.md)
- [Kubernetes v1.36 Limit Ranges](https://v1-36.docs.kubernetes.io/docs/concepts/policy/limit-range/)
- [Kubernetes v1.36 Resource Quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)
