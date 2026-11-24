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
persisted. A separate namespace exercises extended-resource admission and
quota using capacity advertised on the disposable node. It observes the
maximum becoming an effective default, a smaller explicit default, a real
scheduled Pod charged against the quota, and readmission after the usage is
released. Hardware-backed discovery and allocation, namespace coverage, and
usage monitoring belong to the adopter's environment.

From the SAF-K8S repository root, run the case by ID.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0304-011 --docker-context desktop-linux
```

From the separate Control Lab root, use `python3 lab.py` with the same
arguments. The runner prints the receipt and cluster cleanup outcome.

- [SAF-K8S control](../../../../markdown/controls/SAF-K8S-0304-011.md)
- [Kubernetes v1.36 Limit Ranges](https://v1-36.docs.kubernetes.io/docs/concepts/policy/limit-range/)
- [Kubernetes v1.36 Resource Quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)

## Extended-resource adoption check

Check each compatible accelerator resource name on the eligible nodes and in
the consuming workload. Review the effective Container LimitRange object after
API defaulting. An extended-resource maximum can also supply the default limit
and request. For resources that cannot be overcommitted, keep the effective
request and limit equal when both are supplied. Inspect the admitted workload
to confirm a CPU-only container does not receive an unintended allocation.
Use `ResourceQuota.spec.hard` with `requests.<extended-resource>` and compare it
with `status.used`. ResourceQuota alone leaves an omitted device request
absent. Kubernetes uses distinct quota keys for DRA ResourceClaims.

In an authorized context and namespace, collect the named objects.

```sh
kubectl --context "$SAF_CONTEXT" -n "$SAF_NAMESPACE" get limitrange "$SAF_LIMITRANGE" -o json
kubectl --context "$SAF_CONTEXT" -n "$SAF_NAMESPACE" get resourcequota "$SAF_QUOTA" -o json
```

For behavior, use an approved disposable or representative environment. Compare
an omitted request, a pair above the per-container maximum, an aggregate overage
within that maximum, and a compliant request. Retain the admitted resource
values or exact denial, observed quota usage, and the policy revision. Evaluate
device discovery, health, allocation and execution with the applicable device
stack. For namespace coverage, reconcile owned namespaces and their approved
policies, exceptions, quota monitoring and onboarding checks.

- [Kubernetes v1.36.1 LimitRange defaulting](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/apis/core/v1/defaults.go#L346-L373)
- [Kubernetes v1.36 extended-resource quotas](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#quota-for-extended-resources)
