# SAF-K8S-0403-029 — Admission policy for Secret environment references

```sh
python3 lab.py test SAF-K8S-0403-029 --docker-context desktop-linux
```

On a disposable Kubernetes v1.36.1 cluster, the same fixture requests are
accepted before policy installation and denied afterward. The namespace-scoped
ValidatingAdmissionPolicy checks direct `env[].valueFrom.secretKeyRef` and
`envFrom[].secretRef` for regular and init containers. It also checks both
forms through `pods/ephemeralcontainers` UPDATE and a Deployment template at
admission. Denial receipts require the policy's unique error message.

The test checks the current policy generation and waits for a specific
dry-run denial before issuing the real requests. An enrolled Pod using a
ConfigMap environment source and an empty Secret volume is accepted. The
unlabeled comparison namespace accepts the original shape. The test uses
empty fixtures and retains no credentials.

Deployed policy bindings and reporting, exception governance, namespace
enrollment, and additional controller templates require separate evidence.

[Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) ·
[Kubernetes v1.36 ephemeral containers](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
