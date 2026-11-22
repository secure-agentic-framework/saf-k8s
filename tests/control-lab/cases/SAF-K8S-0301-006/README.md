# SAF-K8S-0301-006 — Narrow PSA exceptions

```sh
python3 lab.py test SAF-K8S-0301-006 --docker-context desktop-linux
```

A local Kubernetes 1.36.1 API server uses named namespace, RuntimeClass
and requester exemptions. Ordinary Restricted admission rejects the
harmless missing-settings fixture. The native exemption admits the
designated fixture, and a separate admission policy denies near-miss names,
labels and ServiceAccounts while preserving the exact allowed declaration.
An unexempt RuntimeClass stays subject to Restricted PSA.

Two Pods use their own projected identities to submit exactly the same
harmless server dry-run. The configured requester receives the exemption.
The ordinary requester receives the Restricted denial even though the
submitted Pod names the exempt requester in its serviceAccountName. The
probe uses ordinary authentication over TLS.

The API audit backend retains the request and response for the approved
workload dry-run. Creating an empty Secret in that same namespace generates
a Metadata event with neither body.

Verify deployed exception approval, controller identities, label and
ServiceAccount ownership, actual infrastructure workloads and their
compensating controls separately.

[Kubernetes Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/) ·
[Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
