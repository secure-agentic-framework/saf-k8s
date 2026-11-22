# SAF-K8S-0605-006 — Pod Security Admission for AI workload namespaces

```sh
python3 lab.py test SAF-K8S-0605-006 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 API first admits a synthetic Pod with a
Restricted-only deviation through server-side dry-run. The same request
receives the exact Pod Security Admission rejection after enforcement is
pinned to Restricted v1.36. A compatible comparison remains admissible in
the same namespace, and an independent unclassified namespace provides an
unaffected comparison.

The namespace admission policy begins in audit mode. Its real API metadata
audit event identifies a proposed AI namespace below Restricted. That
namespace then demonstrates native PSA audit and warning under Baseline
enforcement. The compatible comparison produces no PSA violation annotation.
The test then enables deny and audit on the namespace policy and verifies
protections on namespace creation, enforcement downgrade, and removal of
the AI classification label. A correctly labeled namespace and an ordinary
unclassified namespace still pass. All Pod requests are dry-runs.

Deployment follow-up covers enrollment and trust for the AI classification
label, actual namespace-creating operators, audit transport and alerting,
and approved exceptions.

- [Kubernetes v1.36 Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
