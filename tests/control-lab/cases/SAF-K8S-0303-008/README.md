# SAF-K8S-0303-008 AppArmor approval and exception admission

Run `python3 lab.py test SAF-K8S-0303-008` with the catalog revision recorded in
the verified result. One namespace-scoped ValidatingAdmissionPolicy checks
explicit named-profile approval, Pod defaults and overrides across regular,
init and ephemeral containers. API requests for an unconfined Pod use server
dry-run. An actual Pod serves as the inert, scheduling-gated target of
`pods/ephemeralcontainers` dry-run updates.

A separate namespace holds the exception ConfigMap. The fixture tests an
active approval for one direct Pod name, namespace and authenticated requester,
then exercises missing safeguards, incorrect scopes, revoked grants and
validity windows. The two synthetic submitters can create Pods in the selected
namespace but cannot edit the named approval. The example requires effective
`RuntimeDefault` seccomp and disables token automount for the exception.
Kubernetes evaluates a fixed time supplied by the fixture controller.
If the ConfigMap is absent, the matched admission policy fails closed.
No unconfined workload is created or started by this case.

## Adopter checks

Inventory protected workload classes and verify their nodes, runtime support,
loaded approved profile revisions and effective confinement on running Pods.
Exercise harmless allowed and denied behavior as separate runtime probes.
Test all container lists and the ephemeral-container subresource. For controller
workloads, bind approved exceptions to trusted workload ownership and requester
identity. Inspect approval ownership and audit records, exercise denied
alteration, expiration and revocation against your trusted time policy, and
verify any controller action required for existing Pods. Verify that your
compensating controls are present at admission and enforced in the runtime.

- [Kubernetes AppArmor tutorial](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
- [Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes seccomp tutorial](https://v1-36.docs.kubernetes.io/docs/tutorials/security/seccomp/)
