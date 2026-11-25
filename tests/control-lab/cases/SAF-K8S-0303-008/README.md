# SAF-K8S-0303-008 AppArmor approval and exception admission

Run `python3 lab.py test SAF-K8S-0303-008` with the catalog revision recorded in
the verified result. One namespace-scoped ValidatingAdmissionPolicy checks
explicit named-profile approval, Pod defaults and overrides across regular,
init and ephemeral containers. The admission matrix initially exercises unconfined requests with server
dry-run. A separate inert, scheduling-gated Pod is the target of
`pods/ephemeralcontainers` dry-run updates.

A separate namespace holds the exception ConfigMap. The fixture tests an
active approval for one direct Pod name, namespace and authenticated requester,
then exercises missing safeguards, incorrect scopes, revoked grants and
validity windows. The two synthetic submitters can create Pods in the selected
namespace but cannot edit the named approval. The example requires effective
`RuntimeDefault` seccomp and disables token automount for the exception.
Kubernetes evaluates a fixed time supplied by the fixture controller.
If the ConfigMap is absent, the matched admission policy fails closed.
The running withdrawal comparison below covers one owned inert workload.

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

## Running exception withdrawal

The reference creates a single inert workload with its exact active exception,
then revokes the grant. The API refuses an update to the same object while that
Pod remains running. An independent, precisely named remediator removes the
observed Pod with UID and resource-version preconditions. The original submitter
and unrelated target comparisons fail authorization. The now-revoked request
cannot recreate the workload, and an unrelated Pod remains available.

Admission and cleanup evidence tracks this fixture's declared profile and
workload lifecycle. Direct evidence of loaded AppArmor behavior comes from the
separate [profile delivery and enforcement case](../SAF-K8S-0303-007/README.md).
In a deployment, verify the profile for each supported node and the approved
response to withdrawal or expiry for both new and existing workloads. Record
approval, exception scope, observed decision and remediation timing.
