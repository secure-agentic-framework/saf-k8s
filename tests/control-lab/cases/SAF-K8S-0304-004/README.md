# SAF-K8S-0304-004 ephemeral container security

Run `python3 tests/control-lab/lab.py test SAF-K8S-0304-004 --docker-context desktop-linux`
from the framework root.

The case uses a disposable Kind v1.36.1 cluster. It checks restricted Pod
Security Admission on a normal Pod, and both RBAC and admission on the
named Pod's ephemeral-container subresource. All noncompliant requests
use dry run. A permitted ephemeral marker actually runs non-root with
a seccomp filter. Readback verifies that the original Pod and its init
container stay in place, and the ordinary Pod route rejects an ephemeral
addition.

The RBAC fixture grants the approved debugger `update` on one Pod's
`pods/ephemeralcontainers` subresource. The unapproved identity has named
read access and is denied both the direct update and server-dry-run patch.
That read permission lets the patch reach the write authorization check.

## Verify your implementation

1. Confirm the namespaces and runtime classes that allow debugging, their
   effective Pod Security Admission levels and versions, and their exemptions.
   Inventory approved operators, their identity bindings, and the actual
   subresource verbs used by each debug client.
2. In a disposable namespace, verify the same approved Pod accepts a compliant
   request from the scoped debugger. Verify the unapproved identity is denied
   when using the relevant update and patch verbs. Use server dry runs for
   requests with disallowed security settings.
3. For each additional workload-specific security setting, verify that admission
   rules explicitly include `pods/ephemeralcontainers`. Verify the running
   approved debug process has the expected identity and profile.
4. Confirm API audit records for both permitted and denied operations, including
   the actor, verb, resource, subresource, namespace and response decision.
   Check downstream severity and alert delivery separately. The current case
   exercises native Metadata audit capture separately from downstream alerts.

The supplemental admission policy checks an ephemeral container's read-only root
setting for the owned Pod. Restricted PSA alone admits the safe dry-run
without that setting. The additional policy denies it, and the read-only marker
runs successfully. An API server policy records only Metadata for the fixture
namespace's ephemeral-container update and patch operations. The case matches
the exact target, actor, verb, HTTP response and dry-run status, and retains
the bounded projection in `ephemeral-debug-audit.json`. It checks that object
payloads are absent.

- [Kubernetes ephemeral containers](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Kubernetes Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
