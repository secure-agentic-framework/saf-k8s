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

Production debug role reviews, audit collection, runtime variations
and namespace coverage require deployed evidence.

- [Kubernetes ephemeral containers](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Kubernetes Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
