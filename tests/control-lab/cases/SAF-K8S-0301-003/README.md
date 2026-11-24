# SAF-K8S-0301-003 Stage Pod Security Admission before enforcement

This demonstration uses a modern Kind API server where PodSecurityPolicy is
absent. A synthetic legacy declaration identifies a read-only root filesystem
requirement. The test exercises separate application and infrastructure
namespace phases with benign Pods and server dry-runs. It captures audit and
warn behavior before enforcement, then independently verifies that a scoped
admission rule preserves the legacy filesystem requirement. Rolling back the
infrastructure namespace leaves that rule and the application policy in force.

```sh
python3 lab.py test SAF-K8S-0301-003 --docker-context desktop-linux
```

## Verify a real migration

1. Before upgrading a legacy cluster, capture API version, active PSP plugin,
   PSP definitions and binding or use permissions. Identify policies actually
   chosen for existing workload Pods and controllers. Include governed
   application and infrastructure namespaces, owners and special cases.
2. Compare each effective PSP field and mutation/default with the chosen pinned
   PSS profile. For each gap, record the approved replacement or explicitly
   update workload templates. Verify the replacement and both allowed and
   denied requests before retiring any original guard.
3. Roll out audit and warn first in each planned namespace. Review warnings
   and attributed audit evidence, then promote one namespace group at a time
   and confirm newly created and replacement Pods are healthy. Keep safe
   rollback criteria and retained gap coverage during each transition.
4. Verify the provider or version-specific upgrade and PSP removal boundary.
   Record the exact old and new state, admission results, workload health,
   exceptions and approvals. Preserve independent evidence for delegated
   providers and controls with no PSS equivalent.

The test verifies a phased modern target and one legacy constraint. Legacy
API execution or in-place cluster upgrade history comes from adopter evidence.

- [Kubernetes PSP migration guide](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/)
- [Kubernetes API removal guide](https://v1-36.docs.kubernetes.io/docs/reference/using-api/deprecation-guide/#podsecuritypolicys-v125)
- [Kubernetes v1.36 Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
