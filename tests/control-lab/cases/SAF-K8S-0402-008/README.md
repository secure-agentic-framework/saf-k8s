# SAF-K8S-0402-008 — Distinct identity assignment for AI workload types

This case prepares three ordinary, synthetic Kubernetes Pods that represent
Training, Inference, and Pipeline workloads. Each Pod has an explicit and
different Kubernetes ServiceAccount. After creating one namespaced Role and
RoleBinding per identity, it uses the API server's named-read authorization
reviews to confirm that each identity retains its own harmless ConfigMap read
and is not authorized to read the other two ConfigMaps.

## Provenance

| Field | Evidence |
| --- | --- |
| Pinned catalog commit and control permalink | `133a8698a45e2b335b51728bf4c62f7bda98d15f`; [pinned control markdown](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0402-008.md) |
| Pinned catalog entry | `catalog/index.json`: draft, D04, “Distinct identity assignment for AI workload types”; row SHA-256 `53d56fec8fa31f01eaaf7e613848eda1231d0bc99041480c6a142fab12c94b95` |
| Pinned control markdown digest | SHA-256 `f25c93ea78c1f9be7de74738fde1e70b6767e9489e8c8ca70869004de56f5995` at the pinned commit |
| Local framework source inspected | `../saf-k8s-framework/markdown/controls/SAF-K8S-0402-008.md`, checkout commit `ed8c075e7d2fe644ba0917e0362dd94e51878f83`, SHA-256 `f94491e46d68ca14a4dcd184f5b355d18f1c95050db86e98f6c74da2b3829e80`; its digest differs from the pinned markdown, so the commit permalink above defines the reviewed catalog text |
| Reviewer and date | Local review on 2026-11-21. |
| Tested platform and Kubernetes version | Disposable kind on the pinned Kubernetes v1.36.1 node image. |
| Primary references | Kubernetes v1.36 ServiceAccounts, RBAC, and SubjectAccessReview authorization API documentation linked below. |

## 1. Verify the claim

The pinned catalog statement requires different Kubernetes ServiceAccounts for
Training, Inference, and ML Pipeline workloads, with role-appropriate
permissions, and says workload types with different access needs must not share
an account. Its implementation surface also names admission policies that map
workload labels or annotations to the expected ServiceAccount. The case checks
three explicitly assigned Pod identities and their effective namespaced
ConfigMap read decisions. It does not implement or validate an admission
policy.

| Obligation from the catalog | Mechanism and applicability | Evidence needed | Result |
| --- | --- | --- | --- |
| Assign distinct identities to the three named workload types | Three ordinary Pods specify three different ServiceAccounts; each has a workload-type label | Read the live Pod specs and confirm all three expected, unique `serviceAccountName` values | Recorded in the passing result |
| Give each identity a workload-specific permission boundary | Each Role grants only `get` for its exact case-owned ConfigMap, and its RoleBinding names only the matching ServiceAccount | Inspect exact Role rules, RoleBinding `roleRef`, and subject; submit API-server authorization reviews | Recorded in the passing result |
| Preserve required access and withhold unrelated named reads | A named GET `SubjectAccessReview` is submitted for each ServiceAccount against all three ConfigMaps | Each identity is allowed its own named read and is not allowed either other named read | Recorded in the passing result |
| Enforce workload-type-to-ServiceAccount mapping | The catalog describes an admission policy keyed to workload labels or annotations | Separate admission-policy review and live admission probes | Out of scope for this case |

### Applicability notes

Kubernetes assigns a Pod's ServiceAccount through `spec.serviceAccountName`.
Namespaced Roles and RoleBindings supply its Kubernetes API permissions. The
fixtures disable ServiceAccount token automount because the case asks the API
server to review named subjects directly; no workload token is read, copied,
or used. This proves Kubernetes identity assignment and the reviewed native
RBAC decisions for these exact fixtures only.

Cloud IAM roles, workload identity federation, Vault or external service
credentials, cluster-wide or cross-namespace grants, and real data-lake,
registry, feature-store, model-serving, or AI pipeline permissions need
independent evidence. Kubeflow, KServe, training-operator, notebook, and
production admission integrations also need separate verification. The
synthetic ConfigMaps are ordinary namespaced Kubernetes API objects, not model
artifacts or training datasets.

## 2. Make the test fail for the expected reason

The runner creates three harmless Pods with the same synthetic ServiceAccount.
A case-owned RoleBinding gives that account all three named ConfigMap reads.
The baseline checks each actual Pod assignment and all three authorization
decisions. It then recreates the three Pods with distinct ServiceAccounts and
removes the shared binding.

## 3. Implement the control and rerun

The fixtures define three ServiceAccounts and three harmless ConfigMaps.
`case.py` creates one ordinary idle Pod per workload type with its explicit
ServiceAccount and token automount disabled. The second manifest adds three
exact-name `get` Roles and one corresponding RoleBinding for each ServiceAccount.

After the bindings are present, the case checks their live declarations and
submits nine named `SubjectAccessReview` requests. A passing result has this
matrix:

| Kubernetes identity | Training data ConfigMap | Inference model ConfigMap | Pipeline config ConfigMap |
| --- | --- | --- | --- |
| Training | Allowed | Not allowed | Not allowed |
| Inference | Not allowed | Allowed | Not allowed |
| Pipeline | Not allowed | Not allowed | Allowed |

The ordinary harmless operation preserved for each synthetic workload is its
own named read. The other two named reads must not be authorized. This case
does not issue actual ConfigMap GETs as the workload identities; it observes
the API server's effective authorization decision through `SubjectAccessReview`.

## 4. Inspect and retain the evidence

The supervisor can run the case from the local control-lab root with:

```sh
python3 lab.py test SAF-K8S-0402-008 --docker-context desktop-linux
```

Use the valid local Docker context and the lab's pinned node image. The live
review should retain the server version, Pod identity observations, declared
Role and RoleBinding checks, all before/after authorization decisions, and
cluster cleanup in the normal result record. The framework retains
`verified/SAF-K8S-0402-008.json`. Keep authorization request payloads limited
to these synthetic user names, namespace, verb, resource, and fixture names.

Scope is one namespace, three Pods, three case-owned ConfigMaps, and the shared and individual
ServiceAccount and RBAC fixtures. It excludes
ClusterRoles, ClusterRoleBindings, additional permissions, identity groups
beyond the standard ServiceAccount groups, actual credential use, external IAM,
admission enforcement, production workloads, and real AI platform behavior.

## 5. Record the disposition

| Field | Evidence |
| --- | --- |
| Outcome | Live behavior confirmed for the synthetic Kubernetes identities. |
| What the case is designed to establish | Three synthetic Kubernetes workload types use distinct ServiceAccounts; each has one reviewed, preserved named read and is not authorized for the other two named reads |
| What requires separate evidence | Admission mapping enforcement, broader Kubernetes RBAC inventory, external IAM and federation, platform operators, actual AI/model environments, and the organizational lifecycle of identity assignments |
| Proposed catalog correction | The core control wording agrees with the observed Kubernetes ServiceAccount and RBAC behavior. |
| Rerun path and follow-up | `python3 lab.py test SAF-K8S-0402-008 --docker-context desktop-linux`; the primary Bead links both runs and the deployment follow-up |

## Version-matched upstream references

- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/) — assigning a ServiceAccount with `spec.serviceAccountName` and the token automount setting.
- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) — Roles, RoleBindings, and `resourceNames` behavior.
- [Kubernetes v1.36 authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/) — API-server authorization decisions and review APIs.
- [Kubernetes v1.36 SubjectAccessReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/) — named user/group request attributes and server-populated authorization status.
