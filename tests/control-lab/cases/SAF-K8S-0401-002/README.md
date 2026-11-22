# SAF-K8S-0401-002 — RBAC permission audit and analysis

This defensive RBAC audit runs on a fresh disposable kind cluster and
compares two authorization decisions before and after remediation.

## Provenance

| Field | Evidence |
| --- | --- |
| Catalog commit and control permalink | `133a8698a45e2b335b51728bf4c62f7bda98d15f`; [pinned control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0401-002.md) |
| Pinned catalog entry | `catalog/index.json`: draft; SHA-256 `87ef1438b413241e96856e0762c6ed6a130b1e980467187a92a0968688f19aae`; “RBAC permission audit and analysis” |
| Current framework markdown | `../saf-k8s-framework/markdown/controls/SAF-K8S-0401-002.md`; SHA-256 matches the pinned control markdown (`ee817cb4173ef6e34b5bebb7b3116293e1d6747a5c5a24665d37e1335869edca`) |
| Reviewer and date | Local review on 2026-11-21. |
| Tested platform and Kubernetes version | kind with pinned `kindest/node:v1.36.1`. |
| Primary references | Kubernetes v1.36 RBAC, authorization API, and SubjectAccessReview API links below. |

## 1. Verify the claim

The pinned statement calls for periodic RBAC permission audits that find
overly permissive roles, detect escalation paths, and remediate findings. Its
objective says role and binding changes should not silently expand effective
permissions. The local catalog statement matches the pinned control text. This
case tests one narrow part of that claim: additive namespaced RBAC grants and
an unnecessary ordinary ConfigMap read. It does not test privilege-escalation
path detection or periodic organizational operations.

| Obligation from the catalog | Mechanism and applicability | Evidence needed | Result |
| --- | --- | --- | --- |
| Audit roles and bindings for excess permission | Two namespaced Roles and RoleBindings refer only to one synthetic ServiceAccount | Read both exact Role declarations; submit named GET authorization reviews | Recorded in the retained passing result |
| Compare declared and effective permissions | Kubernetes evaluates a `SubjectAccessReview` for each named ConfigMap GET against the synthetic username and its standard ServiceAccount groups | Red response for both reads, then compare after deleting only one binding | Recorded in the retained passing result |
| Remediate and preserve needed access | Delete only `saf-0401-002-unneeded-reader`; leave the required Role and binding in place | Green denied decision for unnecessary read and allowed decision for required read | Recorded in the retained passing result |

The declared required Role grants `get` on only
`saf-0401-002-required-config`. A second Role grants `get` on only
`saf-0401-002-unneeded-config`; the same synthetic ServiceAccount is bound to
both. Since Kubernetes RBAC grants are additive, the effective result should
allow both named reads before remediation. The second read is unnecessary to
the stated fixture task and is the finding.

## 2. Make the test fail for the expected reason

The red check expects the exact Role rules and both case-owned bindings to be
present. It then creates two non-persistent `authorization.k8s.io/v1`
SubjectAccessReviews for the synthetic subject: `get` the required ConfigMap
and `get` the unneeded ConfigMap in `saf-0401-002`. Both should return
`status.allowed: true`. This is the API server's authorization decision, not a
manifest-only union calculation or an access scan.

## 3. Implement the control and rerun

The corrected state removes only the unnecessary case-owned RoleBinding. The
Role and fixture remain for the before/after comparison. The green check expects
the API server to allow the required named GET and withhold authorization for
the unneeded named GET. The positive check repeats the required named GET
authorization review and requires `status.allowed: true`.

Expected observations for a passing run:

| Phase | Required named GET | Unneeded named GET | Binding state |
| --- | --- | --- | --- |
| Red | Allowed | Allowed (finding) | Required and unneeded bindings present |
| Green | Allowed | Not allowed | Required binding remains; unneeded binding removed |
| Positive | Allowed | — | Required named read remains authorized |

The review addresses only the explicitly named synthetic identity and fixture
objects.

## 4. Inspect and retain the evidence

From the local SAF-K8S control-lab root, the supervisor can run:

```sh
python3 lab.py test SAF-K8S-0401-002 --docker-context desktop-linux
```

Use a valid local Docker context. The runner should record the pinned node
image, Kubernetes server version, all three phase results, command transcript,
and cluster cleanup in the case evidence directory. No credentials are placed
in this case or in the review payloads. The SAR requests are ephemeral API
review operations; the only persistent objects are synthetic case fixtures in
the disposable cluster.

The case is limited to one namespace, one ServiceAccount, two Roles, two
RoleBindings, and two ConfigMaps. It does not cover ClusterRoles,
ClusterRoleBindings, other namespaces, aggregated roles, real subjects,
workloads, escalation verbs, production data, admission policy, managed-service
configuration, audit scheduling, or organizational finding tracking.

Confirm `cleanup: deleted` in `result.json` after a run.

## 5. Record the disposition

| Field | Evidence |
| --- | --- |
| Outcome | Live result covers the two namespaced authorization decisions. |
| What the case is designed to establish | A defensive audit can detect an unnecessary namespaced read by comparing exact Role declarations with API-server effective decisions, then remove the identified binding while retaining a required read. |
| What requires separate evidence | Full production-wide RBAC audit coverage, escalation-path analysis, periodic review operations, and real finding tracking. |
| Proposed catalog correction | None from this bounded test. The case does not validate the full scope of escalation-path detection or all-cluster audit requirements. |
| Run paths and follow-up | Retained receipt `verified/SAF-K8S-0401-002.json`. The control bead links both runs and follow-up scope. |

## Version-matched primary sources

- [Kubernetes v1.36 RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) — RoleBinding subject/role references and additive permission model.
- [Kubernetes v1.36 authorization API](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/) — API-server authorization decisions and the authorization review APIs.
- [Kubernetes v1.36 SubjectAccessReview API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/) — explicit user/groups and resource attributes with the decision returned in `status`.
