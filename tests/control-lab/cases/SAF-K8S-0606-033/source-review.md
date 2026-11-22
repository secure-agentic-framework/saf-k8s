# Source review — SAF-K8S-0606-033

## Provenance and boundary

- Catalog source: `secure-agentic-framework/saf-k8s` commit
  `133a8698a45e2b335b51728bf4c62f7bda98d15f`.
- The commit object exists in `../saf-k8s-framework`. The pinned YAML blob object is
  `a14ec0be623959366e732039abc149de27e79a07`; the exact original Markdown
  control blob is `54aa2def1787ad28de8d2468d77056710fd871a8`. Both were read from
  the requested commit with `git show`.
- The lab's pinned catalog index reports control-record hash
  `0db9f36b8f952e8d01e260e3cd9e619b67f90306b5505c3b8044bde1c6583e13`.
  The current framework checkout's Markdown file differs from the pinned
  original; the review uses the pinned Git object, not current working-tree
  prose, as the claim under review.
- The original control's statement requires (a) direct runtime changes
  prohibited through cluster RBAC and (b) Git as the sole approved deployment
  path. Its scope is production namespaces/clusters managed by GitOps and its
  implementation surface includes RBAC, operational controls, and routine
  direct `kubectl` restriction.
- This document covers the source review. The retained result records the live
  observations on Kubernetes v1.36.1.

## Obligation review

| Catalog obligation | Source-backed mechanism | Evidence this case can provide | Result |
| --- | --- | --- | --- |
| Prohibit direct creates, updates, deletes by routine operator identity | Kubernetes RBAC is additive. A Role is namespace-scoped; RoleBinding grants that role's permissions to its subjects within the binding namespace. The case's normal `saf-operator` has no Deployment write grant in `prod-fixture`. | `kubectl auth can-i` for each of create/update/patch/delete as that SA, plus an actual create attempt expected to fail authorization. | Mechanism covered for one SA and one namespaced resource. |
| Git is the only approved path for the selected resource | Kubernetes v1.36 ValidatingAdmissionPolicy uses CEL request attributes including authenticated `request.userInfo`; a ValidatingAdmissionPolicyBinding attaches policy logic and scope. The case selects Deployment CREATE, UPDATE, and DELETE in the fixture namespace and admits only the exact Argo application-controller SA name. | Argo CD v3.6.1 performs a sync from a case-owned Git commit under its actual controller SA. The binding rejects the exact write-capable comparison identity's CREATE dry-run that passed before it. | Live admission coverage for CREATE and one controller identity. Live UPDATE and DELETE denial need separate evidence. |
| All production change paths are Git-controlled | The API policy only identifies an authenticated username; it does not inspect Git provenance, prove human approval, or ensure the controller acts only on repository changes. | No proof for broad path or production fleet. | Unverified beyond the narrowly simulated path. |
| Emergency direct access is governed separately | The catalog rationale explicitly separates exceptional access governance. This draft has no emergency principal, impersonation facility, bypass, or emergency workflow. | None. Requires separate review of SAF-K8S-0606-034 and real operational evidence. | Out of scope. |

## Source notes

1. The pinned source control defines Git-only deployment as the claim but does
   not prescribe a concrete technical control. RBAC can prevent the ordinary
   principal from mutating namespaced resources. A request-admission policy
   provides a second enforcement layer that distinguishes controller identity
   from other identities, while the controller's Git reconciliation provides
   the positive path.
2. Kubernetes RBAC allow rules do not express deny rules. Therefore a missing
   RoleBinding/grant is the RBAC denial model; a scoped admission policy is a
   separate gate. Since authorization precedes admission, the fixture gives
   only `saf-out-of-band-probe` a narrow temporary namespaced Deployment Role
   so the request is authorized far enough to receive the explicit policy
   denial. The case first records a successful create dry-run by that probe SA
   while the binding is absent, then installs the policy and repeats the
   identical request to obtain the explicit policy denial.
   `saf-operator` retains no write grant and demonstrates the ordinary RBAC
   boundary.
3. Kubernetes TokenRequest returns a time-bound ServiceAccount token. The case
   uses `kubectl create token` for actual SAs and a private short-lived
   kubeconfig; it does not synthesize `UserInfo`, use impersonation flags, or
   log credential material.
4. Argo CD v3.6.1's pinned install manifest defines the
   `argocd-application-controller` ServiceAccount and workload. The positive
   result must be tied to the live Argo Application's source revision and
   resulting Deployment, not to a direct API request made with a copied
   controller token.

## Review disposition

**Provisional: Partial, pending the parent's independent run and evidence review.**
The catalog statement is supportable as a control objective. This fixture can
exercise one real GitOps path plus one RBAC denial and one admission denial in
case-owned scope. It cannot establish production coverage, all resource types,
Git review/approval provenance, complete controller least privilege, or
exceptional access governance. Do not record a final claim result until the
parent runs and checks the case and its emitted evidence.

## Primary upstream sources

- [Pinned catalog control Markdown](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-033.md)
- [Pinned catalog controls YAML](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/saf_k8s_controls.yaml)
- [Kubernetes v1.36 RBAC docs](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 authorization and admission ordering](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [Kubernetes v1.36 Validating Admission Policy docs](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 ServiceAccount administration docs](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Argo CD v3.6.1 install manifest](https://raw.githubusercontent.com/argoproj/argo-cd/v3.6.1/manifests/install.yaml)
- [Argo CD v3.6 auto-sync docs](https://argo-cd.readthedocs.io/en/release-3.6/user-guide/auto_sync/)
