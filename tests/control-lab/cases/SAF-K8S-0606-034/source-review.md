# Source review — SAF-K8S-0606-034

## Provenance and boundary

- Control read from the requested framework Git object at commit
  `133a8698a45e2b335b51728bf4c62f7bda98d15f`, path
  `markdown/controls/SAF-K8S-0606-034.md`. The exact pinned text calls for
  auditable, justified emergency direct access outside the approved Git
  deployment path in production clusters managed through GitOps.
- The review used upstream v1.36 references. The retained result covers the
  live audit and approval checks on Kubernetes v1.36.1.
- The harness's runtime identity is a case-owned ServiceAccount with a
  short-lived token issued before either API action. It is authorized only to
  patch two named, inert ConfigMaps in one isolated namespace. No impersonation,
  privilege bypass, or unauthorized request is used.

## Claim and obligation review

| Catalog obligation or wording | Versioned mechanism and applicability | Evidence planned in this case | Source-review result |
| --- | --- | --- | --- |
| Record emergency direct access outside GitOps | Kubernetes auditing can record API requests processed by kube-apiserver when the audit policy and backend are configured. A direct fixture ServiceAccount PATCH is a normal API request; Kubernetes does not define whether it is outside an organization's GitOps path. | One actual API PATCH per fixture action; native event must name the authenticated fixture ServiceAccount and exact request. | Mechanism is supported for this request class. GitOps classification and production scope are not established by Kubernetes audit alone. |
| Make the request auditable | Audit policy rules select information level; rules are evaluated in order. `Request` records metadata and request object. `auditID`, `stage`, `verb`, `user`, `objectRef`, and `responseStatus` are documented event fields. | HTTP response `Audit-Id` must match exactly one native JSONL event for the `ResponseComplete` stage; verify actor, patch verb, namespace, ConfigMap name, body, level, and code. | Versioned Kubernetes documentation supports the tested event fields and policy behavior. Native event proves what this local API server recorded; it does not prove remote forwarding or retention. |
| Capture justification or approval | Kubernetes audit policy has no incident-ticket or human-approval field. Approval and review are organization-owned procedures or systems. | A separate fixture approval record describes exact actor, verb, namespace, resource, name, and body. A fixture execution receipt binds its action/approval IDs to the observed native audit ID. No-justification has neither record nor receipt and must not join. | External fixture-procedure evidence only. Does not establish a real approval system, approver identity, or review activity. |
| Apply the claim to production GitOps clusters and namespaces | The source control states broad organizational applicability. Kubernetes audit configuration is per API server and the configured backend; the native feature cannot establish every production cluster, namespace, request path, or API server provider's behavior. | None in source-only draft. A future local Kind run can validate this one mechanism only. | Production coverage, managed control plane behavior, GitOps/controller identity governance, and path classification need separate evidence. |
| “Fully auditable for review after use” | A successful local audit write is not evidence of retention duration, access controls, integrity, alerting, reviewer assignment, or completed review. | None; record as residual scope. | The catalog phrasing is broader than the executable Kubernetes mechanism. Keep as a governance objective, but qualify any control-efficacy result. |

## Versioned primary sources

1. [Pinned SAF-K8S control at revision 133a8698](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0606-034.md) — exact statement, objective, rationale, scope, and enforcement surface reviewed.
2. [Kubernetes v1.36 Auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) — audit event lifecycle, stages, ordered first-match policy rules, levels, `--audit-policy-file`, and audit log backend.
3. [Kubernetes v1.36 kube-apiserver Audit Configuration API](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-audit.v1/) — `auditID` unique per request; event user, verb, object reference, response status; `requestObject` is recorded at Request level; policy rule dimensions and ordered matching.
4. [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/) — Role namespace scope, additive permissions, and `resourceNames` restrictions for named-resource requests. Using `patch` avoids the documented limitation on restricting top-level `create` by resource name.
5. [Kubernetes v1.36 Service Accounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/) — ServiceAccount identity and short-lived TokenRequest credentials via `kubectl create token`.
6. [Kubernetes v1.36.1 audit filter source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/endpoints/filters/audit.go) — pinned API-server request audit filter and stage processing.
7. [Kubernetes v1.36.1 audit type source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/apis/audit/types.go) — pinned audit event/header definitions, including `Audit-ID`.

The v1.36 docs are the versioned upstream documentation baseline for the
v1.36.1 Kind node image declared by the draft. The static docs describe API
semantics; the `Audit-Id` to event equality is an explicit runtime assertion,
not a claim that this source review observed a running server.

## Proposed scope and deterministic expected observations

The draft reuses the native audit policy and independent-event-correlation
pattern of cases `SAF-K8S-1001-010` and `SAF-K8S-1006-004`, narrowed to one
human-governance fixture and a single ConfigMap API operation. It does not copy
the former case's unrelated audit levels or the latter's collection job.

| Case-owned value | Fixed expected value |
| --- | --- |
| Namespace / authenticated username | `saf-0606-034-fixture` / `system:serviceaccount:saf-0606-034-fixture:fixture-emergency-operator` |
| No-justification request | `patch configmaps/saf-breakglass-no-justification`; body `{"data":{"state":"reviewed-no-ticket"}}`; native event match true; approval join false |
| Authorized request | `patch configmaps/saf-breakglass-approved-action`; body `{"data":{"state":"reviewed-under-approval"}}`; approval `APPROVAL-0606-034-002`; action `ACTION-0606-034-002`; native event match true; approval join true |
| Policy-selected event | `Request`, `ResponseComplete`, HTTP 200; matching response `Audit-Id` and event `auditID` |
| Credential evidence | No bearer token in stdout, case evidence JSON, or logs; transient token file mode `0600`, deleted with the temporary cluster directory |

`incident-approval.json` is distinct from the Kubernetes audit backend and from
the generic request fixtures. `record_external_receipt` represents the
case-owned external procedure that pairs a ticket with the Audit-ID observed on
the ordinary API response. It is synthetic review evidence, not a native audit
field. Generated audit IDs and timestamps are intentionally not prefilled with
fake observations. They are collected in a future run, where the event/header
join and the approval/action receipt are checked.

## Disposition

**Source review: Partial / executable scope proposed, runtime unverified.** The
upstream source supports a native audit event for a matching API request and a
scoped ServiceAccount fixture. Kubernetes does not supply the separate
justification, approval, retention, or review process. No test ran, so this is
not a passing control result. The original catalog claim remains a broad
governance objective; production effectiveness requires evidence from the
deployed clusters and independently operated approval/review procedure.
