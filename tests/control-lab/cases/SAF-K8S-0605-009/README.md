# SAF-K8S-0605-009 — AI custom resource validation and policy constraint enforcement

Replay with `python3 lab.py test SAF-K8S-0605-009 --docker-context desktop-linux`. Both the original catalog and corrected revision passed all 12 checks on separate fresh Kubernetes v1.36.1 clusters. The case uses the lab's digest-pinned Kubernetes v1.36.1 Kind node and a digest-pinned Python backend. Every custom-resource request is a named server-side dry-run. The CRD stores synthetic scalar fields only; there is no reconciler, model, data, GPU, or workload action.

## Pinned control and assessment

Catalog source: commit [`133a8698a45e2b335b51728bf4c62f7bda98d15f`](https://github.com/secure-agentic-framework/saf-k8s/tree/133a8698a45e2b335b51728bf4c62f7bda98d15f). The local pinned index identifies this control as `ai-specific`, title “AI custom resource validation and policy constraint enforcement,” and control hash `4931d212956af9f49bd3a40b7455e01d392baad750fd66fd0b8339840112df97`.

The pinned statement says: “AI-specific Custom Resource Definitions must have validating admission webhooks that enforce structural schema correctness, security constraints, and organizational policy requirements before AI custom resources are admitted to the cluster.” This case retains that mandatory webhook mechanism. It also demonstrates that structural CRD schema and CEL validation belong to the API server's CRD strategy and remain independently responsible for shape and declared schema rules. The webhook applies a different scoped policy criterion to an otherwise valid CR. Native VAP is retained as a separate example of additional in-process policy; it is not treated as a substitute for the control's required webhook.

The control objective also refers to downstream workload safety, GPU use, and model/data access. The inert CRD has no operator or reconciler, so this case cannot establish any actual operator's deployment compliance, generated Pod safety, GPU accounting, or model/data authorization. Those require separate, operator-specific evidence. Rejection of these bounded synthetic fixtures does not establish that a CR or model is malicious.

| Obligation | Replay evidence | Boundary |
| --- | --- | --- |
| Structural correctness and field bounds | Missing required `spec.modelRef` and `gpu: 3` fail the CRD structural schema; the latter is within the fixed dry-run fixtures. | API-server schema behavior for this illustrative CRD. |
| CRD CEL validation | A schema-valid inference object with `maxTokens: 3500` violates the CRD CEL ceiling of 3072. | One CEL rule and synthetic scalar. |
| VAP policy | Same schema-valid quota counterfactual is admitted before binding, denied after binding in the selected namespace, and admitted in the unselected namespace. | Native policy example retained as distinct scope. |
| Required validating webhook | A labeled `models/unreviewed-demo` object is schema-valid but denied with the configured exact 403 response; labeled `models/approved-v1` remains admitted. | One owned webhook and one synthetic allow criterion. |
| Namespace and object scope | Webhook configuration matches only CREATE of `inferenceplans` in the enabled namespace with the explicit fixture label. | Does not establish production configuration ownership or coverage. |
| Structural validation ordering | The malformed labeled dry-run must return audited Status 422/Invalid with the required-field message and show no matching backend event. | Replay evidence for v1.36.1 only; source ordering is cited below. |
| Deployment outcomes | None. | No actual KServe, Kubeflow, Ray, Volcano, or other operator is installed or assessed. |

## Webhook fixture and evidence handling

The case creates a fresh synthetic CA and HTTPS leaf key/certificate from files in a temporary directory. The leaf SAN is the in-cluster Service DNS name. The private key is placed in a case-owned TLS Secret and mounted read-only. The backend image is pinned by digest, has no service-account token, uses a read-only root filesystem, and logs only fixture name and allow/deny outcome. HTTP request logging is suppressed; neither the AdmissionReview body nor key or token material is logged.

The case waits for the Deployment rollout and one ready EndpointSlice address before it installs the validating webhook. A successful approved probe and a recorded denied probe then establish that requests reach the ready backend. All custom-resource probes use fixed names, server-side dry-run, and synthetic CR fields. The ValidatingWebhookConfiguration matches only the custom API CREATE operation, selected namespace label, and fixture object label. The same disallowed fixture outside the namespace selector must remain admitted.

For the malformed-object ordering check, the case-owned Kind profile enables a metadata-only audit policy limited to CREATE of `inferenceplans` in the synthetic namespace. The unique request name correlates the API audit `ResponseComplete` with its dry-run status and the backend event search. It requires API status code 422, reason `Invalid`, a `spec.modelRef` required-field message, and no backend event with that fixture name. The audit policy does not retain `requestObject`.

Kubernetes v1.36.1 source supports this specific ordering: the generic registry calls `rest.BeforeCreate` before its create-validation callback ([tagged `store.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L445-L475)); the CRD strategy's `Validate` performs schema validation, embedded-resource checks, and CEL ([tagged `strategy.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiextensions-apiserver/pkg/registry/customresource/strategy.go#L184-L208)); and the API handler passes admission as the create-validation callback ([tagged `create.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L165-L174)). Both live runs confirmed this ordering for the missing required field and the CRD CEL violation.

## Versioned references

- [Pinned SAF-K8S-0605-009 control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0605-009.md)
- [Kubernetes v1.36: CustomResourceDefinitions](https://v1-36.docs.kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/) — structural schemas, CEL schema validation, and additional admission webhook validation.
- [Kubernetes v1.36: Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) — in-process CEL policy and namespace binding scope.
- [Kubernetes v1.36.1 `store.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go#L445-L475)
- [Kubernetes v1.36.1 CRD `strategy.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiextensions-apiserver/pkg/registry/customresource/strategy.go#L184-L208)
- [Kubernetes v1.36.1 create handler](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L165-L174)

The lab retained the original result in `evidence/SAF-K8S-0605-009/20261122T092125Z-c16ab5eb/result.json` and the corrected result in `evidence/SAF-K8S-0605-009/20261122T092125Z-92b344a5/result.json`. The outcomes and observed details match exactly across both revisions. The corrected source preserves the mandatory validating webhook for security and organizational policy.

## Adopter verification

1. Inventory each installed AI operator, served CRD version, schema, webhook,
   quota, and namespace selector. Include all version conversions and upgrade
   paths.
2. With separately authorized harmless requests, test malformed structure,
   out-of-range accelerator values, disallowed model references, and
   quota-invalid declarations. Retain exact admission decisions and scope
   comparisons.
3. Verify generated workloads separately for model/data authorization,
   resource enforcement, and security context. A CR admission result alone
   does not prove downstream safety.

Open child: `saf-lab-0605-009.2`. Native receipt: 12 checks.
