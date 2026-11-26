# SAF-K8S-1007-014 — AI asset classification and criticality governance

From the SAF-K8S framework checkout, run the disposable case with:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-014 --docker-context desktop-linux
```

The control-lab runner creates a fresh Kind Kubernetes v1.36.1 cluster using its digest-pinned node image. This case adds one owned namespace, a zero-replica mock Deployment that specifies `docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`, and a native Kubernetes `ValidatingAdmissionPolicy` plus binding. The policy validates synthetic sensitivity, criticality, and exposure labels on ConfigMaps in that labeled namespace.

The red assertion shows that the API admits an unclassified AI asset record via server-side dry-run before policy installation. The first green assertion attempts the same unclassified record after the policy is active. The case records the policy denial and verifies that a subsequent API read returns no object. It then attempts an out-of-set sensitivity value and likewise requires denial and absent readback. The green assertion creates the permitted synthetic record, reads it from the Kubernetes API, and compares its UID, labels, and data to the input. The positive assertion updates that same ConfigMap's allowed classification labels, reads it back, verifies that its UID and record data are unchanged, and computes a different route from the observed labels.

The route names and rule are local fixture logic: `internal`/`low`/`none` routes to `synthetic-standard-review`; `restricted`, `high` or `critical`, or `review` routes to `synthetic-priority-review`. These routes do not create tickets or invoke external systems. Raw JSON evidence contains only the case-owned objects, synthetic metadata, API responses, and generated cluster UIDs. No Secret resources are created.

## Coverage and limits

This case demonstrates Kubernetes API-server admission of a narrow classification schema for one synthetic AI service registry record; rejection of missing and invalid values; permitted durable readback; and a fixture-only route change for the same record. The zero-replica Deployment supplies an API-visible workload identity without starting Pods or pulling a fixture image. The classification values and routing threshold are authored for this test because the pinned control does not define a taxonomy or routing algorithm.

It does not demonstrate asset discovery or inventory completeness; classification of real models, datasets, pipelines, endpoints, or GPU-backed services; enforcement on Pods/Deployments or other API kinds; organization-wide taxonomy governance; identity or ownership verification; lifecycle review or drift detection; real sensitivity or criticality assignment; legal/regulatory applicability; real risk analysis; incident prioritization; ticket delivery; production monitoring; or response-time outcomes. It does not establish that any real organization or asset is compliant.

## Primary references

- [Kubernetes v1.36 Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) documents CEL validation, policy/binding behavior, and the stable API.
- [Kubernetes v1.36 ValidatingAdmissionPolicy API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-v1/) documents the v1 policy resource.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting a Kubernetes node image by digest for a specific Kubernetes version.
- [Docker Official Python image](https://hub.docker.com/_/python) is the primary image source for the digest-pinned mock workload image.

## Verify an adopting asset inventory

1. **Approve the taxonomy.** Record the organization-approved sensitivity, business-criticality, and regulatory-exposure categories, their definitions, decision owner, approval date, and review cadence. Identify which categories trigger enhanced risk review. Link classifications to the organization’s risk process and use approved categories and thresholds.
2. **Define the in-scope asset inventory.** For models, datasets, pipelines, endpoints, and GPU-backed services in scope, record each asset’s stable identifier, owner, environment, asset type, classification values, rationale, source of truth, and last-review date. State discovery/reconciliation sources and explicitly list exclusions and unknowns so inventory completeness is measurable.
3. **Verify identity binding and coverage.** Sample each represented asset class and reconcile its registry record to the actual Kubernetes object/workload and owner. Capture object kind, namespace, stable UID or equivalent identifier, classification, and relationship. Document non-Kubernetes assets or assets represented by other resource kinds separately; the portable test enforces ConfigMap labels only.
4. **Verify deployed enforcement.** Export the active admission policy and binding (or equivalent mechanism), selectors, resource kinds, namespaces, and policy mode. Using an approved nonproduction namespace or server-side dry-run, show that missing and invalid classifications are rejected, approved values are accepted, and an authorized classification change is auditable. Record approved exclusions, failure behavior and the tested deployment scope.
5. **Trace operational routing.** Select one real low-priority and one elevated-classification record. Show the actual review/risk/incident queue or workflow receives the correct asset identity, classification, owner, timestamp, and disposition, and that a classification change updates the route. Redact personal or sensitive content while retaining traceable IDs. The fixture’s `synthetic-standard-review` and `synthetic-priority-review` names are local calculations and create no tickets.
6. **Close with governance evidence.** Include the responsible Platform, AI/ML, Security Operations, and GRC reviewers as applicable; approvals, exceptions, sampled reconciliation results, stale-record handling, and next review date. Report sampled coverage and unresolved assets. Link resulting remediation records to the sampled deployment scope.
