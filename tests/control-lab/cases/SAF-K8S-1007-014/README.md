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
