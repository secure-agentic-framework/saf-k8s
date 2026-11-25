# SAF-K8S-1003-005 adopter verification

## Mapping and tested boundary

NIST AI RMF 1.0 MEASURE 2.7 states: “AI system security and resilience—as identified in the MAP function—are evaluated and documented.” This control can contribute to the detection-evaluation slice only when the MAP assessment identifies the covered Kubernetes behaviors as relevant to the AI system. It does not independently establish overall AI-system security or resilience.

The portable test runs two tokenless, restricted Kubernetes Jobs in disposable Kind v1.36.1. Both execute `promtool test rules` from the digest-pinned Prometheus 3.16.0 image against synthetic audit-event series. The fixture contains two detection rules only: privileged AI-namespace Pod creation (T1610) and AI Pod exec requests (T1609). Four safe or out-of-scope near misses must stay quiet. A no-rules comparator confirms the positive synthetic events have no actionable match without the rules; the enabled rule tests check expected rule/technique IDs, labels, annotations, runbook IDs, and safe near misses. A synthetic change-review fixture binds the rules digest and MITRE Containers v20.1 metadata version.

The Jobs are unit-rule evaluators. They do not run a Prometheus server, scrape live audit events, test production event normalization or alert routing, invoke a SIEM/SOAR, or exercise analyst response. The runbook JSON is synthetic and its presence does not prove an operational responder.

## Paired portable evidence

- Lab: `saf-k8s-control-lab/evidence/SAF-K8S-1003-005/20261122T165329Z-4bbeb6fb/result.json`
- Framework: `saf-k8s-framework/tests/control-lab/evidence/SAF-K8S-1003-005/20261122T165329Z-0a9a2d6c/result.json`
- Both: 4 of 4 checks passed; catalog revision `133a8698a45e2b335b51728bf4c62f7bda98d15f`; control-row digest `ec4d26b3ae76623533a3d4822d86de61b5df13bd2b586dbf1e0cb2f8135493f2`; Kubernetes v1.36.1; different disposable Kind cluster IDs; cleanup `deleted`.
- The receipt shows fixture assertions only; do not describe it as live detection or production alert-delivery evidence.

## Reproduce in an authorized disposable lab

The control-lab runner requires Docker/Kind, kubectl, and the pinned node and Prometheus images. Use only the synthetic fixtures in an owned disposable local cluster; do not direct the test at production or third-party systems.

From `saf-k8s-control-lab`:

```sh
python3 lab.py test SAF-K8S-1003-005 --docker-context desktop-linux
```

From `saf-k8s-framework`:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1003-005 --docker-context desktop-linux
```

Retain the resulting JSON receipts and confirm all four named assertions, pinned Kubernetes version, catalog revision, control-row digest, unique cluster ID, and cleanup. Rerun both repositories after case, rule, fixture, or control changes; prior results are limited to the recorded fingerprints.

## Deployed verification required for the open adoption gate

1. **Bind scope to MAP.** Record the AI system and deployment, MAP revision, prioritized security/resilience risks, and why privileged workload creation and Pod exec are applicable. List other material risks not covered by these two rules.
2. **Verify source and normalization.** Identify the authoritative audit or telemetry source and the exact event schema. Show that authenticated principal, verb, API resource, namespace, workload identity, and privilege state survive normalization into the deployed rule inputs. Use approved inert events or controlled nonproduction exercise data.
3. **Verify the deployed detection.** Record the production rule file and digest, Prometheus/runtime or managed service version, rule-to-technique mapping/version, deployment approval, enabled scrape/export path, and observed results for representative positive and safe near-miss events. Document source coverage and known blind spots.
4. **Verify delivery and prioritization.** Capture an exact generated alert and delivery receipt through Alertmanager/SIEM/on-call routing, including timestamps, destination, severity, deduplication/suppression behavior, and acknowledgment. Confirm priority against the organization's risk criteria and show how duplicates or out-of-scope events are handled.
5. **Verify analyst disposition.** Attach the case/ticket or protected incident record showing the assigned responder, triage result, supporting audit context, escalation/containment decision, any override, and closure or follow-up. Preserve privacy controls and remove sensitive data from portable evidence.
6. **Reconcile proof after changes.** Record the current rule, event-source, runbook, and deployment revisions. Re-run both portable candidates for changes and compare their result `catalog_revision` and `control_sha256` to the exact current published control. Keep adopter evidence separate from synthetic receipts.

## Primary sources

- NIST AI 100-1, *Artificial Intelligence Risk Management Framework (AI RMF 1.0)*, Table 3, MEASURE 2.7: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- MITRE ATT&CK for Containers v20.1 release metadata (the test pins this version; confirm applicability against deployed architecture rather than treating it as a complete coverage claim): https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1
- Prometheus rule unit-testing reference (the fixture uses `promtool test rules`; this is unit-evaluator evidence, not scrape/delivery proof): https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/
