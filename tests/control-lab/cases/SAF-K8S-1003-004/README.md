# SAF-K8S-1003-004 adopter verification

## Scope and crosswalk disposition

The control governs a versioned MITRE ATT&CK for Containers technique inventory, evidence references, explicit coverage gaps and change review. Its current portable test validates that the register corresponds to selected upstream metadata and does not claim deployment coverage without independent evidence.

The corrected crosswalk removes the NIST AI RMF 1.0 MAP 3.2 association. The current canonical title (“Potential harms to people, organizations, and ecosystems …”) does not match NIST AI 100-1 Table 2. MAP 3.2 instead states: “Potential costs, including non-monetary costs, which result from expected or realized AI errors or system functionality and trustworthiness—as connected to organizational risk tolerance—are examined and documented.” The fixture documents technical attack scenarios, detection/mitigation references, and unmeasured coverage; it does not estimate or examine AI-system costs relative to organizational risk tolerance. Keep this control's independent ATT&CK coverage purpose. Reconsider a conditional input relationship only if the organization separately documents how its attack register informs that MAP cost assessment.

## Existing paired portable evidence

- Lab: `saf-k8s-control-lab/evidence/SAF-K8S-1003-004/20261122T164925Z-b222716e/result.json`
- Framework: `saf-k8s-framework/tests/control-lab/evidence/SAF-K8S-1003-004/20261122T164925Z-437b1089/result.json`
- Both: 3 of 3 checks passed, catalog revision `133a8698a45e2b335b51728bf4c62f7bda98d15f`, control-row digest `45775658ceee3763e8fa28984db673a5697cf40a85d04dfea2a1f608409796c8`, Kubernetes v1.36.1, distinct disposable Kind cluster IDs, cleanup `deleted`.
- Observations: the ungated Job accepted the invalid register; the enabled validator rejected wrong tactic/technique metadata, event mismatch, absent gap disposition, and a deployment claim lacking independent evidence; the corrected register passed with T1610/T1611/T1613 and three owned gaps, all showing deployment `unknown`.

## Reproduce the fixture

The case uses one ConfigMap and three tokenless Kubernetes Jobs in disposable Kind v1.36.1. Jobs use the pinned Python 3.13 image and checked-in metadata/fixture files; no live MITRE fetch or target interaction is performed during the case. Dependencies are Docker/Kind, kubectl, the pinned node image, and the pinned Python image. Run only in an authorized disposable local lab.

From `saf-k8s-control-lab`:

```sh
python3 lab.py test SAF-K8S-1003-004 --docker-context desktop-linux
```

From the SAF-K8S repository root:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1003-004 --docker-context desktop-linux
```

Confirm three checks, exact catalog revision and row digest, Kubernetes version, different disposable cluster IDs, and deleted cleanup. The test validates a narrow register and gap-review mechanism; it does not validate the organization's deployed ATT&CK coverage.

## Deployed evidence for the open review

The remaining adopter item, `saf-lab-1003-004.1`, calls for deployment and telemetry evidence. For each assessment:

1. Inventory AI-relevant Kubernetes components, versions, namespaces, workload identities, admission controls, runtime telemetry sources, audit sources and monitoring integrations. Record source owners and evidence dates.
2. Select the currently applicable official ATT&CK for Containers techniques based on the actual architecture. Preserve the release/version and technique/tactic metadata used; explain exclusions and prioritization.
3. For each technique, distinguish tested prevention, measured detection, partial coverage, and unknown/unmeasured deployment state. Link only independently reviewable evidence such as approved policy decisions, redacted audit samples, effective telemetry records, alert receipts or mitigation test results.
4. Assign each gap an accountable owner, impact/priority, remediation or acceptance decision, due date, and next-review trigger. Keep “unknown” where no deployment evidence exists; do not infer deployed coverage from the synthetic test.
5. Revisit the mapping after ATT&CK release, architecture, control or telemetry changes. Retain the prior and new metadata digests, review approval, and closure evidence for changed gaps.
6. If using the register to inform NIST MAP 3.2, link it to a separate record that examines potential costs from AI errors or system functionality/trustworthiness against organizational risk tolerance. This control does not supply that cost analysis.

## Primary sources

- NIST AI 100-1, *Artificial Intelligence Risk Management Framework (AI RMF 1.0)*, Table 2, MAP 3.2: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
- MITRE ATT&CK for Containers v20.1 release metadata: https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1
- MITRE Containers matrix for the pinned release: https://attack.mitre.org/versions/v20/matrices/enterprise/containers/
