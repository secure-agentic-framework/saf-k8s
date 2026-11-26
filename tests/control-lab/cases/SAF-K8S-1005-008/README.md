# SAF-K8S-1005-008 adopter verification

## Scope and current portable evidence

The control requires maintained Kubernetes incident playbooks for compromised training jobs, model poisoning detection, GPU cryptomining, and inference endpoint abuse, with at least annual tabletop or live exercises. The NIST AI RMF 1.0 MANAGE 1.3 mapping is conditional: use it only for playbooks tied to high-priority AI risks identified through the organization's MAP function. MANAGE 1.3 calls for responses to MAP-identified high-priority AI risks to be developed, planned, and documented; response choices can include mitigation, transfer, avoidance, or acceptance.

The published portable case runs a digest-pinned, tokenless mock responder in disposable Kind v1.36.1. It processes checked-in synthetic event envelopes, validates four defensive playbook records, rejects a missing owner, disabled playbooks and mismatched event/resource metadata, routes expected scenarios, checks a healthy no-action case, and restores only explicitly named case-owned fixture resources. The responder compares the fixture artifact to a pinned SHA-256 reference. For suspected model poisoning, preserve verified artifact identity, review input and artifact provenance, and assess model behavior against approved evaluation criteria. The GPU event is fictional and demonstrates routing, not GPU detection. No production workload, model, GPU, DCGM/driver telemetry, inference endpoint, external containment, or actual recovery is exercised.

Published paired receipts: lab `evidence/SAF-K8S-1005-008/20261122T171715Z-b6116519/result.json` and framework `tests/control-lab/evidence/SAF-K8S-1005-008/20261122T171715Z-0a1040ad/result.json`. Each records 18 passing checks against catalog revision `133a8698a45e2b335b51728bf4c62f7bda98d15f` and control-row digest `4b0332e246a7260e1234803efd1e1e7d6621d0bf5952287fe31552dbfb9334e8`; the cluster names differ and cleanup is `deleted` in both. This proves parity of the portable case at that exact revision, not production response capability.

## Reproduce the portable fixture

Run only in an authorized, disposable local lab with the pinned Kind/Docker context and synthetic fixtures. Do not point the case at production or third-party targets.

```sh
python3 lab.py test SAF-K8S-1005-008 --docker-context desktop-linux
```

From the SAF-K8S repository root:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1005-008 --docker-context desktop-linux
```

Retain both resulting `result.json` files. Confirm the control ID, catalog revision, row digest, Kubernetes version, 18 assertion results, disposable cluster identity, `status: passed`, and cleanup result. A test pass means the local synthetic playbook contract behaved as designed; it is not an annual exercise record.

## Deployer evidence required for the remaining obligation

1. **Bind risks to playbooks.** Provide the current AI system MAP/risk register revision, identify which risks are high priority, and link each applicable risk to one or more of the four playbooks. Record accepted risks and why no playbook applies where relevant.
2. **Verify production signals.** For each playbook, identify the actual detection source and owner: training-job integrity, model artifact/poisoning checks, GPU telemetry (including provider/DCGM source where used), or inference-route abuse signals. Show a safe representative event or approved exercise record reaches the intended trigger and is distinguishable from benign activity.
3. **Review action and authorization.** Record who approves the response, what Kubernetes resources or service scope can be affected, the containment/recovery decision, rollback conditions, escalation contacts, and how legal/privacy or business constraints are considered. Confirm least-privilege permissions and emergency authorization through the organization's normal change-control process.
4. **Exercise and record outcomes.** Attach the tabletop or live exercise date, participants, scenario, expected versus observed trigger/action, recovery result, gaps, accountable remediation owner and due date. Keep exercise records separate from the synthetic fixture receipt. Confirm the stated annual cadence is met and schedule the next exercise.
5. **Reconcile evidence after changes.** Recheck playbook, trigger, responder, policy, and source-system revisions against the risk register; preserve hashes or immutable version references and record approvals. If control/catalog files change, rerun the exact lab and framework candidates and compare current control-row fingerprints before carrying forward prior receipts.

## Source

NIST, *Artificial Intelligence Risk Management Framework (AI RMF 1.0)*, NIST AI 100-1, Table 4, MANAGE 1.3: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf. The standard requires a risk response to be developed, planned, and documented for high-priority risks identified by MAP; this control's portable test verifies only a synthetic responder/playbook readiness slice.
