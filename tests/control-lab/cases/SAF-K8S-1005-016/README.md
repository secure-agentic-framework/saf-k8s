# SAF-K8S-1005-016 adopter verification

## Scope and crosswalk disposition

This control governs documented post-incident AI model retraining, rollback, quarantine, or related recovery decisions based on model-integrity verification. It excludes the integrity-verification mechanics and requires a justified, reviewable decision tied to recovery outcomes.

The corrected crosswalk removes the NIST SSDF 1.1 RV.2.2 association. RV.2.2 is “Plan and implement risk responses for vulnerabilities.” NIST's examples concern making a risk-based choice to remediate or otherwise address each vulnerability, planning temporary mitigation until permanent remediation exists, and issuing security advisories. The current control does not identify or respond to a software vulnerability. Its portable case validates a synthetic recovery decision record and does not perform rollback, retraining, quarantine, or vulnerability remediation. Retain the control and its portable evidence under its own AI recovery-governance claim; do not use it as proof of SSDF vulnerability response. Map vulnerability-specific response only to a control whose actual scope covers that activity.

## Paired portable evidence

The [published receipt](../../verified/SAF-K8S-1005-016.json) records 21 matching checks on separate Kubernetes v1.36.1 Kind clusters, both deleted. The catalog revision is `7c3baea51daeee549889a02037bae9ddd1dccf68` and the control-row digest is `7ce0cbfb8a5b088e9edb6df6ffb63b88e695d95a2d9e430b4af8bfad89554419`. Lab run `20261126T021719Z-b6be2dc4` and independent framework run `20261126T021956Z-d448840a` each demonstrate the same refusal-before-change and exact approved inert Deployment rollback.

## Reproduce the portable fixture

Run only in an authorized disposable local lab. Dependencies are Docker/Kind, kubectl, the pinned Kind node image, and the pinned Python 3.13 container image. The case uses case-owned immutable ConfigMaps and tokenless restricted Jobs. Jobs emit decisions only; they make no network calls and do not mutate model or deployment state.

From `saf-k8s-control-lab`:

```sh
python3 lab.py test SAF-K8S-1005-016 --docker-context desktop-linux
```

From the SAF-K8S repository root:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1005-016 --docker-context desktop-linux
```

Retain both result JSON files and verify the 16 checks, catalog revision, row/control digest, Kubernetes version, unique cluster IDs and cleanup. Rerun after any change to the case, fixtures or catalog; do not carry forward receipts across changed fingerprints.

## Deployed evidence still required

The open adopter item is `saf-lab-1005-016.1` (“Verify production rollback approvals and recovery outcomes”). It requires production-equivalent, authorized evidence for actual decision actors, trust in release/integrity evidence, and approved recovery outcomes. For each relevant incident:

1. Record the affected AI system, incident/case ID, model and version, and authorized recovery decision owner and approver. Show how their identities and approval authority were verified.
2. Preserve the integrity validation procedure, trusted evidence source, exact artifact/model version and immutable digest, reviewer, and verification timestamp. Explain how the evidence is protected against alteration and linked to the incident.
3. Record the decision (retrain, rollback, quarantine, or another action), rationale tied to integrity results, alternatives considered, residual uncertainty, risk acceptance where applicable, and required approvals.
4. Verify the actual approved outcome in an authorized production-equivalent environment: the intended version was restored, retraining completed, quarantine remained effective, or the chosen alternative was implemented. Capture before/after identifiers, timestamps, release records and rollback/recovery status without exporting sensitive model or incident data into the synthetic lab.
5. Record validation and monitoring after recovery, unresolved gaps with accountable owners and due dates, and the incident/case closure approval. Reconcile every artifact and decision to exact control and evidence revisions.

The portable fixture demonstrates only the evidence-record gate; it is not operational recovery evidence and does not close the deployment-only child.

## Primary source

NIST SP 800-218, *Secure Software Development Framework (SSDF) Version 1.1*, RV.2.2: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf. Official publication page: https://csrc.nist.gov/pubs/sp/800/218/final. RV.2.2 addresses responses to vulnerabilities, including risk-based remediation or other vulnerability response, temporary mitigation, and security advisories.

## Reconcile the approved recovery target

The case starts an inert Deployment pinned to a local marker. While it is
running, a separate restricted review Job refuses a decision with a
mismatched target digest, and the same Deployment and Pod keep the baseline
marker. The case then reads back an immutable approved decision record and
runs the review Job against its exact fixture evidence. After approval, the
case applies the target revision and confirms the same Deployment reaches a
new generation with one Ready replacement Pod and the approved marker.

The case harness applies the Deployment only after the review succeeds.
The target uses synthetic evidence and serves no application endpoint. Use
the procedure below for actual model and incident recovery.

## Verify an adopting incident recovery process

1. Open an incident record, assign an incident commander and recovery owner, identify affected model versions and deployments, and preserve the incident, release, and integrity evidence before changing service state.
2. Have an authorized independent reviewer verify the integrity result against a trusted registry or release record, exact model digest, signature/checksum method, evidence provenance, and verification time. Record any unavailable or inconclusive evidence as a blocker or explicit risk decision.
3. Select rollback, retraining, quarantine, or another response using the verified findings. Record the target revision/digest, rationale, alternatives, scope, risk, approver, and any time-bounded exception before execution. Keep decision ownership separate from approval and execution where policy requires.
4. Execute through the approved recovery/change path with a bounded rollout or maintenance window. Define the stop and reversal conditions in advance; monitor replica availability, readiness, error rate, latency, and required service capacity during transition. Pause or reverse if the approved health limits are breached; preserve the observed state and decision trail.
5. Verify the exact intended model/deployment revision and digest after recovery, repeat required integrity checks, confirm service health and monitoring, and obtain independent closure approval. Record residual risks with owners and due dates and link all records to the incident and control revision.
