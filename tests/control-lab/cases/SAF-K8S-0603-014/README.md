# SAF-K8S-0603-014 — Fail-closed attestation admission

Run `python3 lab.py test SAF-K8S-0603-014` from the control lab.

The case installs pinned Kyverno on disposable Kind and signs two in-toto
records over each fixture image digest using independent keys. The policy
requires the approved build and promotion signatures and checks the promotion's
reference to the verified build record. Missing, incorrectly signed, and
unlinked records receive policy-specific API denials.

The case checks fresh digests while the owned registry is unavailable and
while the API server cannot reach the matching registered webhook. It
observes the failure reason and permits the same completed chain after
restoring each dependency. The demonstrated scope is Pod creation in one
enrolled namespace. Deployed policy scope, cache behavior, registration
lifecycle, and any additional stages require their own evidence.

## Adopter verification

1. Inventory every deployed admission route and enrolled namespace, including
   policy/webhook registration ownership, all attestation stages, trust roots,
   and cache behavior.
2. On an approved inert workload, show that absent, wrong-promoter, and
   unlinked attestations are denied by the deployed path. Record the exact
   policy response and confirm no object was persisted.
3. With an authorized change window, verify registry/verifier and admission
   dependency outages fail closed, then recover and recheck the same approved
   request. Retain correlated audit and registration lifecycle evidence.

Open child: `saf-lab-0603-014.1`. Native receipt: 10 checks.
