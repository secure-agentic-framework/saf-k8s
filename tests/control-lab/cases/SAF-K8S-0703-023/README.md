# Verify an evidence-preserving response to an owned fixture Pod

```sh
python3 lab.py test SAF-K8S-0703-023 --docker-context desktop-linux
```

The case creates its own inert Pod, replacement, and witness. It captures the
replacement's exact UID and public marker, stores a checksummed snapshot, and
requires fixture-only approval for that UID. The API denies a request with
the old UID. A responder Role allows the one approved fixture action, and
the test verifies the same witness remains Ready, evidence is retained, and
a separate approved fixture schedules on the reclaimed synthetic slot.

Review real incident authorization, controller ownership, forensic handling,
containment, and post-action monitoring separately.

## Adopter verification

1. Identify incident authority, confirmation threshold, responder identity, and permitted action for each workload/controller type. Record when quarantine, suspend, delete, or alternate containment is authorized.
2. In an approved exercise, bind the action to the exact current object UID and owner/controller; reject stale or name-reused targets. Preserve the required snapshot, metadata, and custody record before containment.
3. Execute the approved scope only; check unrelated workloads stay healthy, no replacement controller recreates the target, and accelerator capacity is recovered as intended.
4. Retain the approver, responder, target generation, decision time, action result, evidence digest, and post-action monitoring. The fixture proves one inert Pod action, not the organization's real incident authority or forensic requirements.
