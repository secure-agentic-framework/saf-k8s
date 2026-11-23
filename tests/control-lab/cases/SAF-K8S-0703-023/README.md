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
