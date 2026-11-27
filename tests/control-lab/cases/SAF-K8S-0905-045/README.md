# Verify a digest-bound behavioral evaluation and review

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-045 --docker-context desktop-linux
```

A Kubernetes Job computes the expected behavior of three fixed inert text
markers. The evaluation trace records the candidate identity, input digest
and observed marker output. The reviewer recalculates the trace digest and
uses its own Kubernetes permissions to record the decision. The case
compares the unsafe marker rejected with a warning and the approved safe
marker. Kubernetes authorization checks verify the identities' permissions.

For an actual model release, use approved inputs and an explicit rubric tied
to a pinned model artifact. Verify the runtime and sandbox boundaries,
evaluation coverage, human reviewer authority, evidence retention, and every
promotion path. The case executes a deterministic toy evaluator.


This scratch extension adds one fixed inert `toy-inconclusive-v1` marker. The evaluator records an `inconclusive` outcome; the separate reviewer persists `escalated` with the evaluation digest, and a second ConfigMap GET verifies that the candidate remains unapproved. This is a durable workflow-record witness only; organizational escalation authority and human review remain adopter evidence.
