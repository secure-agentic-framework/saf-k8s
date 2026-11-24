# SAF-K8S-0905-045 sandboxed behavioral vetting and disposition

`python3 tests/control-lab/lab.py test SAF-K8S-0905-045 --docker-context desktop-linux`

The unchecked path records an inert candidate’s approval before vetting.
A bounded, read-only, tokenless evaluator Job then processes fixed JSON
in a restricted Pod. The owned cluster records evaluator ingress and
egress policy. A separate reviewer Job reads the sealed evaluation,
retains exact approved and rejected dispositions, and emits a Kubernetes
Warning event tied to the evaluator Job. Scoped RBAC limits both identities.

This fixture uses deterministic toy evaluation cases. Real model artifacts,
sandbox assurance, reviewer identity, escalation, functional evaluation
coverage, and production promotion controls require separate evidence.
