# SAF-K8S-0204-002 — Attributable Falco alerts and verified delivery

```sh
python3 lab.py test SAF-K8S-0204-002 --docker-context desktop-linux
```

Kind emits API audit metadata for two owned ConfigMap reads. Pinned Falco
and its audit plugin evaluate finite copies of the live records. An
unmatched rule, a copy with identity removed, and an explicitly disabled
rule produce no matching alerts. The active rule sends the marked alert
through Falco's native HTTP output to a separate receiver. The test matches
the received audit ID, actor, and namespace to the source and checks that
the ordinary API operation remains available. Only synthetic fixture
objects and audit metadata are used.

## Verify deployment applicability and evidence

1. Identify the required rule and hypothesis, source type, supported tool
   and plugin or driver version, governed scope, and identity fields.
   Verify the effective source and rule inventory and approved exceptions.
2. Run owned positive and negative fixtures, including missing context and
   unavailable sources. Record the expected events and alerts, rule
   version and matching identity. Test the rollout and disable path.
3. Reconcile delivery to the configured receiver and responsible responder.
   Exercise loss, backpressure, retry and duplicate handling. Record timing,
   retention, alert-only behavior and authorization for any active response.
4. Validate separately for each applicable kernel, network, runtime and
   API-audit source. This example exercises the audit plugin, one rule and
   its HTTP delivery path.

[Falco 0.45.2 rules and output configuration](https://github.com/falcosecurity/falco/blob/0.45.2/falco.yaml) ·
[Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
