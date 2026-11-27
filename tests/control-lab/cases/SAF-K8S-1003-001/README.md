# SAF-K8S-1003-001 — STRIDE review gate

```sh
python3 lab.py test SAF-K8S-1003-001 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. Four native Jobs in Kubernetes v1.36.1 Kind compare disabled and enabled review workflows. They read the same synthetic records and evidence from a mounted ConfigMap and run the validator in a digest-pinned Python container.

The disabled workflow accepts the incomplete record. The enabled gate rejects it for a missing STRIDE disposition and evidence reference. An otherwise complete record fails after its review deadline. The valid record passes with nine component classes, six STRIDE categories per class, one linked threat and mitigation per cell, and two distinct recorded approval roles. The runner verifies actual Kubernetes Job outcomes and exit codes.

Start a review with `template.json`. Fill the component trust boundaries and evidence paths, record the disposition for each component and category, and associate identified threats with owners and mitigations. A disposition of `not-applicable` requires a rationale. Use the fixture folders for an example record and relative evidence paths.

The current case uses synthetic reviewers and approvals. Production evidence must cover deployment inventory, evidence authenticity, reviewer authority, mitigation decisions and the architecture change process.

[Kubernetes Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/) · [Microsoft STRIDE threat categories](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

## Architecture and flow binding

The separate `stride_architecture_gate.py` supplement binds a synthetic reviewed
STRIDE record to the exact bytes and revision of a case-owned DFD fixture. Each of
the nine component entries declares a flow and trust-boundary ID; every synthetic
threat cell must resolve to a flow belonging to that same component and boundary.
The added Jobs check a positive record, a metadata-only ConfigMap change, a material
graph revision change (old review rejected, refreshed review accepted), a dangling
flow reference, and a flow borrowed from another component. The graph, reviewers,
threats, and mitigations are synthetic fixture data.

Use reviewed architecture inputs and current data-flow diagrams to complete the
worksheet. Record significant changes, reevaluate affected threats and mitigations,
and retain the authorized reviewer and approval records. Microsoft describes using
data flows and trust boundaries to identify threats and determine mitigations.
[Threat Modeling for Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers).

## Crosswalk evidence

The scoped source retains 16 conditional relationships. An adopted STRIDE
assessment can contribute its Kubernetes infrastructure findings to applicable
risk management, evaluation, architecture, development and documentation outcomes.
Collect the actual organizational judgments, asset or component evidence, owner
approvals and reviewed mitigations or treatments for the applicable obligations.
[EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) ·
[NIST AI RMF](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) ·
[NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) ·
[NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final).
