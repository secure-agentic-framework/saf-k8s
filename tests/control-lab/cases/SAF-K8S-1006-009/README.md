# SAF-K8S-1006-009 Policy decision evidence and export

From the SAF-K8S framework checkout, run with local Docker, Kind, Helm and
kubectl.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1006-009 --docker-context desktop-linux
```

The runner commits two versions of a namespaced fixture policy to local Git
and applies the exact committed bytes. Kyverno v1.20.0 records its Audit-mode
pass and fail in PolicyReports. Kubernetes captures the inert allowed and
denied requests and their exact fixture markers in separate API audit events.
The runner collects the report before applying the Deny revision.

A distinct in-cluster exporter sends the four matched request events, report
snapshot, and policy history to a fixture Service. The receiver rejects the
first export and stores nothing. Once enabled, the receiver accepts exactly one
copy of the full evidence envelope, which the runner reads back and compares.

The case tests the fixture evidence mechanisms and an ephemeral export. Actual
AI workload coverage, production delivery, durable retention, source approval,
and tamper protection require separate evidence.

[Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [Kyverno v1.20.0 release](https://github.com/kyverno/kyverno/releases/tag/v1.20.0)

The revision check reads the live policy, compares its canonical API content with the
approved fixture source, and correlates four audit decisions to matching generations.
The exporter records a failed delivery and retains the staged envelope. It retries
when the fixture receiver recovers and clears the spool only after acknowledgment.
The spool belongs to one Pod. Durable retention and application-specific deployment
coverage require separate evidence.
