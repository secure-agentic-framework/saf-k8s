# SAF-K8S-0204-001 — Runtime signal scope, loss visibility, and receipt

```sh
python3 lab.py test SAF-K8S-0204-001 --docker-context desktop-linux
```

A restricted Job traces its own child with pinned strace, exercising a file
open, loopback connection, and approved child process execution. The test
observes a deliberately out-of-scope file open and forwards only the three
selected events. An independent Pod receives the batch after an intentional
HTTP 503. The test reconciles event timestamps and counts, receipt, and
Downward API identity against the actual Pod. The workloads use synthetic
markers and keep trace data for unrelated operations out of the evidence.

## Verify deployment applicability and evidence

1. Inventory the governed compute classes and determine which kernel,
   runtime, architecture and provider modes support the chosen collector.
   Reconcile actual ready sensor placement to expected coverage, including
   autoscaled and managed pools. Record alternate evidence and ownership.
2. Verify deployed tool, driver and event configuration, scope and
   privileges. Use harmless expected and out-of-scope fixtures for process,
   file and network events on each applicable class. Retain workload identity,
   source version, timestamps and independently observed output.
3. Exercise configured rate limits, queue health, node or source loss signals,
   deliberate destination failure and recovery. Reconcile event IDs, dropped
   counts and delivery acknowledgements from the chosen receiving system.
   Record the observed resource envelope and alert ownership.
4. Validate the operational retention, sanitization and approved exceptions.
   This fixture exercises an owned child and one event delivery failure.
   Driver/kernel event loss and production-node coverage use their own evidence.

[strace reference](https://manpages.debian.org/trixie/strace/strace.1.en.html) ·
[Kubernetes v1.36 Downward API](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/downward-api/) ·
[Falco kernel event sources](https://falco.org/docs/concepts/event-sources/kernel/)
