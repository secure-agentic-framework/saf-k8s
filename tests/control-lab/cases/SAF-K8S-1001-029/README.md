# SAF-K8S-1001-029 — Ingestion coverage and completeness

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-029 --docker-context desktop-linux
```

Digest-pinned Fluent Bit 5.1.2 tails two structured fixture files in a
disposable Kubernetes cluster and forwards both to a case-owned HTTP sink.
The runner reconciles each source's expected IDs against the sink's records.

Both sources deliver their exact events in the baseline. Omitting the AI
fixture file creates a missing-source result. Supplying both complete
files and installing a scoped Fluent Bit filter removes one specific event
in transit. The sink distinguishes that partial delivery from a missing
source and sees both complete feeds again after the filter is removed.

The case uses synthetic Kubernetes-audit and AI-event records.
Actual audit and AI event production, sustained completeness and freshness
monitoring, production SIEM routing, and alert delivery require separate
evidence.

- [Fluent Bit 5.1 Tail input](https://docs.fluentbit.io/manual/5.1/data-pipeline/inputs/tail)
- [Fluent Bit 5.1 HTTP output](https://docs.fluentbit.io/manual/5.1/data-pipeline/outputs/http)
