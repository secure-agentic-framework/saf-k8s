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

## Adopter verification

1. Declare expected production audit and AI event sources, stable source identities, required event classes, owners, maintenance windows, and approved source-specific freshness/completeness criteria.
2. Reconcile source-side IDs/counts and timestamps against SIEM arrivals over a representative interval; verify the monitor distinguishes a missing feed from partial in-flight loss.
3. In an approved staging route, generate benign missing-source and partial-loss conditions, confirm deployed detections identify the affected source, and observe the routed operations alert and analyst disposition.
4. Restore the source/route and confirm health returns only after expected records resume. Preserve source and sink evidence, rule/config version, alert timestamps, and closure record.
5. Keep retention, high availability, sustained-load coverage and incident response outside the narrow fixture claim unless separately evaluated.

The test observes actual Kubernetes Warning Events for a missing source and partial delivery, no warning for the complete baseline, and a recovery event after the expected records return. Retain the adopted alert destination and response as separate evidence.

[NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
