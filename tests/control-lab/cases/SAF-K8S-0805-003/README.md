# SAF-K8S-0805-003 accelerator incident review

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0805-003 --docker-context desktop-linux
```

The case tests Kubernetes RBAC and admission with synthetic incident
records. It rejects escalation with inadequate evidence or an unauthorized
reviewer. An approved decision allows only the named reviewer to scale an
inert fixture Deployment. The comparator remains available.

The historical check uses the two T4 framebuffer captures from
`SAF-K8S-1002-003`. Each run recorded 0 MiB idle and 232 MiB after a
deliberate allocation in the known-good fixture. The case checks the
source summary and receipt digests and preserves each pseudonymous workload
reference and capture interval in an immutable hold record.

Admission denies a dry-run escalation for either recorded allocation,
even when the named reviewer submits it. Both records describe approved
fixture workloads with missing independent corroboration. The test also
checks that the comparator retains its UID and readiness. Live freshness,
incident attribution, and production response require further evidence.

The original and historical scenarios account for five checks. The historical triage artifact is
`historical-t4-triage-hold.raw.json`. [T4 reference summary](https://github.com/secure-agentic-framework/saf-k8s/blob/23a8b7a4be1fec186b4138fc30e12ab0964e33b9/tests/control-lab/cases/SAF-K8S-1002-003/t4-reference/reference-result.json)

The A100 admission replay submits the same inert escalation before and after
binding. After installation, it waits for the named policy and binding to
actually reject that request, confirms a valid hold is admitted, then retains
and independently reads back the immutable hold. A second escalation denial,
an exact NotFound read, and an accepted corroborated dry-run comparator finish
the replay. The two added checks use synthetic input and do not use GPU hardware
or perform workload actions. See `a100-admission-replay.json`.

The [live A100 telemetry reference](../SAF-K8S-1002-003/a100-reference/README.md)
records the source signal for the observed hold. The repeat test of the live
escalation decision remained open after Spot preemption.
