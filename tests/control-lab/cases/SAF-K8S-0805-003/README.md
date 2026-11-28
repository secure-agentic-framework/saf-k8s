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

The A100 replay submits the same inert escalation before and after binding.
It waits for the named policy and binding to reject that request, then retains
and reads back the exact immutable hold. The reviewer cannot create or patch
the separate approval. A distinct identity creates the immutable approval
used by the binding. The lab independently reads back the exact record. The replay submits the exact comparison record
using server dry-run. Self-asserted corroboration and changes to
the run, hold, workload, device or source digest are denied by the same
named policy. The comparison record remains absent and the hold survives
fixture cleanup.

The A100 admission replay uses synthetic ConfigMaps. It covers that policy
and identity boundary without allocating GPU memory or performing a workload
action. The approval is scoped to this run. Wall-clock expiration and
production approval provenance are outside the test's evidence.
See `a100-admission-replay.json`.

The [live A100 telemetry reference](../SAF-K8S-1002-003/a100-reference/README.md)
records the source signal for the observed hold. The repeat test of the live
escalation decision remained open after Spot preemption.

## Live A100 reference

The A100 run bound the same CUDA workload, GPU, and exporter throughout the
test. Direct GPU telemetry and Prometheus both reported 556 MiB against the
128 MiB threshold. Alertmanager delivered the warning and the case stored an
immutable hold. Kubernetes denied escalation without independent approval.
The independently approved comparator passed in dry-run and remained absent
from storage. The original workload kept running and returned to its initial
0 MiB reading after the allocator released memory.

[Reviewed live receipt](a100-hold-reference.json) ·
[Case-by-ID hardware replay](../../references/gcp-a100/campaign/README.md)
