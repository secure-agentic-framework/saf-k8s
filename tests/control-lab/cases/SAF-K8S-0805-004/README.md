# SAF-K8S-0805-004 Accelerator placement eligibility

Run from the SAF-K8S checkout with Docker, Kind, kubectl, Python, and Helm.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0805-004 --docker-context desktop-linux
```

Kind runs two nodes with distinct modeled accelerator profiles. Native
admission denies unapproved placement, and the scheduler binds eligible
Pods to their approved nodes.

The exception check uses the pinned Kyverno admission consumer and its live
clock. The fixture requires an immutable approval from the named approver and
binds it to the exact requester, Pod, and sharing profile. It submits the
same server-side dry-run request before and after expiry. The consumer
admits the request inside the approved window and denies it after the window
while the stored approval stays the same. An ordinary eligible placement
remains admissible. The lab receipts include the API-server clock
observations and both policy diagnostics.

The modeled-profile checks cover admission, scheduling, and expiry.
Actual GPU isolation and protected inventory require hardware evidence.

A separate namespace exercises the admission logic used by the physical MIG
runner. Before policy installation, a server dry-run of the marked whole-GPU
request succeeds. The installed binding must then return the named Forbidden
decision for that exact request. The approved MIG limit and an unmarked
whole-GPU request pass server dry-run. The probe also confirms the workloads
were never persisted. `mig-profile-admission.json` records the observed
results. This check exercises Kubernetes admission without allocating devices.
