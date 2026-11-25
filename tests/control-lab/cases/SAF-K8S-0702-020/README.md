# SAF-K8S-0702-020 — Namespace ResourceQuota for accelerator workloads

A Kubernetes v1.36.1 kind namespace starts with a limits-prefixed entry for
a synthetic accelerator. The API stores that quota object and still admits
the over-budget dry-run declaration. Replacing it with a requests-prefixed
quota makes the same declaration fail. The NVIDIA GPU resource name uses
the same request accounting. An at-budget accelerator declaration is
admitted only as a dry-run.

The runnable test independently exercises CPU and memory request and limit
quotas, PVC storage requests, and Pod, PVC and Service counts. It leaves one
bounded Pod Ready. Accelerator scheduling, device health, scope selectors,
and policy rollout across training namespaces require separate evidence.

```sh
python3 lab.py test SAF-K8S-0702-020 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Kubernetes v1.36 ResourceQuota](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/#quota-for-extended-resources)
- [Kubernetes v1.36 GPU device resources](https://v1-36.docs.kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/)

## Adopter verification

1. Inventory each enrolled AI/accelerator namespace, its owner and workload
   selectors. Record the quota and rollout owner and verify the quota exists
   before admitting tenant workloads.
2. On each cluster, record the actual device-plugin advertised GPU/MIG resource
   names and node health/capacity. Compare these with quota keys and the
   workload request fields. Use the advertised resource name.
3. Validate effective ceilings for accelerator, CPU, memory, storage and
   object counts using approved non-production dry-runs or bounded synthetic
   workloads. Capture one allowed at-limit request and one over-limit denial
   for each relevant resource, plus observed quota status/usage.
4. Check approved scope selectors and policy coverage across existing and new
   training namespaces. Document selector owners, exceptions, rollout timing,
   and separate LimitRange defaults from ResourceQuota enforcement.
5. Retain dated device health/capacity, quota inventory, admission results,
   utilization monitoring and remediation, and repeat after device-plugin,
   namespace, workload or quota-policy changes.

**Portable evidence:** current digest `a062cd95f6a93938db8ffb4752b79e2f884041ca690bfa156e4088fcdd841c36`
matches the passed **13-check** receipt, catalog revision
`948824b695442ac07ffd3bfcc0b84a66ef9c79de`; paired lab/framework runs are in
Beads and both clusters were deleted. The fixture covers Kind v1.36.1
admission for synthetic GPU and dummy accelerator names, CPU/memory/storage
requests and limits, Pod/PVC/Service counts, and verifies quota status; it
does not observe a device plugin, real accelerator health/scheduling, training
namespace selector coverage or rollout. Those are adopter evidence.
