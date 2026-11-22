# SAF-K8S-0304-003 — QoS class assignment for workload stability

Run from the control lab directory on a local Docker context.

```sh
python3 lab.py test SAF-K8S-0304-003 --docker-context desktop-linux
```

The runner uses a fresh kind Kubernetes v1.36.1 cluster. The original control and
its revised wording are tracked by `saf-lab-0304-003` and
`saf-lab-ra86d379016c3b4b45c73`. The framework retains
`verified/SAF-K8S-0304-003.json` with the exact tested catalog revision.

| Check | Observation |
| --- | --- |
| Baseline | The critical fixture reaches Running with BestEffort QoS before admission policy is applied. |
| Enforcement | A case-scoped ValidatingAdmissionPolicy rejects the same critical Pod shape in a server dry run. The ordinary BestEffort fixture remains admissible. |
| Assigned QoS | Live Pods report Guaranteed, Burstable, or BestEffort from their applicable CPU/memory specifications. The init-container case is Burstable and the Pod-level case is Guaranteed. |
| Storage and CPU | A Guaranteed Pod retains unequal ephemeral-storage request and limit. Its idle container has an active Linux CPU quota matching its declared limit. |

The fixture policy applies to a dedicated label in the disposable namespace.
In production, choose the critical workload designation and control who can set
it. Validate the applicable resource budgets and inspect admitted `status.qosClass`.
The case reads the CPU quota without creating pressure. Kubelet memory-pressure
ranking considers use relative to requests and Pod Priority. Production sizing,
eviction behavior, admission coverage, pressure telemetry and exceptions are
tracked in `saf-lab-0304-003.2`.

- [Kubernetes v1.36 Pod QoS classification](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/pod-qos/)
- [Kubernetes v1.36 requests, limits and CPU throttling](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes v1.36 node-pressure eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/)
