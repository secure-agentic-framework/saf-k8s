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
| Enforcement | A case-scoped ValidatingAdmissionPolicy rejects critical BestEffort, multi-container (one container lacks a budget), and non-Guaranteed init-container shapes in server dry runs. The ordinary BestEffort fixture remains admissible. |
| Assigned QoS | Live Pods report Guaranteed, Burstable, or BestEffort from their applicable CPU/memory specifications. The init-container and multi-container cases are Burstable; the Pod-level case is Guaranteed. |
| Storage and CPU | A Guaranteed Pod retains unequal ephemeral-storage request and limit. Its idle container has an active Linux CPU quota matching its declared limit. |

The fixture policy applies to the critical workload label in its own namespace.
The API server sets `status.qosClass` on a Pod at creation. A server dry run can
show its value and the admission decision. Separate live probes verify Ready
containers and the configured CPU quota. The label-update sample checks the
same policy for a Pod newly designated critical.

## Verify your implementation

1. Inventory the workload classes handling sensitive data, security functions,
   or stateful services. Use a controlled source for classification and restrict
   who can change it. Record the rules and scopes covering created and updated
   Pods, controllers and any approved exceptions.
2. Check equal, positive CPU and memory requests and limits for every regular
   and init container, or equivalent Pod-level values if supported and enabled.
   Use approved, measured budgets. Test admission with a conforming critical
   request, a weaker critical request, and an ordinary exception where allowed.
   On an admitted running Pod, inspect `status.qosClass`, readiness and actual
   resource configuration.
3. Check usage relative to requests, Pod Priority, and resource-specific
   pressure thresholds and eviction events. Inspect CPU throttling and readiness
   over a representative load window. Guaranteed QoS can still experience
   throttling and eviction. These fixtures read an active CPU quota and apply no
   node pressure. GPU hardware is unnecessary for this CPU and memory check.

- [Kubernetes v1.36 Pod QoS classification](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/pod-qos/)
- [Kubernetes v1.36 requests, limits and CPU throttling](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes v1.36 node-pressure eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/)
- [Kubernetes v1.36.1 Pod API create strategy](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/registry/core/pod/strategy.go)
