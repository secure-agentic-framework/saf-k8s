# SAF-K8S-0304-010 — Requests and limits

From the framework root, run the check on a disposable Kind cluster.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0304-010 --docker-context desktop-linux
```

The input checker verifies that the raw Pod JSON declares CPU, memory and
local ephemeral-storage requests and limits for each regular and init
container. Native admission verifies the effective fields. It rejects absent
declarations and accepts a limit-only input when the API has already filled
in the request. The positive case runs with the explicit declarations and
reads the 500m CPU quota and 256 MiB memory ceiling from Linux cgroups. The
probe applies no CPU, memory or storage pressure.

A pinned Kubernetes sample device plugin inside the disposable Kind node
registers two synthetic resource units. The conditional admission example
denies missing or wrong resource keys on creation, and denies a server-dry-run
update designating an ordinary Pod as accelerator-required. The kubelet hands
out two distinct synthetic markers. A third request stays Pending with the
expected insufficient-resource reason. The fixture only uses the Kind node's
private kubelet plugin socket and synthetic markers.

## Verify your implementation

1. Check every rendered workload template before defaulting. Verify approved
   quantities and all applicable regular and init containers. Review the
   issued Pod independently to see any API or namespace policy defaults.
2. Verify the admission policy with complete, incomplete, defaulted and
   exempt samples. Check the policy bindings and errors on the cluster's
   API version. Use a trusted source for accelerator-required workload
   classification.
3. Measure actual workloads to choose resource values. Compare requests with
   applicable node capacity, overhead and reservations. Verify CPU throttling
   and memory enforcement on Linux, and confirm kubelet local storage
   accounting and eviction behavior for the platform in use. Retain the
   authored and admitted fields, runtime observations and workload evidence.
4. For a device-plugin allocator, confirm the supported driver/runtime
   combination and the device resource key. Verify an intended workload
   schedules, receives the expected physical device and completes a safe
   workload smoke test. The synthetic fixture verifies generic device-plugin
   admission and allocation behavior. Physical accelerator results require
   hardware.
5. Where the EU AI Act Article 13 instructions obligation applies, use
   verified workload measurements as an input to the provider's compute
   and hardware disclosures. Expected lifetime and maintenance need
   system-level evidence.

- [Kubernetes v1.36 requests and limits](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Kubernetes v1.36 validating admission](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes v1.36 device plugins](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/)
- [European Commission Article 13 text](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-13)
