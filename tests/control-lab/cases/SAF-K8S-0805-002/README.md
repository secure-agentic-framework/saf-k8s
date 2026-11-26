# SAF-K8S-0805-002 Correlate allocation observations to live workload identity

Run a disposable Kind API server with an audit policy limited to creation of fixture Pods. Advertise a synthetic resource, schedule a Pod, delete it, and schedule a new Pod with the same name. Read both successful creation audit events and join a synthetic allocation observation to the first workload by cluster, namespace, node, Pod UID, container and resource. Missing, wrong-node and conflicting observations remain unresolved and a snapshot has no exact allocation duration.

The test observes scheduler and API behavior. There is no device plugin, hardware, kubelet PodResources socket, external collector, or provider allocation history in the fixture.

## Native scheduler allocation and reservation

A separate check advertises a case-owned inert device in a `resource.k8s.io/v1` ResourceSlice. The Kubernetes scheduler must allocate the matching ResourceClaim and reserve it for the exact scheduled Pod UID. The harness independently reads the Pod, ResourceClaim and source ResourceSlice. It then recreates the Pod and claim under the same names and checks both new UIDs and the replacement's own reservation. The harness reads the scheduler-produced status and never writes it.

Four checks passed in each of two independent disposable Kind v1.36.1 clusters. The result records the scheduler behavior for an inert advertised resource. For device delivery, verify the adopted device plugin or DRA driver and actual resource identifier and allocation on the selected node. Correlate the authoritative observation to the cluster, namespace, node, Pod UID and applicable container or claim. Preserve protected timing and retention evidence and report absent or ambiguous records as such.

From the framework checkout, run `python3 tests/control-lab/lab.py test SAF-K8S-0805-002 --docker-context desktop-linux`. See [Kubernetes v1.36 Dynamic Resource Allocation](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/).
