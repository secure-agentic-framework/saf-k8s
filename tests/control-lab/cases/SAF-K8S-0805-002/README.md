# SAF-K8S-0805-002 Correlate allocation observations to live workload identity

Run a disposable Kind API server with an audit policy limited to creation of fixture Pods. Advertise a synthetic resource, schedule a Pod, delete it, and schedule a new Pod with the same name. Read both successful creation audit events and join a synthetic allocation observation to the first workload by cluster, namespace, node, Pod UID, container and resource. Missing, wrong-node and conflicting observations remain unresolved and a snapshot has no exact allocation duration.

The test observes scheduler and API behavior. There is no device plugin, hardware, kubelet PodResources socket, external collector, or provider allocation history in the fixture.
