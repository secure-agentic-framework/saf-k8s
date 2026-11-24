# SAF-K8S-0202-012 — Rootless node verification and placement eligibility

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0202-012 --docker-context desktop-linux
```

Run from the SAF-K8S framework root. In the separate validation repository,
run `python3 lab.py test SAF-K8S-0202-012` with the same Docker context and
`--catalog-index catalog/additions/SAF-K8S-0202-012.json`.

Use macOS ARM64 with local rootful Docker, Kind, kubectl, and Lima VZ.
The case creates a pinned Kubernetes v1.37.0 Kind cluster and a second
Kind cluster in its own mount-free Debian ARM64 guest. The guest installs
Podman and runs the second cluster under its dedicated unprivileged user
with delegated IDs and cgroup v2. Both clusters and the guest are removed
after the run. Upstream package and image downloads may be required.

On the ordinary cluster the kubelet reports false and its process has
the initial UID map. A second node with the gate disabled omits the field.
In the Linux guest the kubelet reports true, and
independent kernel observations show the intended maps and the same
noninitial user namespace for kubelet, containerd, kube-proxy, and kindnetd.

The fixture verifies that a separate, node-scoped issuer can manage the
eligibility label and that NodeRestriction denies a node identity's dry-run
request to assign it. An ordinary label provides the positive comparison.
The real scheduler holds the test Pod before eligibility, places it after
corroboration, holds another Pod after simulated evidence expiry, and places
it after fresh evidence is collected. A second withdrawal with missing evidence
holds new placement. A running Pod keeps its original identity and node
through withdrawal.

## Verify your implementation

1. Inventory every node pool claiming rootless operation. Identify the node UID,
   boot ID, kubelet and runtime versions, effective CNI and kube-proxy or its
   replacement, CSI drivers, owner and platform support. Verify the selected
   kernel, delegated cgroup v2, networking and storage prerequisites against
   the current platform's documentation. Include provider limits and approved
   exceptions. Pod-level user namespaces have their own scope.
2. Capture the Node report and Lease using the authorized context.

   ```sh
   kubectl --context "$SAF_CONTEXT" get node "$SAF_NODE" -o json \
     | jq '{uid: .metadata.uid, bootID: .status.nodeInfo.bootID,
            userNamespace: .status.nodeInfo.runningInUserNamespace,
            kubelet: .status.nodeInfo.kubeletVersion,
            runtime: .status.nodeInfo.containerRuntimeVersion,
            ready: [.status.conditions[] | select(.type == "Ready")]}'
   kubectl --context "$SAF_CONTEXT" -n kube-node-lease get lease "$SAF_NODE" -o json \
     | jq '{node: .spec.holderIdentity, renewTime: .spec.renewTime}'
   ```

3. Use an independently authorized host collector in the host's initial user
   namespace. Identify the actual service processes from runtime or service
   inventory. Record their process start identity, namespace links and all UID
   and GID mapping ranges, with the host baseline and subordinate ID allocation.
   Bind the sample to the Node UID, boot ID and timestamp. Validate that
   namespace root maps to approved non-root host IDs for each required process,
   and check that the mappings belong to the intended namespace. For transient
   CNI executables, verify the actual launch namespace with supported host or
   provider telemetry. Where access is delegated to a provider, retain
   equivalent corroboration for the exact platform and node.
4. Use the Node report as one input. A current Lease establishes liveness.
   Collect fresh process evidence to renew eligibility. Set an explicit
   freshness window, reviewed issuer, allowed Nodes and approved label key.
   Check effective Node authorization and NodeRestriction, and verify the
   distinct issuer and its effective permissions. Revoke or hold eligibility
   for stale or absent evidence, Node replacement, meaningful configuration
   change, or expired exception. Retain the issuer decision, evidence versions
   and label transition.
5. In a disposable environment compare scheduler placement before grant,
   after grant, after evidence expiry, and after reevaluation. Find existing
   workloads on nodes losing eligibility and record the applicable policy
   decision. A standard node selector affects new placement. Existing Pod
   remediation uses the adopter's separate workload lifecycle policy.

[Kubernetes v1.37 rootless mode](https://kubernetes.io/blog/2026/09/04/kubernetes-v1-37-rootless-beta/) ·
[Kind rootless providers](https://kind.sigs.k8s.io/docs/user/rootless/) ·
[Kubernetes node isolation and labels](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-isolation-restriction)
