# SAF-K8S-1007-011 — Cluster maintenance sequence and recovery

Run from the SAF-K8S framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-011 --docker-context desktop-linux
```

The digest-pinned, two-node Kubernetes v1.36.1 Kind fixture reads live control
plane, worker and add-on versions. It rejects a kubelet-first plan and evaluates
a synthetic one-minor sequence against the pinned skew constraints. The
`v1.37.0` candidate in the decision receipt is a modeled version. The control
plane and worker remain on v1.36.1 during that planning comparison. The
separate native rehearsal in the same case uses an actual patch transition
from v1.36.1 to v1.36.6.

The native rehearsal uses Linux ARM64 node images and a local target bundle
built from the pinned Kubernetes server archive. On an ARM64 Docker host,
prepare the bundle if it is absent:

```sh
sh tests/control-lab/build-v1.36.6-node.sh /tmp/saf-k8s-v1.36.6-build
```

The builder verifies the official archive SHA-256 and pins its Kind base image.
Set `SAF_UPGRADE_NODE_IMAGE` to use an alternate local name for this verified
bundle. The case checks both binary digests and the four target component
manifest digests before using them. It runs kubeadm dry-run and apply on the
owned control plane, then drains the worker, applies its kubeadm update,
restarts each kubelet with the verified binary, and returns the worker to
scheduling. The fixture observes the API server and both upgraded Node versions,
ready target static components and kube-proxy, available CoreDNS, the unchanged
Kindnet image and a DNS-routed HTTP response
from the unchanged two-backend service. Health is checked at named points.

The case then captures and validates a post-upgrade etcd snapshot before
deliberately changing a harmless ConfigMap. It reuses the owned-cluster
restore routine from SAF-K8S-1005-030 to restore into a new data directory
with a revision bump and compaction. The API returns the original UID and
data, and a fresh client reaches the same Service through the recovered
infrastructure. This data recovery leaves the component binaries at v1.36.6.
The rehearsal uses the existing etcd binary and single-member topology.
The runner deletes its cluster and private staging on completion.

On the owned worker the real Eviction API rejects disruption under the
effective PodDisruptionBudget. After the fixture explicitly permits disruption,
the drain completes. The new workload stays Pending while the node is
cordoned. The exact Pending replacement becomes Ready after uncordon.

A separate workload fixture independently measures HTTP 200 for the stable
release, HTTP 503 for the candidate, and HTTP 200 after reverting to the exact
previous Deployment revision. An observed health response triggers the fixture
decision. The health comparison and worker maintenance produce distinct
evidence. Control plane or node version recovery uses its supported
distribution procedure.

## Verify your implementation

1. Record the current and intended versions and artifacts for each API server,
   controller manager, scheduler, node, kubectl client and relevant add-on.
   Collect live version and Node identity observations for the exact cluster.
   List the CNI, CSI, DNS, admission and accelerator dependencies and their
   supported versions. Determine the supported upgrade path using the target
   distribution or provider runbook and version-specific Kubernetes policy.
2. Document approved sequencing, maintenance owners, capacity and health gates,
   pause and recovery triggers, and the authority for each change. Verify
   skew at each intermediate state against all serving API servers. Include
   mixed-version control-plane limits and one-node-at-a-time disruption where
   required. Record the specific compatibility and version evidence.
3. Rehearse worker cordon, eviction and drain with the real PDBs and scheduling
   constraints in a disposable representative environment. Confirm a prohibited
   disruption blocks. Use an approved maintenance window or capacity plan to
   permit disruption, then verify the exact replacement identity, readiness
   and application health before proceeding. Preserve rollout, readiness and
   volume or accelerator recovery evidence.
4. Rehearse component-specific recovery for an approved simulated failure.
   Restore the exact prior workload or add-on revision where the component
   supports it, replace affected nodes where required, and exercise the
   distribution's supported control-plane recovery. For self-managed etcd
   recovery, test snapshot integrity and recovery per SAF-K8S-0102-008 and
   SAF-K8S-1005-030. For managed clusters use the provider-supported recovery
   or replacement procedure and verify its limits at the exact release.
5. Retain measured pre-change, failed-candidate and post-recovery health,
   exact versions, affected resources, RTO/RPO where applicable, ownership
   and decision records. Repeat the rehearsal after changes to versions,
   configuration or recovery dependencies.

## Official primary sources

- [Kubernetes v1.36 Version Skew Policy](https://v1-36.docs.kubernetes.io/releases/version-skew-policy/) — component skew limits and supported upgrade order for a 1.36 to 1.37 transition.
- [Kubernetes: Upgrading kubeadm clusters](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/) — kubeadm control-plane procedure and upgrade checks.
- [Kubernetes: Upgrading Linux nodes](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/upgrading-linux-nodes/) — control-plane-before-worker guidance, draining, kubelet update, and uncordon sequence.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — publishes the pinned v1.36.1 node image digest used by the lab runner.
- [Docker Official Images: Python](https://github.com/docker-library/official-images/blob/master/library/python) — official-image metadata source for the digest-pinned mock runtime reference.

- [etcd v3.6 disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/) for snapshots, revision bumps and compaction.
