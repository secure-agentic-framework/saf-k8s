# SAF-K8S-0104-013 Kubernetes upgrade and recovery evidence

A disposable kubeadm control plane upgrades from Kubernetes 1.36.1 to 1.37.0, followed by its kubelet. The test verifies the ordered version change and a public marker retained across it. A separate Deployment rollback restores a failed workload rollout on the upgraded cluster. The selected transition skips etcd and certificate upgrades. Deployed control-plane recovery, availability, multi-node sequencing, add-on policy and provider procedures need separate evidence.

Run the same-control rehearsal from the SAF-K8S repository root.

~~~sh
python3 tests/control-lab/lab.py test SAF-K8S-0104-013 --docker-context desktop-linux
~~~

For multi-node patch sequencing, add-on checks, and actual data recovery,
use the [companion patch and recovery rehearsal](../SAF-K8S-1007-011/README.md).
It observes the API server transition before the worker update, then tests both
kubelets, control-plane components, DNS, CNI, and a synthetic Service. It
restores an exercised single-member etcd snapshot while keeping the upgraded
Kubernetes binaries. The minor and patch runs provide distinct evidence for
their respective versions and topologies.

## Verify your implementation

1. Record the release and distribution, source and target versions, control
   plane and worker topology, and versioned runtime, CNI, CSI, DNS, admission,
   and other critical add-on dependencies. Name the owner and recovery
   authority for each boundary, including provider-operated components. Use
   the release-specific distribution and component documentation to confirm
   each proposed transition and intermediate skew. Record maintenance impact,
   pause thresholds, and approval for both routine and emergency changes.
2. Capture authorized, read-only version and health evidence from the exact
   cluster. For example, use the commands below with a named kubeconfig
   context and a kubectl version supported at the sampled stage. Correlate
   each component's observations with the approved change plan and the
   workload probes selected for the affected interfaces.

   ~~~sh
   kubectl --context "$context" version -o json
   kubectl --context "$context" get nodes -o wide
   kubectl --context "$context" get --raw='/readyz?verbose'
   ~~~

3. Rehearse on representative infrastructure. Verify backups before changing
   components, observe the expected version order and available capacity, and
   repeat API, DNS, admission, storage, and application probes wherever the
   change could affect them. Include workload continuity metrics if the plan
   requires availability during the transition. Advance only when the
   predeclared version, health, and disruption thresholds are met.
4. Exercise each applicable recovery path and compare observed recovery time
   and data loss with the approved objectives. Capture before, injected failure,
   and recovered observations. Record the exact workload revision, data
   identity, or service behavior restored. For self-managed etcd, record the
   topology, version, backup identity and integrity, tested restore procedure,
   and recovery checks. For managed components, use the provider's supported
   restore, replacement, or escalation process and retain its evidence. Record
   any recovery path still awaiting exercise.
5. Retain the dated impact analysis for CM-4 and the rehearsal records for
   the in-scope CP-10 recovery boundary. Include platform versions, approvals,
   timestamps, health results, recovery measurements, and unresolved exceptions.

- [Kubeadm upgrade procedure for Kubernetes v1.37](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)
- [Kubernetes v1.36 version skew policy](https://v1-36.docs.kubernetes.io/releases/version-skew-policy/)
- [etcd v3.6 disaster recovery](https://etcd.io/docs/v3.6/op-guide/recovery/)
- [NIST SP 800-53 Revision 5, release 5.2.0](https://github.com/usnistgov/oscal-content/blob/v1.4.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json)

## Versioned user namespace preflight

For the catalog revision containing the user-namespace preflight, the runner
selects the exact patch rehearsal. It starts with the reviewed v1.36.1 Kind
image and applies v1.36.7 and v1.37.3 in order. Official binaries and OCI
component manifests are pinned in `upgrade-pins.json`. Before each change
it reads the owned node's kubelet configuration, effective mapping source,
persisted Pod mappings and relevant events. Unknown or incompatible
observations hold the upgrade before the kubelet is changed.

A restricted non-root `hostUsers: false` canary stays Ready under its
original Pod UID with the same effective UID and GID mappings through the
two transitions. The case also retains the workload marker, verifies the
running kubelet executable digest and API server build metadata, and
rehearses the existing fixture Deployment recovery. The separate legacy
snapshot still selects its original minor-upgrade case.

The published receipt records the exact versions it exercised and the
single-node rehearsal boundary. The adopter must repeat the preflight for
each actual target release and pool. Select applicable provider, add-on,
etcd, certificate and control-plane recovery evidence separately.
