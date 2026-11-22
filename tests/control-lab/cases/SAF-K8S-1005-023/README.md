# SAF-K8S-1005-023 — GPU-aware node containment and quarantine

This case is a draft for the lab supervisor's two-run verification on a fresh,
disposable Kind Kubernetes v1.36.1 cluster. `case.py` uses the lab's existing
`saf-test` namespace and the digest-pinned Kind node image recorded in the
lab's runner. It creates only uniquely named case resources and reads only
those resources plus the selected disposable node.

The fixture labels one Kind node with synthetic accelerator inventory metadata.
It does not assert that Kind has a GPU, install a device plugin, request an
accelerator resource, execute inference, use model data, or connect to a feed
or target. Its digest-pinned Docker Official Python container only sleeps.
There are no credentials or Kubernetes Secret reads. All incident IDs and
forensic markers are reserved synthetic placeholders.

## Observable outcomes

- **Red baseline:** before quarantine, a synthetic Pod selected by the fake
  accelerator label becomes Running on the target node. The mock workload is
  Ready and the PDB reports zero allowed disruptions for its single replica.
- **Green quarantine and hold:** the runner captures raw baseline node, Pod,
  and PDB readbacks, then cordons and adds a case-specific `NoSchedule` taint
  to that disposable node. A second non-tolerating, label-selected probe stays
  Pending; the existing mock Pod remains. The Eviction API rejects one
  voluntary eviction while the PDB's `disruptionsAllowed` remains zero.
- **Positive evidence preservation:** before the eviction attempt that marks
  the simulated handoff boundary, the case writes the decision and observed
  API objects into an immutable ConfigMap and reads it back. It verifies that
  record again after the hold and stores raw post-boundary API readbacks.
  No external handoff occurs, and there is no direct-delete or force-drain
  fallback.

The runner also retains its standard command transcript and per-check result.
Case raw evidence is written as `pre-quarantine.raw.json`,
`pre-handoff-evidence.raw.json`, `eviction-hold.raw.txt`, and
`post-handoff-observations.raw.json`. These records contain Kubernetes object
metadata for the disposable case, fixture markers, and the API's eviction
response; they do not contain Secret data, tokens, or credential material.

## Source basis and control review

Kubernetes documents that marking a Node unschedulable prevents new Pods from
being scheduled there without removing existing Pods. Taints with `NoSchedule`
likewise repel new Pods that do not tolerate the taint. Kubernetes documents
that `kubectl drain` uses eviction for Pods it removes, and that a PodDisruptionBudget
can reject voluntary eviction when the budget would be violated. The Eviction
API documents HTTP 429 for an eviction disallowed by the configured PDB. This
case observes these API mechanics directly on a disposable cluster.

Primary sources:

- [Kubernetes Nodes: manual administration and unschedulable nodes](https://v1-36.docs.kubernetes.io/docs/concepts/architecture/nodes/#manual-node-administration)
- [Kubernetes Taints and Tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/)
- [Kubernetes Safely Drain a Node](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/)
- [Kubernetes Pod Disruption Budgets](https://v1-36.docs.kubernetes.io/docs/tasks/run-application/configure-pdb/)
- [Kubernetes API-initiated Eviction](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/api-eviction/)
- [Kubernetes Node API reference](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/core/node-v1/)
- [Kind v0.32.0 release and v1.36.1 node image digest](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)
- [Docker Official Python 3.13 slim image digest listing](https://hub.docker.com/layers/library/python/3.13-slim/images/sha256-e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90)

The pinned control requires documented, AI-specific containment procedures
that balance evidence preservation with disruption to co-scheduled AI work.
The API mechanics here do not show that an organization has such a playbook,
that incident authority or escalation is defined, or that response decisions
are coordinated. The PDB is a fixture safety limit and the ConfigMap is a
readback check; neither demonstrates durable, access-controlled, tamper-evident
forensic storage or operational chain of custody.

## Coverage boundary and unresolved claims

This case covers synthetic scheduling quarantine, one workload's PDB-limited
voluntary eviction, preservation/readback of fixture metadata before a
simulated handoff, and retention of the node/workload state afterward. It does
not run `kubectl drain` to completion, test drain concurrency or rate limits,
exercise multiple co-scheduled workloads, or establish whether the pending
probe is serviceable elsewhere. It does not validate GPU device-plugin state,
GPU process termination, hardware reset/isolation, node-level forensic capture,
real checkpoint generation/consistency, checkpoint restore, workload-specific
preStop behavior, training-state integrity, service availability or customer
impact.

Real GPU-aware drain and checkpoint behavior therefore remains unresolved.
Production evidence is still required for the approved containment playbook,
node/GPU inventory and process-to-workload mapping, safe drain and eviction
limits, workload-specific checkpoint and recovery validation, evidence custody
and retention, decision approvals, and measured impact on unaffected workloads.
A passing synthetic run is evidence only for the recorded Kind API observations;
it is not evidence of production implementation or control effectiveness.
