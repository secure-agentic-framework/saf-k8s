# SAF-K8S-0104-007 Emergency maintenance validation

This Kind exercise records a protected drain that stops when the only Ready fixture Pod cannot be evicted. After adding capacity, the worker drains and the workload reschedules. An independent client reads the live HTTP marker through the Service before and after drain. The case uncordons the worker and confirms it accepts a new marker. It checks live runbook gates, rather than installing a software patch. Deployed emergency approvals, platform-specific patching and independent recovery need their own evidence.

The emergency patch example verifies an independently authorized role before
it runs the native patch and recovery sequence. Pending approval and the
executor's attempted self-approval fail. The approved ticket binds the
baseline and target versions and exact target control-plane image. The
actual patch upgrades v1.36.1 to v1.36.6, including both kubelets, and
checks the same DNS-routed Service after the patch and after recovery of
a harmless marker from a post-upgrade etcd snapshot.

The companion [native rehearsal](../SAF-K8S-1007-011/README.md) supplies the
verified ARM64 target-bundle requirements and recovery prerequisites. The
approval identities and trigger are fixture records. The recovery restores
API state on the patched version.

## Verify your implementation

1. Record the incident or maintenance trigger, identified issue and affected
   inventory, exposure and severity, target versions, scope, deadline,
   decision owners and responsible provider or component roles. Retain
   evidence that the authorized request and exact selected change match.
2. Rehearse the approved sequence on representative infrastructure. Include
   service impact, capacity and disruption limits, patch compatibility,
   backups and preflight, and a measurable abort or continue decision.
   Exercise the patch only after the required scoped approval.
3. Observe actual installed component versions and owned service and security
   checks at each boundary. Exercise the supported restoration or forward
   repair. Record diagnosis, measured recovery, validation and remaining
   risks, and notify the designated roles.
4. Preserve the approval and time history, pre-change impact analysis,
   patch provenance, checkpoints, recovery results and follow-up actions.
   Confirm that these records support the portions of the relevant
   remediation requirements that apply to your environment.

- [Kubernetes v1.36 kubeadm upgrade guide](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)
- [NIST SP 800-53 Rev. 5, release 5.2.0](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SSDF v1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
