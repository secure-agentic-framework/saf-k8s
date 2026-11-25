# SAF-K8S-0303-003 SELinux categories

Run `python3 lab.py test SAF-K8S-0303-003` from the lab directory using the catalog
revision recorded with the verified result. The case persists two inert,
scheduling-gated Pods with different requested MCS levels and reads them back
from Kubernetes. Pod Security Restricted admits an omitted level and rejects
a custom role. A separate restricted Kind Job supplies the observed levels to
a disconnected ARM64 guest with the pinned Debian SELinux reference policy.

Two guest processes receive the observed categories during setup and preserve
their exact process contexts across the transition to enforcing. They can read
their matching synthetic canaries and cannot read each other's despite matching
DAC permissions. Changing only one object category changes both decisions.
Actual kubelet/container runtime labeling, production policy, and CSI volume
behavior need direct SELinux-enabled deployment evidence.

- [Kubernetes security contexts](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes Pod Security Standards](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Red Hat MCS documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/assembly_using-multi-category-security-mcs-for-data-confidentiality_using-selinux)

## Adopter SELinux and storage verification

1. Inventory SELinux-enabled node pools, kernel/runtime and policy revisions, admission settings, workload/namespace identity, requested versus runtime-assigned MCS levels, and applicable storage/CSI types. State the isolation unit and approved sharing rules.
2. On a representative supported node, compare the Pod's admitted `seLinuxOptions` with the actual process label and file/object labels. Reconcile each identity to its workload and node. Record any default or runtime allocation behavior and compare it with the manifest.
3. With an approved inert canary and matching DAC permissions, verify the workload can access its own labeled object and is denied access to a distinct tenant's object. Exercise only the approved sharing case, if any. Capture process/object contexts and attributable SELinux decision records.
4. For each CSI or volume path in scope, verify the actual mount context, relabel behavior, access mode and persistence across Pod replacement or restart. Record provider or storage-driver ownership where the operator cannot observe relabeling.
5. Retain sanitized node/runtime/policy revision, Pod and storage identities, requested/admitted/observed contexts, allowed/denied outcomes, audit-source coverage and exceptions. Recheck after node, runtime, policy, admission, CSI or workload changes and keep unsupported profiles or storage paths explicitly unverified.
