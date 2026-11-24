# SAF-K8S-0201-008 Kubelet file ownership and permissions

From the framework root, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0201-008 --docker-context desktop-linux
```

The case uses Kubernetes v1.34.8 and kube-bench v0.16.0 with the CIS 1.12 node profile.
It reads only three file arguments from each running kubelet. On the control-plane
and worker nodes, the scanner checks the active configuration and an empty synthetic
kubeconfig at separate read-only mounts. The stock configuration fails 4.1.9 at
`0644`. The empty kubeconfig fails 4.1.5 and 4.1.6 with `0644` and a non-root
owner. The test tightens the real configuration to `0600`, fixes the synthetic
file and repeats the same four checks on the same files with fresh scanner Jobs.
The evidence includes matching file identities, the config ownership check,
node readiness, scored results, and scanner identity.

Each actual kubeconfig stays untouched and is checked from the node using file
metadata. The fixture verifies that the enrolled nodes have no bootstrap
kubeconfig and that the stock kubeadm client credential link points to a protected
target within the expected directory. The runner retains metadata only. The lab
uses kubeadm paths, one control-plane node and one worker.

## Verify your implementation

1. Inventory applicable node pools, node OS and image versions, Kubernetes
   releases and the approved distribution-specific benchmark or equivalent
   baseline. Record which components and nodes the provider operates.
2. Derive the active `--config`, `--kubeconfig`, and conditional
   `--bootstrap-kubeconfig` paths from the effective service arguments or an
   authorized provider export. Capture only the selected paths. Include other
   effective configuration sources and the relevant credential references.
3. Check file type, numeric ownership, mode, ACLs and parent-directory access
   with approved read-only tooling. On Linux, `stat`, `readlink`, and
   `getfacl` can report the metadata. Record both the link and resolved
   target for rotating credentials, including boundaries on which directories
   can contain the target and who can change the link or its ancestors. Use
   approved provisioning metadata to establish credential references and avoid
   retaining kubeconfig, certificate or key contents.
4. Apply the selected profile to each file class. For CIS 1.12, the active
   configuration and kubeconfig use mode `0600` or more restrictive and
   `root:root` under 4.1.5, 4.1.6, 4.1.9 and 4.1.10. Preserve the kubelet's
   required read access. Assess client CA certificates under their own rules.
   Use credential protections while bootstrap is active. On kubeadm, absence
   of the temporary bootstrap kubeconfig is expected after enrollment.
5. Collect dated provisioning and recurring scan results by pool, node and
   effective path. Keep the applicable version and profile, tool, observed
   metadata, assessment result and any remediation or approved exception.
   Retest dated changes, including node-image revisions. For provider-operated
   scope, retain service and pool-specific evidence covering equivalent
   protections or record the unresolved verification gap.

File metadata supports CM-5 access restrictions and CM-6 configuration settings.
Approval and enforcement of change access, permitted deviations and ongoing
monitoring require their own operating records.

- [Kube-bench v0.16.0 CIS 1.12 node checks](https://raw.githubusercontent.com/aquasecurity/kube-bench/v0.16.0/cfg/cis-1.12/node.yaml)
- [Kubernetes v1.34 kubelet paths](https://v1-34.docs.kubernetes.io/docs/reference/node/kubelet-files/)
- [Kubeadm v1.34 node bootstrapping](https://v1-34.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/#tls-bootstrap)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

The runner retains the older mode evaluator for historical catalog replays.
Its `0644` assumption is the finding corrected by the current case.
