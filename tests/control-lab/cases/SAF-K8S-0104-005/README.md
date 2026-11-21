# SAF-K8S-0104-005 — Synthetic metadata-only permission audit

Run through the lab harness:

```sh
python3 lab.py test SAF-K8S-0104-005
```

The standard harness provisions an isolated kind cluster. The case copies only its
own fixtures into a temporary directory and checks metadata for this fixed,
case-owned allowlist of public kubeadm-style node paths:

| Synthetic path under `node-root/` | Expected type | CIS Kubernetes Benchmark 2.0 reference |
| --- | --- | --- |
| `etc/kubernetes/manifests/kube-apiserver.yaml` | regular file | 1.1.1–1.1.2 |
| `etc/kubernetes/manifests/kube-controller-manager.yaml` | regular file | 1.1.3–1.1.4 |
| `etc/kubernetes/manifests/kube-scheduler.yaml` | regular file | 1.1.5–1.1.6 |
| `etc/kubernetes/manifests/etcd.yaml` | regular file | 1.1.7–1.1.8 |
| `etc/kubernetes/admin.conf` | regular file | 1.1.13–1.1.14 |
| `etc/kubernetes/controller-manager.conf` | regular file | 1.1.16, 1.1.18 |
| `etc/kubernetes/scheduler.conf` | regular file | 1.1.15, 1.1.17 |
| `etc/kubernetes/pki/etcd/ca.key` | regular file | 1.1.19, 1.1.21 |
| `var/lib/etcd` | directory | 1.1.11–1.1.12 |

The audit uses `lstat` on those exact paths. It does not enumerate or traverse
the synthetic tree, follow symlinks, open fixture files, inspect their contents,
or inspect paths outside that fixture during the red and green checks. Fixture text is a
public marker, not a kubeconfig credential, manifest copied from a node, key, or
etcd data. Every `chmod` is applied only to the temporary fixture copy.

The red observations confirm detection of the deliberately permissive copied
fixture metadata and a mismatched synthetic owner expectation. The green
observation checks all nine allowlisted path types, modes, and numeric owner/group
IDs after tightening fixture-copy modes. The positive observation accepts a
synthetic kubeconfig with a stricter mode. Numeric IDs are inherited from the
case-created fixture and used only to exercise equality checking; they do not
claim that production files are `root:root` or the etcd directory is
`etcd:etcd`. A read-only node probe also measures mode, UID, GID, and type at the same
exact stock kind paths. It opens no file body and changes no node file. The
reference mode checks and observed ownership are separate results. The stock
kind etcd directory reports UID and GID 0, which provides no production
`etcd:etcd` attestation.

## Provenance and claim review

Pinned catalog: `catalog/index.json` points to framework commit
`133a8698a45e2b335b51728bf4c62f7bda98d15f`; current checkout's control markdown
was also read at `../saf-k8s-framework/markdown/controls/SAF-K8S-0104-005.md`.
The pinned catalog control digest is
`d42e824e15a3f427c69a62bd108a0bce53b5faf1040cc9b51ef2875440939a50`.
The statement claims ownership and permission enforcement on manifests,
kubeconfigs, certificate key material, and etcd data, plus provisioning-time
and recurring verification.

For an independent mode/path cross-check, the lab's standard harness pins
kindest/node v1.36.1. kube-bench's current platform table and version map cover
CIS 2.0 through Kubernetes 1.35 and contain no 1.36 mapping, so this case does
not claim version-matched CIS validation for 1.36.1. The rules below are
reference points only, not a claim that CIS 2.0 is the applicable benchmark for
that image. kubeadm's versioned documentation independently supports the
representative manifest, kubeconfig and PKI path conventions used here.

- CIS 2.0 control-plane static manifests: mode `0600` or tighter and owner
  `root:root` (1.1.1–1.1.8).
- Administrative and component kubeconfigs: mode `0600` or tighter; ownership
  `root:root` for admin, scheduler and controller-manager kubeconfigs (1.1.13–1.1.18).
- PKI directory and files: `root:root`; certificate modes at most `0644`; key
  modes `0600` (1.1.19–1.1.21). This case includes one synthetic key path only.
- The active etcd data directory is mode `0700` or tighter and owner `etcd:etcd`
  (1.1.11–1.1.12). The fixture represents only the directory metadata.

**Claim validity:** partially supported by the benchmark specification for the
selected representative metadata rules; the control's environment-wide and
operational claim remains unverified. This implementation checks only metadata
logic on copies and does not show that production nodes enforce these values.

The CIS auditor selects some paths through runtime configuration, `--data-dir`,
or directory scans; this case intentionally checks only the exact allowlist
above. Provisioning enforcement, completeness of host paths, owner-name mapping,
PKI-wide checks, actual control-plane node state, managed-service responsibility,
and recurring schedule evidence remain unverified. Recurring schedule proof is a
separate control obligation and requires schedule/configuration plus retained
execution evidence; a one-time synthetic pass cannot establish it.

### Primary references

- [Pinned SAF-K8S-0104-005 control markdown](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0104-005.md)
- [kube-bench CIS Kubernetes benchmark support](https://github.com/aquasecurity/kube-bench/blob/main/docs/platforms.md)
- [kube-bench CIS 2.0 control-plane file checks](https://github.com/aquasecurity/kube-bench/blob/main/cfg/cis-2.0/master.yaml)
- [kube-bench CIS 2.0 etcd checks](https://github.com/aquasecurity/kube-bench/blob/main/cfg/cis-2.0/etcd.yaml)
- [kube-bench path and benchmark configuration](https://github.com/aquasecurity/kube-bench/blob/main/cfg/config.yaml)
- [Kubernetes v1.35 kubeadm implementation details](https://v1-35.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/)
- [Kubernetes v1.35 kubeadm certificate and kubeconfig paths](https://v1-35.docs.kubernetes.io/docs/setup/best-practices/certificates/)
