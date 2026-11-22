# SAF-K8S-0201-008 — Kubelet file metadata review

Run through the control lab harness:

```sh
python3 lab.py test SAF-K8S-0201-008 --docker-context desktop-linux
```

## Provenance

| Field | Evidence |
| --- | --- |
| Original catalog control | [`SAF-K8S-0201-008.md` at catalog/framework commit `133a8698a45e2b335b51728bf4c62f7bda98d15f`](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0201-008.md) |
| Current framework control read for this review | `../saf-k8s-framework/markdown/controls/SAF-K8S-0201-008.md`, framework checkout `ed8c075e7d2fe644ba0917e0362dd94e51878f83` |
| Original catalog record digest | `e2870408e7ea5a280c731018ac220345b884eac77f9c148eb24153a8914cef81` from the parsed record in `catalog/index.json` |
| Reviewer and date | Local review on 2026-11-21 |
| Tested platform, Kubernetes version, runtime, and add-ons | Pinned kindest/node v1.36.1. See `verified/SAF-K8S-0201-008.json`. |
| Primary references | Kubernetes v1.36 documentation and Kubernetes source tag v1.36.1, linked below |

The catalog statement requires root ownership and maximum modes of `0644` for
configuration and `0600` for private keys. The upstream references below document
the kubelet/kubeadm paths and which kubeconfig material contains credentials. They
do not define one universal UID, GID, or POSIX mode for every path or node image.
This case therefore treats the catalog's UID and mode limits as the claims under
review. It records numeric GID for evidence but does not assume group `root`; the
required group and group-access policy need an organization-specific baseline.

## Review obligations and evidence

| Catalog obligation | Case evidence | Boundary |
| --- | --- | --- |
| Kubelet configuration file ownership and mode | Read-only `stat -L` of `/var/lib/kubelet/config.yaml`; assert UID 0 and no bits beyond `0644`. | One required path on the harness control-plane node. |
| Kubelet kubeconfig and bootstrap credential protection | Read-only metadata for `kubelet.conf` and, when present, `bootstrap-kubelet.conf`; classify both as credentials with a `0600` ceiling. | Upstream documents the embedded authentication key and bootstrap lifecycle; the bootstrap file can be absent after enrollment. |
| Active kubelet client certificate/key | Read-only `stat -L` of `kubelet-client-current.pem` when present, recording target metadata and applying the credential ceiling. | The active pointer is a representative path; this is not a recursive audit of the certificate directory. |
| Permission rule has meaningful red/green cases | Harmless temporary local files model an over-permissive credential, the catalog ceiling, and stricter modes. | Fixture bodies contain only a public marker and are never read; no node file is modified. |
| Root ownership claim | Collect numeric UID/GID for each present allowlisted node file; require UID 0 on the three required node paths. | This does not resolve usernames, GID policy, ACLs, or access through mounts/capabilities. |

The only node operation is `stat -L -c '%F|%u|%g|%a'` against the fixed paths in
[`fixtures.json`](fixtures.json). The case never opens or prints credential or
configuration contents. It does not run `find`, inspect process arguments, change
permissions, or broaden access on real node files. Synthetic mode checks operate
only on temporary local files created by this case.

The allowlist includes kubeadm's standard kubelet config, instance config, flags
file, kubelet kubeconfig and optional bootstrap/client-certificate paths. Paths
not present are reported as absent; missing required paths fail the node check.
Every present allowlisted path must satisfy the root UID and category mode ceiling;
missing optional paths are recorded without treating absence as a failure. A pass
cannot establish the control's whole-directory or every-node claim, a recurring
audit schedule, node image provisioning, group policy, provider attestation, ACL
behavior, or whether an escaped workload can reach host files. Those require
separate system evidence.

## Primary versioned upstream references

- [Kubernetes v1.36 local files and paths used by the kubelet](https://v1-36.docs.kubernetes.io/docs/reference/node/kubelet-files/) — configuration path, certificate directory and configurable locations.
- [Kubernetes v1.36 kubeadm implementation details](https://v1-36.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/) — standard kubeconfig and PKI paths; bootstrap and client credential lifecycle; generated kubeconfigs contain embedded authentication keys.
- [Kubernetes v1.36 kubeadm kubelet integration](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/kubelet-integration/) — kubeadm writes `/var/lib/kubelet/config.yaml` and its node instance configuration.
- [Kubernetes v1.36.1 kubeadm path constants](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kubeadm/app/constants/constants.go) — versioned source for the kubelet runtime directory and well-known configuration filenames.

The retained passing result contains the node metadata and synthetic mode
checks. A rerun writes its full result and command transcript under `evidence/`.
