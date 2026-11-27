# SAF-K8S-1007-015 — GPU node onboarding security baseline validation gates

This case checks a bounded GPU-node baseline decision on a fresh disposable
Kind v1.36.1 cluster. It preserves the six existing assertions and adds one
OS-version counterfactual that rejects a wrong or missing release ID before
the case removes its hold taint.

```sh
python3 lab.py test SAF-K8S-1007-015 --docker-context desktop-linux
```

The runner uses a fresh disposable, single-node Kind cluster running
Kubernetes v1.36.1. It supplies the digest-pinned Kind node image in `case.py`;
the only additional workload image is the digest-pinned official Kubernetes
`pause` image used by one benign scheduling probe. Published base receipts are
at lab `f98b1341115e31e9d5413d3c89445c991a486b76` and framework
`b3a2e0b6df6121a6cbaf42cd9b09cd034327f0b1`, both with cleanup recorded as
deleted.

## Observable outcomes

The case reads only an allowlist from the default node's `status.nodeInfo`: name, UID, kubelet version, container runtime version, operating system, architecture and kernel version. It adds the case-scoped `saf-lab.example/onboarding-hold=pending-validation:NoSchedule` taint and creates a tokenless pause Pod that tolerates Kind's default control-plane taint but not the case hold. The API shows the probe Pending with no assigned node, and a scheduler `FailedScheduling` event refers to the case hold key.

The local decision function then combines those observed Kind fields with a separately named JSON fixture of synthetic baseline attestations:

- **Red:** the synthetic fixture omits the runtime protection attestation. The decision rejects it, and the node remains held.
- **Green:** the complete synthetic fixture passes the local decision function against the observed Kind fields. The case removes only its own hold taint.
- **Positive:** the same probe is observed scheduled to the default node and its pause container becomes Ready. This verifies the taint and scheduler behavior in this disposable cluster.

The raw evidence file, `node-onboarding.raw.json`, contains allowlisted system fields, case-owned fixture data, the scheduler event, Pod UID/status, image ID and structured checks. It excludes credentials, environment variables, logs, and unfiltered object dumps.

## Coverage and unresolved claims

The fixture demonstrates an example gate shape and Kubernetes `NoSchedule` scheduling behavior. The strings `kubelet_hardening_attestation`, `container_runtime_protection_attestation` and `operating_system_baseline_attestation` remain synthetic fixture claims. The case also reads selected effective kubelet configz fields, the live CRI's default runc `SystemdCgroup` value, and selected `/etc/os-release` fields. Those observations are limited to the disposable Kind node and the local example predicates; they are not signatures, an attestation authority, a production baseline, or a production admission decision. `status.nodeInfo` values remain reported system metadata only.

The control's production immutable-root requirement remains unverified and separate. GPU capability, drivers, device plugins, device health, GPU allocation, GPU workload readiness, multi-node scale-out, and actual production baseline enforcement also remain out of scope. The v1.36.1 Node API fields used here are system metadata only; this case makes no claim that a Kind node is representative of a GPU host.

## Official primary sources

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — identifies the Kubernetes v1.36.1 node image and its digest.
- [Kubernetes v1.36 Taints and Tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) — documents `NoSchedule`, tolerations and the scheduler's treatment of unmatched taints.
- [Kubernetes v1.36 core API source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/api/core/v1/types.go) — defines Node system information fields, including kubelet, runtime, OS and kernel versions.
- [Kubernetes v1.36 container images](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/) — documents image digest references and their immutable content identity.

## Scratch supplement: allowlisted live node measurements

The case retains the six existing checks and their case-owned `NoSchedule` taint behavior. It reads only allowlisted effective kubelet and runtime fields and OS release ID/version from the exact invocation's single Kind node. The runner resolves that node through `kind get nodes --name <owned-cluster>`, checks its Kind cluster label and name, obtains kubelet values from that exact Node's `/configz` proxy, queries the running containerd CRI endpoint with `crictl info -o json` inside that node container, reads only `/etc/os-release` and `/proc/net/tcp{,6}` there as UID/GID 65534, and rechecks the Kubernetes Node UID. Configz must identify `kubelet.config.k8s.io/v1beta1` / `KubeletConfiguration`; `authentication.anonymous.enabled` and `authorization.mode` must be explicit. Only an absent `readOnlyPort` is normalized to the documented v1.36.1 default 0, and the case independently requires no listening socket on port 10255. This normalization relies on the pinned [v1.36.1 kubelet type](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.1/staging/src/k8s.io/kubelet/config/v1beta1/types.go) and [v1.36 kubelet config reference](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/). It persists parsed allowlisted values only; full config output, credentials, and process environment are not recorded. If configz or any other selected field is unavailable or ambiguous, the case blocks.

The containerd probe uses the existing local CRI socket read-only; root is used only inside the disposable node container to access that socket. The response stays in memory, and code retains only the default runtime name, its runc runtime type, and `SystemdCgroup` value. It requires `defaultRuntimeName == runc`, `runtimeType == io.containerd.runc.v2`, and the exact `runtimes.runc.options.SystemdCgroup` field. This follows the documented `crictl info` verbose status schema; it ignores the separate top-level legacy `systemdCgroup` value. A command error identifies only a fixed stage name, without stderr or response content. The local comparison values are a disposable Kind example, not an approved organizational baseline or evidence about GPU hosts. The policy requires the measured example OS release to be exactly Debian `ID=debian`, `VERSION_ID=13`; wrong and missing release IDs are rejected while the same Node remains held and the same probe remains Pending. Other or missing version IDs do not pass this example policy. This does not select approved releases for production GPU hosts. The supplement fails closed for missing/ambiguous fields, a different node UID, or a nonmatching example value. It does not claim production node admission, immutable-root enforcement, measured boot, GPU readiness, hardware/driver attestation, or onboarding authority. Those remain organizational evidence or separate control scope. 1007-016 hardware/driver evidence is intentionally not duplicated.


## Live evidence before removing the hold

The live measurements and fail-closed counterfactuals run while the original case taint is still present. Each malformed-input, wrong-UID, wrong-version, and missing-version decision is followed by separate reads of the same probe UID/phase/assignment and the same Node UID/hold state. The case removes its hold only after the existing synthetic approval and the live versioned example baseline pass. The six existing checks remain present, and the OS-version counterfactual adds a seventh. This remains a disposable Kind policy example, not an organizational admission or GPU-node conclusion.


For the CRI query shape, see the upstream [containerd CRICTL guide](https://github.com/containerd/containerd/blob/main/docs/cri/crictl.md#display-status--configuration-information-about-containerd--the-cri-plugin) and [pinned `cri-tools` v1.36.0 CLI source](https://github.com/kubernetes-sigs/cri-tools/blob/v1.36.0/cmd/crictl/info.go).
