# SAF-K8S-1007-015 — GPU node onboarding security baseline validation gates

This draft covers a small, bounded decision and scheduling demonstration in the existing harness:

```sh
python3 lab.py test SAF-K8S-1007-015 --docker-context desktop-linux
```

The supervisor should execute it on a fresh disposable, single-node Kind cluster running Kubernetes v1.36.1. This draft has not run Docker or Kubernetes. The runner supplies the digest-pinned Kind node image in `case.py`; the only additional workload image is the digest-pinned official Kubernetes `pause` image used by one benign scheduling probe.

## Observable outcomes

The case reads only an allowlist from the default node's `status.nodeInfo`: name, UID, kubelet version, container runtime version, operating system, architecture and kernel version. It adds the case-scoped `saf-lab.example/onboarding-hold=pending-validation:NoSchedule` taint and creates a tokenless pause Pod that tolerates Kind's default control-plane taint but not the case hold. The API shows the probe Pending with no assigned node, and a scheduler `FailedScheduling` event refers to the case hold key.

The local decision function then combines those observed Kind fields with a separately named JSON fixture of synthetic baseline attestations:

- **Red:** the synthetic fixture omits the runtime protection attestation. The decision rejects it, and the node remains held.
- **Green:** the complete synthetic fixture passes the local decision function against the observed Kind fields. The case removes only its own hold taint.
- **Positive:** the same probe is observed scheduled to the default node and its pause container becomes Ready. This verifies the taint and scheduler behavior in this disposable cluster.

The raw evidence file, `node-onboarding.raw.json`, contains allowlisted system fields, case-owned fixture data, the scheduler event, Pod UID/status, image ID and structured checks. It excludes credentials, environment variables, logs, and unfiltered object dumps.

## Coverage and unresolved claims

The fixture demonstrates an example gate shape and Kubernetes `NoSchedule` scheduling behavior. The strings `kubelet_hardening_attestation`, `container_runtime_protection_attestation` and `operating_system_baseline_attestation` are synthetic fixture claims. This case does not inspect kubelet configuration, runtime configuration, host OS settings, signatures, an attestation authority, onboarding automation, or a production admission decision. `status.nodeInfo` values identify reported node system information; they do not prove those security properties.

The control's production immutable-root requirement remains unverified and separate. GPU capability, drivers, device plugins, device health, GPU allocation, GPU workload readiness, multi-node scale-out, and actual production baseline enforcement also remain out of scope. The v1.36.1 Node API fields used here are system metadata only; this case makes no claim that a Kind node is representative of a GPU host.

## Official primary sources

- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — identifies the Kubernetes v1.36.1 node image and its digest.
- [Kubernetes v1.36 Taints and Tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) — documents `NoSchedule`, tolerations and the scheduler's treatment of unmatched taints.
- [Kubernetes v1.36 core API source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/api/core/v1/types.go) — defines Node system information fields, including kubelet, runtime, OS and kernel versions.
- [Kubernetes v1.36 container images](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/) — documents image digest references and their immutable content identity.
