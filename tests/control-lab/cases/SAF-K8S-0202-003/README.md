# SAF-K8S-0202-003 — Runtime inventory and patch SLA validation

From the SAF-K8S control lab directory, run:

```sh
python3 lab.py test SAF-K8S-0202-003 --docker-context desktop-linux
```

The harness creates its own disposable kind cluster from the exact pinned image
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
For every Kubernetes node, the case records
`status.nodeInfo.containerRuntimeVersion` and checks that the corresponding
Docker node container's configured image equals that exact digest reference.
The case compares the node-reported string with the packaged `containerd`
binary and records the packaged `runc` version. This inventories the pinned
fixture nodes. A production inventory feed requires separate evidence.

## Expected red and green results

The case evaluates the two case-owned inventory records against
`fixture-policy.json`, `synthetic-release.json`, and
`synthetic-advisory.json`:

- **Red:** `SYNTH-NODE-OUTDATED` is below fictional fixed version `9.4.2` and
  has no patch date. Its 14-day patch deadline is `2026-11-15`. The expected
  result fails only `patch_sla`; the synthetic vendor-support and advisory
  provenance checks pass independently.
- **Green:** `SYNTH-NODE-APPROVED` is at fictional fixed version `9.4.2`, has a
  patch date inside the same SLA, and has the same supported status and
  synthetic advisory provenance. It passes all three checks. Further cases
  reject a late patch, expired support, and unknown advisory provenance.
- **Positive:** a digest-pinned, tiny BusyBox pod runs as UID 65534 with dropped
  capabilities, small resource bounds, and a runtime-default seccomp profile.
  It must schedule to one of the reported nodes, complete successfully, and
  print `fixture-ok`.

All inventory, release, advisory, support dates, and SLA records are synthetic.
The version `9.4.2` is intentionally not an upstream containerd version. The
synthetic advisory is not a CVE or GHSA and no vulnerability is exercised. The
fixture intentionally keeps the outdated record within its synthetic vendor
support window, so patch timing, support status, and advisory provenance are
separate decision inputs. The policy is an evaluator example, not a proposed
production patch SLA or vendor support assertion.

## Review gates and scope

| Catalog obligation | Test mechanism | Boundary |
| --- | --- | --- |
| Track runtime versions | Read node-reported CRI runtime version for each node and verify the actual kind node image reference | Only the fresh pinned kind nodes in this run |
| Check supported matrix | Evaluate explicit synthetic inventory support status and support-until date | No real vendor lifecycle decision |
| Apply vulnerability patch SLA | Compare installed version and patch date with a synthetic fixed release and 14-day deadline | No live advisory feed, scanner, patch rollout, or remediation workflow |
| Validate compatibility | Schedule and complete a minimal pinned BusyBox fixture | One benign workload, not production workload compatibility |

The case reads runtime binary versions from the pinned nodes. CRI-O, gVisor,
Kata, NVIDIA runtimes, managed service patch commitments, node
pool rollout behavior, and production enforcement are outside its scope. A real control review still
needs an organization's approved support matrix, documented patch SLA, trusted
advisory provenance and applicability, node inventory, rollout records, and
workload-specific compatibility evidence.

## Pinned catalog and version-matched primary references

- Pinned control record in the lab catalog: SHA-256
  `3cf58ffe3e4a2fde5c76e0ea36fcb6d356125a84dab803789e942505196bb353`.
- Current framework control text: [SAF-K8S-0202-003](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0202-003.md).
- Framework source revision inspected: `e6c14f0bfb63d7e221447e20d136a8cfb8ba31a0`.
- [Kubernetes v1.36 Node API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/core/node-v1/): defines `containerRuntimeVersion` as reported by the node through the runtime remote API.
- [Kubernetes v1.36 container runtime docs](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/container-runtimes/): documents the CRI requirement for Kubernetes 1.36.
- [kind node image releases](https://github.com/kubernetes-sigs/kind/releases): the runner pins the image digest in its checked-in `lab.py`; this case verifies each node container uses that same reference.
- [containerd versioning and release policy](https://containerd.io/releases/): primary project source for real release-branch lifecycle and Kubernetes/runtime compatibility guidance. It is a living policy page and is cited as review context only; the synthetic fixture does not encode its real version or support claims.

## Prerequisites, evidence, and cleanup

The supervisor needs the framework control-lab runner, Docker using a local Unix
socket context, `kind`, `kubectl`, and an available pinned BusyBox image or the
ability to pull it. The framework retains the reviewed receipt at
`verified/SAF-K8S-0202-003.json`.

The runner retains `commands.log` and `result.json` under its evidence path and
deletes the owned cluster in its `finally` cleanup. Review the returned node
image references, per-node runtime values, red and green policy decisions, pod
scheduled node and successful output, and `cleanup: deleted`. The case itself
creates only one pod in the harness-owned `saf-test` namespace; cluster teardown
cleans it up. No credentials or host files are used.
