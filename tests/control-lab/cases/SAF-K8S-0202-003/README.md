# SAF-K8S-0202-003 — Runtime inventory and patch SLA validation

From the SAF-K8S control lab directory, run:

```sh
python3 lab.py test SAF-K8S-0202-003 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 Kind cluster has a control plane and a
dedicated canary worker. The test checks each node's CRI-reported containerd
version against its packaged binary and records its runc version. It verifies
containerd's exact signed v2.3.7 tag with the pinned maintainer public key and
an isolated local GnuPG keyring. It also rejects altered signed input.

On the canary worker, the test downloads the official v2.3.7 release archive
for its architecture and matches the reviewed digest. The same non-root
marker Pod spec runs on the worker's original daemon, after the daemon patch,
and after restoring the original executable. Each stage checks the live CRI
v1 runtime version and Kubernetes Node information for the same worker. The
fixture changes only the daemon binary inside the disposable worker. The
exercise covers that patch path and the marker workload.

Use GnuPG and curl. The lab needs HTTPS access to GitHub's public release
assets for the canary. No release binaries are checked in.

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

The policy-decision records described above use synthetic inputs.
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
- [containerd versioning and release policy](https://containerd.io/releases/): primary project source for release-branch lifecycle and Kubernetes/runtime compatibility guidance. The portable snapshot below records the exact policy blob identity and retrieval-time transcription.

## Portable official metadata comparison

Run the data-only comparison from the repository root:

```sh
python3 case/verify_official_release.py
```

It requires Python 3.9 and local `gpg`. It makes no network calls and does not
install or run a container runtime. The verifier checks the exact Git annotated
tag object ID, tag name, target commit, embedded signature and pinned maintainer
fingerprint. It imports only the bundled public key into a fresh temporary
GnuPG home for each run; it does not use a user's keyring or private keys. The
public-key fingerprint is the trust pin for this bounded check; GPG's web of
trust is not asserted. The tag artifact is the compact exact signed v2.3.7 tag
payload (including its upstream release notes), not a copy of upstream
`RELEASES.md`.

`official-policy-facts.json` records normalized facts with source IDs for the
official release metadata and the `RELEASES.md` blob
`3bfcffe4f4f637d18689ca1893649af81b38fdaf`. The facts are independently
reviewed/transcribed and integrity-pinned in this case; they are not
authenticated by the tag signature. The verifier keeps that distinction in
its output. The reviewed policy states containerd 2.3 is LTS through
2028-04-30, recommends containerd 2.3.0+ with CRI v1 for Kubernetes 1.36, and
does not provide a universal vulnerability-remediation SLA.

The comparator uses the retained fixture observation in
`live-observation.json` (receipt SHA-256
`8ae804e8dd10efcfb4afc5dd24557c53356886ef73c77e3bb4da3158504b271a`): on
2026-11-22, the one kind node reported and packaged containerd 2.3.1 under
Kubernetes 1.36.1. It marks 2.3.1 as older than the pinned reviewed release
2.3.7, while still meeting the published 1.36 recommendation and 2.3 LTS
horizon on that observation date. Version comparison alone does not establish
whether any advisory applies, whether a patch deadline was missed, or whether
production nodes have the same version. No particular advisory is evaluated.

The original synthetic red/green SLA cases below remain the only SLA arithmetic
exercise. Alternative runtime coverage and canary, rollout, and rollback steps
remain adopter guidance in the review's `adoption.md`; no real infrastructure
was changed by this portable case.

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


The signed tag and public verification key were obtained from the upstream
containerd release and maintainer key publication. The reviewed binary digests
come from that release's asset metadata. [containerd v2.3.7 release](https://github.com/containerd/containerd/releases/tag/v2.3.7)
