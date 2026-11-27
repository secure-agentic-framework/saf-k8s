# SAF-K8S-1007-016 — Synthetic GPU-node onboarding gate

Run from the SAF-K8S control-lab checkout:

```sh
python3 lab.py test SAF-K8S-1007-016 --docker-context desktop-linux
```

The default runner creates one disposable Kind v1.36.1 node from
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`.
This case adds one reserved fixture label and one
`NoSchedule` taint to that node. It creates an inert Pod using the
digest-pinned `registry.k8s.io/pause:3.10.1` image before the taint, then creates
an otherwise equivalent Pod without the matching toleration and observes the
scheduler leave it pending for the taint. It parses two local synthetic evidence
records: an attestation-shaped record and a driver-integrity-shaped record. A
negative fixture produces `hold`; matching fixture fields produce a mock
`eligible` decision. Only then does the case create a Pod with the exact
fixture-taint toleration and observe the scheduler assign it to the Kind node.

The original positive eligibility decision is **mocked**. Its attestation fixture says
`verification_performed: false`; that placeholder signature is not verified. The driver
record's placeholder digests are compared as JSON strings only. An additional verifier path separately verifies a per-run test-only signature over an
exact-byte envelope; it does not verify hardware attestation, an external trust root,
a production signature, or a real driver checksum. No host driver, GPU, or hardware
measurement is read. The Pod scheduling exercise verifies Kubernetes scheduler
behavior for a user-created node taint and Pod toleration. It does not connect either
the mock field parser or test verifier to a production node-onboarding workflow or
establish who can apply, remove, or bypass production node labels and taints.

The case writes raw, secret-free evidence under the runner's run-specific
evidence directory. `scheduling-observations.raw.json` is deliberately reduced
to node identity, readiness, the fixture label and taint, and the relevant Pod
schedule conditions and image. `synthetic-evidence-assessment.raw.json` retains
the fictional fixture notice and parser decisions. No Secret objects, host
inspection, real feeds, real targets, or workload payloads are used.

## Coverage and unresolved claims

The case preserves the four original checks and adds four signed-verifier, scheduling,
and cleanup checks. It exercises
actual Kubernetes scheduling on one node and parsing/conservative decisions over
synthetic attestation and driver-evidence metadata.

It verifies only the test-only signature over the case-generated envelope; it does not
establish hardware attestation, external trust-chain validation, or production signature
verification. It also does not establish measured boot, GPU presence/capability, real GPU driver provenance or integrity,
device-plugin registration, accelerator resource scheduling, trust in node
labels/taints, fail-closed onboarding integration, production telemetry, or
multi-node behavior. Those source-control claims remain unverified by this
case. Kind's node is not represented as GPU-capable.

## Primary references

- [Kubernetes v1.36 taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) describes how `NoSchedule` taints filter new Pods unless their tolerations match.
- [Kubernetes v1.36 assigning Pods to nodes](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/) describes scheduler assignment and node selectors.
- [Kubernetes v1.36 scheduling GPUs](https://v1-36.docs.kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/) explains that GPU scheduling depends on vendor drivers and device plugins. This case installs neither.
- [Kubernetes registry documentation](https://github.com/kubernetes/registry.k8s.io/blob/main/docs/debugging.md) documents the official `registry.k8s.io/pause` image repository. The case pins the exact pause image digest used by the existing lab's scheduling fixtures.


## Signed-record verifier path

The case preserves the original four checks and adds four checks. It
uses the runner host's `/usr/bin/openssl` CLI and supports OpenSSL 1.1.1 or newer and
LibreSSL 3.3.6 or newer. This host's exact provider version is kept in raw evidence.
The case creates a per-run RSA-2048 key in a mode-0700 temporary directory. The
private key is never printed or retained; the directory is deleted before the valid
test authorization changes scheduling. The derived public key is designated as an
ephemeral test-only trust root for this run, not a production identity.

The signed envelope uses deterministic canonical JSON bytes and binds the observed
Kind Node UID to a fresh case nonce. The case verifies the signature over those exact
bytes, then checks subject, nonce and replay state. A bit-flipped signature, a
signature from a different key, a validly signed wrong nonce, a validly signed wrong
node, a signed non-object JSON value, and a repeated nonce each hold while the same non-tolerating pause probe remains Pending
under the case taint. The original pending comparator is deleted after its original
raw observation is saved, so only the signed-phase probe can schedule after release.
The verifier re-reads and
matches the Node UID immediately before releasing the taint and after scheduling. A fresh valid
signed record removes only that taint; the same Pod UID then schedules. The existing
fictional driver-evidence record remains separate and is not cryptographically or
physically verified.

This is a verifier and scheduling-gate fixture only. It does not authenticate hardware,
measure boot state, verify a real driver, establish an external trust chain, or test
production control of labels, taints, exceptions or tolerations. No GPU capability or
production onboarding claim is made. The replay check uses a case-local in-memory nonce set only; it does not establish
replay-state persistence across verifier restarts or deployments. After the valid
path, the case deletes its probe and verifies removal of only its own taint and label.
