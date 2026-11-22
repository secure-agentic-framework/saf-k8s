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

The positive eligibility decision is **mocked**. The attestation fixture says
`verification_performed: false`; its placeholder signature is not verified.
The driver record's placeholder digests are compared as JSON strings only. No
host driver, GPU, measurement, signature, checksum, provider, or trust root is
read or verified. The Pod scheduling exercise verifies Kubernetes scheduler
behavior for a user-created node taint and Pod toleration. It does not connect
the mock parser to an actual node onboarding workflow or establish who can
apply, remove, or bypass production node labels and taints.

The case writes raw, secret-free evidence under the runner's run-specific
evidence directory. `scheduling-observations.raw.json` is deliberately reduced
to node identity, readiness, the fixture label and taint, and the relevant Pod
schedule conditions and image. `synthetic-evidence-assessment.raw.json` retains
the fictional fixture notice and parser decisions. No Secret objects, host
inspection, real feeds, real targets, or workload payloads are used.

## Coverage and unresolved claims

The case exercises actual Kubernetes scheduling on one node and reports
independent red, green, and positive checks: schedulable before the scoped
taint, rejected for that taint without its toleration, and assigned after the
matching toleration. It also exercises parsing and conservative decisions over
synthetic attestation and driver-evidence metadata.

It does not establish hardware attestation, cryptographic verification,
measured boot, GPU presence/capability, real GPU driver provenance or integrity,
device-plugin registration, accelerator resource scheduling, trust in node
labels/taints, fail-closed onboarding integration, production telemetry, or
multi-node behavior. Those source-control claims remain unverified by this
case. Kind's node is not represented as GPU-capable.

## Primary references

- [Kubernetes v1.36 taints and tolerations](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) describes how `NoSchedule` taints filter new Pods unless their tolerations match.
- [Kubernetes v1.36 assigning Pods to nodes](https://v1-36.docs.kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/) describes scheduler assignment and node selectors.
- [Kubernetes v1.36 scheduling GPUs](https://v1-36.docs.kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/) explains that GPU scheduling depends on vendor drivers and device plugins. This case installs neither.
- [Kubernetes registry documentation](https://github.com/kubernetes/registry.k8s.io/blob/main/docs/debugging.md) documents the official `registry.k8s.io/pause` image repository. The case pins the exact pause image digest used by the existing lab's scheduling fixtures.
