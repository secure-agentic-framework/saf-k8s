# SAF-K8S-0702-029 — Classification-driven storage and network restrictions

```sh
python3 lab.py test SAF-K8S-0702-029 --docker-context desktop-linux
```

## Versioned source reasoning

Review target: [`SAF-K8S-0702-029.md` at framework commit `133a8698a45e2b335b51728bf4c62f7bda98d15f`](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-029.md).

For Kubernetes v1.36, a `NetworkPolicy` selects Pods and defines ingress or
egress rules, but its data-plane effect depends on a conformant implementation
from the installed networking plugin. The case pins the runner's kind node
image by digest, requires kind v0.32.0 / Kubernetes v1.36.1, checks that the
`kube-system/kindnet` DaemonSet is ready, and records its actual image. kind's
v0.32.0 `kindnetd` source creates the standard NetworkPolicy evaluator and
policy engine. The test still treats observed HTTP outcomes as necessary live
evidence; API acceptance or the presence of a policy alone is not a pass.
The node image is
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`;
fixture Pods use the existing digest-pinned
`docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec`.
No separately downloaded CNI dependency is introduced.

The storage fixture creates two static hostPath PVs backed by directories
created inside the disposable kind node. Both have the same storage class and
capacity but carry different synthetic classification labels. A PVC selector
requests only the confidential label. Before the ValidatingAdmissionPolicy
is activated, the API admits a server-side dry-run for a lower-class Pod
referencing the claim. The same declaration is rejected after policy activation.
The case checks the exact bound PV, writes a fixed synthetic marker through
one nonroot Pod, then reads it through another nonroot Pod using the same claim.
The runner removes the cluster and its fixture directories.

| Obligation | Concrete case evidence | Boundary |
| --- | --- | --- |
| Classification drives a network restriction | Before policy, the sensitive client reaches the live lower-class listener. After policy, repeated ordinary HTTP requests to it fail while same-class requests return the expected marker. | One IPv4 TCP/8080 Pod path on kindnet; no external targets, DNS, IPv6, other protocols, or production CNI. |
| Classification drives storage placement and claim use | A confidential PVC selector binds to the exact confidential PV, the admission policy denies the lower-class Pod declaration, and separate writer and reader Pods confirm persistence. | Static hostPath PVs on one disposable kind node with one scoped admission rule. Production policy enrollment, label authority, backend isolation and encryption require separate evidence. |

Primary references:

- [Kubernetes v1.36 NetworkPolicies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) — NetworkPolicy semantics, CNI implementation requirement, and API limitations.
- [kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — release-pinned Kubernetes v1.36.1 node image digest used by `lab.py`.
- [kind v0.32.0 kindnetd source](https://github.com/kubernetes-sigs/kind/blob/v0.32.0/images/kindnetd/cmd/kindnetd/main.go) — standard NetworkPolicy evaluator and dataplane controller setup.
- [Kubernetes v1.36 Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/) — PV/PVC matching, claim selectors, binding, and Pod volume use.
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) — matching, binding, and enforcement of the scoped Pod admission rule.
