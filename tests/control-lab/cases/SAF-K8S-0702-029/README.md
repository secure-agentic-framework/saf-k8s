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

## Adopter verification

1. Reconcile the authoritative classification source, approved label values,
   workload identities and enrolled pipeline namespaces to actual workloads
   and PVCs. Record label ownership, exception approval and the exact policies
   bound to each classification.
2. For each storage class/backend, trace a classified PVC to its PV and
   workload mounts. Verify the approved class/selector, namespace and
   identity permissions, and any admission rule preventing a lower-class
   workload from using the sensitive claim. Include encryption and backend
   access evidence separately where required.
3. Inventory expected in-cluster, cross-namespace and external network flows
   for each classification, including CNI/version, address families,
   protocols, DNS and shared-service exceptions. Map each flow to effective
   NetworkPolicy or provider controls.
4. In an approved safe test window, validate representative allowed and
   prohibited storage/API and network paths with synthetic markers or
   controlled endpoints. Record caller, source/target, class, policy, result
   and timestamp. Verify a policy object is enforced by actual dataplane
   behavior, not just accepted by the API.
5. Repeat the independent boundary inventory on a defined cadence and after
   label, namespace, storage, CNI, service or external endpoint changes. Retain
   coverage, exceptions, review, remediation and evidence of corrected paths.

**Portable evidence:** current digest `39909a0e00e20c8036621b91a85e7909265929286ada73b40d4c55207ee02396`
matches the passed **8-check** receipt, catalog revision
`7e2e05c327f54bcc2c6aefd64c255880a81ce7c9`; paired lab/framework runs are in
Beads and clusters were deleted. The fixture covers one IPv4 TCP/8080 kindnet
path plus static hostPath synthetic PVC selection, scoped admission denial of
a lower-class Pod mount, and separate writer/reader marker persistence. It
does not establish deployed classification authority, production CNI,
external/DNS/IPv6 flows, backend isolation or encryption.
