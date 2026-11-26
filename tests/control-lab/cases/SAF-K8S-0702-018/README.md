# SAF-K8S-0702-018 — Namespace tenant boundary example

```sh
python3 lab.py test SAF-K8S-0702-018 --docker-context desktop-linux
```

This bounded example gives two synthetic tenants separate namespaces. It checks
one API object read using a namespace-local `Role` and `RoleBinding`, then checks
ordinary same-node IPv4 TCP Pod traffic to fixed HTTP listeners before and after
NetworkPolicy isolation. The lab runner creates a fresh cluster from pinned
`kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`;
kind v0.32.0's default kindnet is left installed and its DaemonSet readiness is
checked. The fixtures use the lab's pinned BusyBox image, no credentials, and
synthetic marker strings.

## Review record

| Field | Evidence |
| --- | --- |
| Pinned catalog | SAF-K8S catalog commit `133a8698a45e2b335b51728bf4c62f7bda98d15f`; `catalog/index.json` SHA-256 `8b5d5d3953fe7609345314925fca4f692357e0cf1d451d66381b5845fc175186`; control SHA-256 `af5c1c0dc4d9ae4d08c6ee1a37b039c8da4d372722ee56c262e19750290a3617` |
| Control wording | Requires organizations to define and document a namespace tenant model and its threat-model-relative properties and limitations. Rationale says namespaces provide logical separation, not complete security isolation alone; this is a design/documentation control, distinct from implementing supplementary controls. |
| Current framework markdown reviewed | `../saf-k8s-framework/markdown/controls/SAF-K8S-0702-018.md` at framework worktree HEAD `e6c14f0bfb63d7e221447e20d136a8cfb8ba31a0`; local working tree also checked. Statement, objective, rationale, scope and enforcement agree with the pinned catalog. |
| Test platform | Runner-pinned Kubernetes 1.36.1 node image; kind 0.32.0 required and checked by the case; one kind node and stock kindnet with DaemonSet rollout checked; IPv4 and TCP. |
| Retained framework evidence | `verified/SAF-K8S-0702-018.json` |

| Catalog obligation | Mechanism and applicability | Required observation | Expected result |
| --- | --- | --- | --- |
| Define/document tenant boundary and limits | Case documentation states what namespaces, API authorization and NetworkPolicy establish and the remaining shared-node/multi-tenant scope. | Review this document against the control statement and scope. | Example documents a concrete boundary and avoids claiming complete isolation. |
| Namespace-local API access | A built-in Kubernetes `Role` permits only `get` on ConfigMap `tenant-record`; a `RoleBinding` binds it to a case-owned ServiceAccount in that namespace. The test performs impersonated API GETs. | Before binding, GET is forbidden. Afterwards each reader gets its own exact object; cross-namespace and same-namespace `other-record` GETs return Forbidden. | Positive own-namespace read; denied cross-namespace and out-of-name reads. |
| Ordinary Pod network isolation | Case-owned clients and fixed HTTP listeners first communicate with no policy. A namespace policy selects all Pods and admits TCP/8080 only for the tenant's own client/listener labels. | Exact marker returned before policy; two consecutive failed connection attempts to the other namespace after both policies; same-tenant listener still returns its marker. | Red cross-tenant connectivity; green blocked path; positive same-tenant path. |

## What Kubernetes itself establishes

Kubernetes namespaces scope namespaced objects and form an organizational
boundary, but creating namespaces alone does not grant or deny a user access.
The API server's RBAC authorizer applies the `Role` through its namespaced
`RoleBinding`; this case proves only the tested GET permissions and names. The
test uses API impersonation as a synthetic ServiceAccount identity, so it does
not test authentication, token issuance, credential handling or tenant control
of RoleBindings.

NetworkPolicy is an API object whose dataplane behavior depends on a plugin
that implements it. The selected kind release includes NetworkPolicy support
in its stock kindnet; the lab observation must prove the exact fixed-listener
request reaches the fixture before policy and is blocked after policy. That
demonstrates this policy pair on this local kind version. It does not make
namespaces a boundary against a node administrator or a kernel/runtime flaw.

This example does not assess shared-node resource contention or side channels,
node/host-network paths, privileged workloads, admission controls, tenant
ability to create or alter policy/RBAC, DNS, Services, IPv6, other CNIs, cloud
networking, vCluster/HNC, workload compromise, or an organization's actual
threat model. These require separate design decisions and evidence. It performs
no intrusion, escape, attack simulation or external-host testing.

## Reproducible outcomes and verification scope

The supervisor should run the command above from the lab root. A passing report
must contain the initial API denial, permitted exact object reads, API denials
outside the Role's namespace/name, two consecutive pre-policy cross-tenant HTTP
successes, two consecutive post-policy failures, successful same-tenant requests and restored cross-tenant connectivity
after removing the policies, in both directions, with `cleanup: deleted` in `evidence/SAF-K8S-0702-018/<run>/result.json`.
The runner retains the command transcript and cluster metadata beside that result.

Prerequisites are Python 3.9+, Docker available to the supervisor, kind 0.32.0,
kubectl compatible with Kubernetes 1.36, and the ability to pull the pinned
node and BusyBox images. The runner creates a unique disposable cluster and
deletes it on completion. On an interrupted run, the supervisor should inspect
the named cluster reported in the command transcript and delete that cluster
with kind; only this case's two namespaces and synthetic resources are created.

## Sources

- [Pinned SAF-K8S catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/saf_k8s_controls.yaml)
- [Current SAF-K8S control markdown](https://github.com/secure-agentic-framework/saf-k8s/blob/main/markdown/controls/SAF-K8S-0702-018.md)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/): a RoleBinding grants a role within its namespace; the binding can bind a ServiceAccount subject.
- [Kubernetes v1.36 RBAC good practices](https://v1-36.docs.kubernetes.io/docs/concepts/security/rbac-good-practices/): prefer namespace-scoped RoleBindings where possible and beware permissions to modify namespace labels.
- [Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/): policies require a supporting network plugin; ingress and egress isolation are independent and additive; a connection must be allowed at both ends; node traffic and `hostNetwork` behavior have stated limitations.
- [Kubernetes v1.36 multi-tenancy](https://v1-36.docs.kubernetes.io/docs/concepts/security/multi-tenancy/): namespace isolation requires other Kubernetes resources, networking plugins and security practices.
- [kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0): release-pinned Kubernetes 1.36.1 node image digest used by the lab runner.
- [kind v0.24.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.24.0): documents out-of-the-box network policy support via `kube-network-policies`; kind v0.32.0 is the lab's pinned kind version.
- [kind networking configuration](https://kind.sigs.k8s.io/docs/user/configuration/#networking): kind's default CNI and option to disable it. The case leaves default CNI enabled.

## Adopter verification

1. Record the actual tenant identity and namespace ownership, who may create/change namespaces, labels, RoleBindings and NetworkPolicies, and the approved threat model. Verify effective API permissions for representative identities and include namespace/name-scoped positive and negative authorization results.
2. Inventory the deployed CNI/version and its NetworkPolicy implementation. Capture effective policies and selectors for both sides of each relevant path; verify approved and denied connections for the protocols, address families, ingress/egress, Services and node paths that the threat model includes.
3. Document what namespace boundaries do and do not isolate. Cover `hostNetwork`, privileged workloads, node/kernel/administrator access, shared resources, DNS, storage and admission/identity controls where applicable; provide separate evidence for controls relied on in those paths.
4. Preserve dated configuration exports, test identity and command/result records, CNI/provider version, policy coverage and exceptions. Have the accountable platform/security owners approve limitations and remediation; repeat after relevant CNI, Kubernetes, tenant-role or policy changes.
5. Report the local 16-check result as portable mechanism evidence. Report deployed identity, CNI and path observations as adopter evidence. Do not state that the fixture validates the production cluster.

The amended crosswalk retains scoped conditional AC-4(2) and SC-32 support when the actual boundary is documented and its effective isolation is verified.
