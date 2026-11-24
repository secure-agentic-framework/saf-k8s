# SAF-K8S-0201-005 — Kubelet hostname override governance

```sh
python3 lab.py test SAF-K8S-0201-005 --docker-context desktop-linux
```

The synthetic red/green checks exercise a default-deny policy and its approval
records. The live arm uses a digest-pinned Kind v1.36.1 control plane and an
owned worker. The worker's kubeadm `JoinConfiguration.nodeRegistration.name`
uses a unique approved DNS name. Kubeadm sets the effective
`--hostname-override` for this name, which differs from the worker's OS hostname.

The test verifies baseline naming, the worker's effective name and flag, Lease
renewal bound to its Node UID, the public certificate subject and group, and the
API server's declared Node authorizer and NodeRestriction settings. It checks
the native client CSR signature and ties the signed, approved CSR to the
worker's active client certificate by fingerprint. The evidence retains only
public enrollment metadata and normalized observations for independent replays.

## Adopter evidence

Use an approved read-only export or provider attestation for managed services.
Never collect kubelet private keys, bootstrap tokens, or other credential
material.

| Area | Read-only check | Evidence to retain | Still unverified when |
| --- | --- | --- | --- |
| Scope and ownership | Record provider/distribution, Kubernetes versions, cluster owner, node pools, and control-plane ownership. | Dated scope covering every cluster and node pool. | Inventory is incomplete or provider behavior is unknown. |
| Effective name inputs | Inspect running kubelet arguments, systemd unit/drop-ins, referenced config, provisioning templates, OS hostname, provider inputs, and registered Node names. | Sanitized effective-state excerpts with timestamps and node identifiers. | Only desired state is visible or a name source/provider rule is hidden. |
| Uniqueness | Compare the complete registered Node inventory with in-scope nodes, including replacement overlap. | Timestamped inventory and comparison. | Inventory is partial or simultaneous replacement behavior is omitted. |
| Exceptions and change governance | Match each effective exception to approval, reason, owner, date, review/expiry, and deployment/provider reference; inspect drift detection. | Current approvals and sanitized policy/audit evidence. | Approval is informal, expired, unbound to effective state, or drift is not detected. |
| Authenticated Node identity | Correlate API audit/provider records to `system:node:<NodeName>` and `system:nodes`; use only approved public certificate metadata. | Sanitized identity record and enrollment correlation method. | Evidence is synthetic, merely a username template, or an uncorrelated certificate subject. |
| Node authorization and NodeRestriction | Inspect effective authorizer/admission config, including structured authorization config; obtain provider/version evidence when managed. | Sanitized effective config or provider attestation and version. | Evidence is only Kind/default or provider docs do not cover the deployed service/version. |
| Bootstrap/provider binding | Review approved CSR/certificate enrollment and approval policy or provider identity controls, including rotation/replacement. | Policy, sanitized approval/audit evidence, provider version, and node-specific binding. | Binding is not attributable to a specific machine or enrollment is undocumented. |

Use these checks for the applicable node pools and capture dated, attributable
evidence from the deployed distribution and Kubernetes minor version. Record
provider-managed paths as unverified if the authority, approval or machine
binding cannot be corroborated.

- [Kubernetes v1.36 Node authorization and naming](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/node/)
- [Kubernetes v1.36 kubelet options](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)
- [Kind configuration: kubeadm config patches](https://kind.sigs.k8s.io/docs/user/configuration/)
