# SAF-K8S-0502-004 — CNI plugin hardening and lifecycle management

Run from the framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-004 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 profile uses Helm 3.17, Kind v0.32.0 and a kernel supported by Cilium. The case installs the digest-verified Cilium v1.20.5 chart, checks the pinned agent and operator images and confirms a synthetic Service answers.

A schema-invalid readiness threshold is rejected by the API server. Without atomic rollback Helm leaves a failed revision. With atomic rollback it creates a failed revision followed by a deployed rollback. The case verifies the exact approved values and image pins are restored and the Service again returns the marker. This checks rejection before a new version of the workload starts.

A separate valid change applies the Cilium agent setting and waits for its Ready rollout and marker route. The operator comparison uses a schema-valid change confined to the case-owned release, verifies Helm applied the manifest, then independently observes a Kubernetes rollout timeout and the exact replacement Pod's container failure, and verifies the existing agent data path remains available. Explicit rollback restores the known-good operator image, rollout strategy and values, and the marker route remains healthy.

The supplement creates one namespaced `CiliumNetworkPolicy` whose selector and
TCP/18080 rule refer only to the owned marker server and client. Kubernetes'
`CiliumEndpoint` status in the captured run had no policy field, so this
observer uses the pinned local v1.20.5 Cilium agent's read-only
`cilium-dbg endpoint get <endpoint-id> -o json`. The endpoint ID comes from the
owned server CiliumEndpoint; the helper selects exactly one ready agent on the
server Pod's node and requires its configured agent image to match the digest
pin. The observed agent model must return the same endpoint ID and CNI
attachment, expose the Pod IP, report `status.policy.realized.policy-enabled` as `ingress` or `both`,
and include an ingress rule whose `derived-from-rules` labels identify this
exact namespaced CNP. These fields describe the policy in the endpoint's
datapath according to the pinned API model; the additional JSON evidence file
contains only a summary, while the harness command log retains the response
for this case-owned synthetic endpoint. The case checks this state before and after the agent rollout and
operator failure/rollback, while confirming the ordinary marker path. It then
deletes the policy and checks object absence and continued marker reachability.
It sends no denied request and makes no policy-bypass comparison, so it does
not prove the negative behavior of the rule.

The Kubernetes CiliumEndpoint owner reference binds the Pod UID. The local
agent endpoint joins through the exact endpoint ID, CNI attachment ID, and
Pod IP. The realized ingress rule carries the policy's exact namespace,
name, and UID and the expected TCP port.

Primary references: [v1.20.5 endpoint-get command source](https://github.com/cilium/cilium/blob/v1.20.5/cilium-dbg/cmd/endpoint_get.go), [endpoint status model](https://github.com/cilium/cilium/blob/v1.20.5/api/v1/models/endpoint_status.go), [policy status model](https://github.com/cilium/cilium/blob/v1.20.5/api/v1/models/endpoint_policy_status.go), [policy model](https://github.com/cilium/cilium/blob/v1.20.5/api/v1/models/endpoint_policy.go), [L4 policy model](https://github.com/cilium/cilium/blob/v1.20.5/api/v1/models/l4_policy.go), and [Cilium 1.20 troubleshooting guidance for mapping realized rules to source policy labels](https://docs.cilium.io/en/stable/security/policy/troubleshooting/).

For adoption, capture the actual plugin version, approved chart and images, hardening values and policy baseline. In an equivalent nonproduction topology exercise an approved version change with relevant CRDs, datapath and node lifecycle. Record agent and operator readiness, the deployed Cilium policy set, effective endpoint identities, realized policy state from the deployed agent, and independent marker traffic before, during and after a representative failure and recovery. Retain the known-good configuration, rollback result, recovery time, patch/advisory owner and any provider-specific commitments. The conditional CM-3(2) contribution covers the tested change-validation and recovery slice. The synthetic one-flow policy does not establish production policy completeness or denial behavior.

[Cilium v1.20 Kind installation](https://docs.cilium.io/en/v1.20/installation/kind/) · [Helm v3 upgrade](https://helm.sh/docs/v3/helm/helm_upgrade/) · [Kubernetes v1.36 workload probes](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/)
