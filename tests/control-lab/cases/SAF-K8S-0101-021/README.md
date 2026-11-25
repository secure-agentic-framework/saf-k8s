# SAF-K8S-0101-021 — API server admission controller chains

Run against two disposable Kubernetes v1.36.1 kind profiles.

```sh
python3 lab.py test SAF-K8S-0101-021
```

The case verifies the server version and effective kube-apiserver arguments,
then compares the startup-reported mutating and validating admission chains
with a versioned synthetic baseline. It inventories exposed API-based
admission policies, bindings and webhook configurations. The comparison
asserts that the two ordered native chains differ only by LimitRanger.

Each profile receives the same namespace LimitRange. When LimitRanger is
disabled, a Pod requesting 200m CPU is accepted by server-side dry-run even
though the namespace limit is 100m. The same request returns Forbidden
with the active chain and a compliant 50m request passes. The API server
evaluates each request without persisting the Pod.

The profile is a fixture. An organization supplies its own approved plugin
list, deviations, configuration inventory and review evidence. Production
replicas, custom webhook policy and managed settings require separate
assessment.

The `static_admission_case.py` release-review wrapper first runs this v1.36.1
case, then provisions separate stock and manifest-policy Kubernetes v1.37.0
kind profiles. It uses digest-pinned `kindest/node:v1.37.0`, temporary
configuration directories, and read-only bind mounts for the admission
configuration and policy manifests. The synthetic probes check a specifically
named ConfigMap, a specifically named disposable dynamic policy, and a
separately named expendable policy. The static rules are scoped to those names
and the release-review namespace; the case does not call webhooks or external
targets.

- [Kubernetes v1.36 admission controllers](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes v1.36.1 admission plugin defaults](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubeapiserver/options/plugins.go)
- [Kubernetes v1.36.1 LimitRanger implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/plugin/pkg/admission/limitranger/admission.go)
- [Kubernetes manifest-based admission control](https://kubernetes.io/docs/reference/access-authn-authz/manifest-admission-control/)
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)

## Adopter verification

1. Pin the Kubernetes release, provider or distribution and tier, API-server
   replicas, and approved baseline revision. Record the owner, approver,
   approved ordered chains, plugin configuration and applicable policy and
   webhook sources. Retain the approval with the exact version it covers.
2. Compare the baseline with the rendered provisioning source and the
   effective runtime configuration on every applicable API server. Inventory
   API-hosted policies and bindings and webhook configurations. Verify
   target scope, selectors, and failure policy using native configuration
   and supported evidence. For webhook behavior, pair the inventory with
   the [webhook failure-policy case](../SAF-K8S-0605-007/README.md).
3. For v1.37 file-backed policy, inspect the feature state, plugin
   configuration, mounted paths, file digests and change permissions. On a
   disposable profile, confirm that startup admission produces the
   expected denial and authorized comparison before API-hosted policies
   are installed. Review the intended scope and approved changes for any
   protected API-hosted objects.
4. Record each deviation with its exact affected profiles, justification,
   approving owner, expiry, and verified compensation or remediation.
   Reconcile approved exceptions after upgrades and control-plane changes.
   An unapproved or expired deviation remains a finding.
5. For managed services, match customer-visible settings and provider
   documentation or attestation to the exact offering and revision.
   Record which runtime details are available, which controls the
   customer can verify, and the evidence for each compensation. Keep
   uncovered provider settings unverified.

Retain the applicable baseline, versioned runtime and configuration
inventory, approved deviations, and allowed and denied evidence with their
collection dates. Verify actual approvals through the adopter's own
change process.

- [Kubernetes v1.37 manifest-based admission](https://v1-37.docs.kubernetes.io/docs/reference/access-authn-authz/manifest-admission-control/)
- [Kubernetes v1.37 API-based ValidatingAdmissionPolicy](https://v1-37.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
