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

- [Kubernetes v1.36 admission controllers](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes v1.36.1 admission plugin defaults](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/kubeapiserver/options/plugins.go)
- [Kubernetes v1.36.1 LimitRanger implementation](https://github.com/kubernetes/kubernetes/blob/v1.36.1/plugin/pkg/admission/limitranger/admission.go)
