# Verify legacy Secret admission and retire an empty sentinel

    python3 tests/control-lab/lab.py test SAF-K8S-0402-015 --docker-context desktop-linux

Dry-run requests compare admission before and after the legacy Secret type
policy. An inert Opaque request remains admissible, and the dry-run objects
remain absent. The fixture also checks the tracking start date.

The disposable profile explicitly leaves the controller manager’s legacy
signer path empty. The case verifies the argument, an absent referenced
ServiceAccount, and the exact sentinel’s metadata and zero data entries.
Manual deletion removes that object while an independent tokenless Pod
stays Ready.

The Kubernetes API-server signer remains configured. A separate Pod
uses one 600-second projected token and the enrolled API CA to read its
single permitted inert ConfigMap. The receipt records the HTTP decision
and the scoped grant.

For deployment verification, inventory legacy token metadata and approved
consumers. Retain approved migration decisions, issuer and audience
coverage, actual reader continuity, eligible cleanup or authorized
revocation, audit and outcome evidence. Verify provider-managed
controllers and their timing against the adopted Kubernetes version.

- [Kubernetes v1.36.1 legacy controller](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kube-controller-manager/app/service_accounts.go)
- [Kubernetes v1.36.1 TokenRequest issuer](https://github.com/kubernetes/kubernetes/blob/v1.36.1/pkg/registry/core/serviceaccount/storage/token.go)
- [Kubernetes v1.36 projected ServiceAccount volume](https://v1-36.docs.kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken)
