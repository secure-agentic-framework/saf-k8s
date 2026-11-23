# SAF-K8S-0303-008 AppArmor approval

Run `python3 lab.py test SAF-K8S-0303-008` using the catalog revision recorded with
the verified result. The case applies a namespace-scoped Kubernetes Validating
Admission Policy for one named profile class. It exercises Pod-level defaults,
explicit regular/init container declarations, and the actual
`pods/ephemeralcontainers` API. Requests stay inert through server dry runs and
an explicit scheduling gate. The selected policy has no unconfined exception.

Node-local profile availability, supported runtime enforcement and production
exception handling require their own evidence.

- [Kubernetes AppArmor tutorial](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
- [Validating Admission Policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
