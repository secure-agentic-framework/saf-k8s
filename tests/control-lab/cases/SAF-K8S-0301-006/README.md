# SAF-K8S-0301-006 Narrow PSA exceptions

The disposable v1.36.1 API server uses native namespace, RuntimeClass and
requester exemptions. The separate admission policy validates actual request
scope and the approved Pod shape. It denies the sample class outside its
approved namespace and checks exact identity, image, host settings and
changes to the scope label. The projected requester comparison shows that
Pod serviceAccountName and authenticated API identity are separate.

Harmless marker Pods also verify a separate ingress NetworkPolicy. The case
retains scoped audit identifiers and verifies that an empty Secret event
contains metadata only.

```sh
python3 lab.py test SAF-K8S-0301-006 --docker-context desktop-linux
```

## Verify an adopter's enforcement

1. Inventory each active exemption by namespace, authenticated requester or
   RuntimeClass. Record the approved workload, owner, expiry, exact fields
   needed, and legitimate controller or direct creation paths.
2. Verify separate admission and authenticated authorization. Check exact
   workload and requester approvals, the allowed Pod security fields, and
   CREATE, UPDATE and subresources where applicable. Confirm that ordinary
   operators cannot widen namespace labels, workload identity, RuntimeClass
   scope or policy configuration. Test benign denials and an approved
   equivalent in an isolated matching environment.
3. Check real controllers, runtime and compensating controls for the
   applicable GPU, CNI, CSI, monitoring or other infrastructure workload.
   Confirm needed operations and observed isolation, including denied and
   permitted traffic. Record the actual rule and enforcement owner.
4. Retain scoped audit for approved actions and metadata for sensitive
   resources. Compare the effective exception inventory with its approved
   register and verify expiry and rollback on the target profile.

This case verifies a single built-in admission policy and a separate owned
marker network. Device and controller behavior, provider-managed controls
and alternative policy engines need corresponding adopter evidence.

- [Pod Security Admission v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Validating Admission Policy v1.36](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- [Kubernetes NetworkPolicy v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
