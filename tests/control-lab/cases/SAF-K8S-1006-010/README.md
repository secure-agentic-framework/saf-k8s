# SAF-K8S-1006-010 policy exception approval and expiry

Run from the lab root.

```sh
python3 lab.py test SAF-K8S-1006-010 --docker-context desktop-linux
```

The test registers a namespaced exception-record CRD and a zero-replica
Deployment in a fresh Kind cluster. It presents real, short-lived fixture
ServiceAccount credentials to the Kubernetes API. A fixture Role authorizes
the approver to create exception records. A separate observer has no write
permission.

The API admits broad-scope and stale records before the policy is bound. After
binding, it admits the precisely scoped and attributed record and rejects a
wildcard scope, stale expiration, mismatched authenticated identity, and
missing approval fields. RBAC denies the authenticated observer and prevents
the approver from updating the fixture cutoff. Advancing the cutoff with the
cluster administrator makes the same previously accepted record fail admission.

The case tests record admission against an administrator-controlled cutoff.
Recurring review, trusted cutoff advancement, and expiry at the real policy
consumer require separate evidence.

[Kubernetes v1.36 ValidatingAdmissionPolicy documentation](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
