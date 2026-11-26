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

The runtime extension executes the same harmless Deployment dry-run against a live Kyverno
1.20.0 consumer. The request is admitted before the fixture policy is applied. With the policy
active it is refused while its record is absent, admitted after scoped approval, and refused
again after the approved UTC expiry with the stored exception unchanged. The case saves
API-server UTC timestamp brackets and the distinct denial responses. This evidence covers the
fixture clock and exact admission path. Managed clock trust and deployment-specific policy
coverage require separate evidence. The case requires Helm and the reviewed Kyverno chart.

- [Kyverno installation and chart versions](https://kyverno.io/docs/installation/installation/)
- [Kyverno CEL resource and time libraries](https://kyverno.io/docs/policy-types/cel-libraries/)

A second synthetic approval exercises the no-renewal path. Separate identities
approve, review, and close the scoped exception. Kubernetes retains an immutable
review decision and ties the closure operation to the exact exception UID. The
same harmless admission request succeeds before closure and is refused after it.
The local fixture exercises a review decision and its effect. Deployment
scheduling, approved role assignments, and retained operating records require
evidence from the deployment under review.

## Verify an adopting deployment

The paired case checks the exception record and a live consumption path.
Use the deployment's own records to establish its time source, scheduled
reviews, role assignments, and coverage.

1. Inventory every deployed policy consumer that honors exceptions; record its policy revision, exception store, decision owner, and authoritative time source.
2. For each consumer, record the approved clock source and measured skew/availability envelope, then set and document the maximum exception lifetime and expiry behavior.
3. Retain each approved exception with a unique identifier, authenticated approver, justification, exact workload and namespace scope, start/expiry timestamps, compensating controls, and linked evidence.
4. Show the deployed approver, reviewer, renewal, and closure roles and their effective permissions. Preserve scheduled review decisions, renewal approvals, and closures with timestamps and exact exception IDs.
5. In an authorized non-production environment, verify the same harmless request is permitted only for the precise approved record, then denied after expiry or closure. Verify missing records and dependency failures follow the approved fail-closed behavior; retain consumer responses and UTC time brackets.
6. Reconcile evidence to the deployed policy revision and assigned owner. Do not treat this fixture receipt as evidence of adopter clock trust, role assignment, recurring review, or production policy coverage.
