# SAF-K8S-0101-008 — Audit policy and credential-bearing bodies

The default KIND cluster accepts the fixture's authorized requests and denies the
same unauthorized read while audit is disabled. A second Kubernetes v1.36.1
cluster runs the revised audit policy. The policy puts Secrets, TokenReview, and
service-account token issuance at Metadata before a narrow ConfigMap request-body
rule. The final Metadata rule covers the remaining requests.

| Fixture request | Status | Decision | Audit level | Body fields |
| --- | ---: | --- | --- | --- |
| Create a noncredential ConfigMap canary | 201 | allow | Request | Request only |
| Create an empty Opaque Secret | 201 | allow | Metadata | Neither |
| Read the canary ConfigMap | 200 | allow | Metadata | Neither |
| Read a named Pod without authorization | 403 | forbid | Metadata | Neither |
| Submit a TokenReview with a public invalid marker | 201 | allow | Metadata | Neither |
| Let the kubelet project a token into an ordinary fixture Pod | 201 | allow | Metadata | Neither |

The case verifies one completed audit event per row, including the effective
identity, verb, target, status, decision, and the presence or absence of body
fields. The in-node filter returns fixed metadata and booleans. The test never
reads the projected token or exports audit bodies. Both clusters are deleted
after the run.

The ConfigMap body rule matches creates by the authenticated `kubernetes-admin`
identity in the isolated `saf-test` namespace. Kubernetes audit policy cannot
select individual object names for this rule. Use the fixture only with
noncredential ConfigMaps in that namespace. Assess each deployed policy and
managed service's audit settings in its own environment.

- [Kubernetes v1.36 auditing](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 audit policy API](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)
- [Kubernetes v1.36 audit annotations](https://v1-36.docs.kubernetes.io/docs/reference/labels-annotations-taints/audit-annotations/)
