# SAF-K8S-0908-006 Secure aggregation and release scope

Run by ID on fresh Kind. Two case-owned contributor pods create
complementary modular shares and write them using scoped Kubernetes
identities. Separate lane pods sum their authorized shares. The release
pod can read only both lane totals. It withholds an undersized cohort
and releases the exact approved aggregate with an aggregate-only schema.

The lab exercises honest participants with non-colluding lanes and a
cohort threshold. Deployment evidence must address operator isolation,
protocol integrity, collusion, replay and dropout, and disclosure risks
across the actual released outputs. The published SAF-K8S-0908-001 case
provides the exact pinned runtime image loader.

- [Practical Secure Aggregation for Federated Learning on User-Held Data](https://research.google/pubs/practical-secure-aggregation-for-federated-learning-on-user-held-data/)
- [Kubernetes RBAC authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

## Participant binding and cohort consistency

The API identifies each Pod's service account with SelfSubjectReview. Each
actor can write only its named share and receipt records. A foreign write
receives Forbidden and its target stays blank. The worker holds a claim for
a different participant and rejects a sequential duplicate submission before
writing. Two authorized synthetic vectors produce the expected aggregate.
Omitting one participant's second-lane share yields mismatched cohorts and
holds release.

This is an additive-sharing reference for authorization and release behavior.
Verify the selected secure-aggregation protocol, actual trust and transport
boundaries, recovery, concurrent replay prevention and approved disclosure
policy in the adopted implementation.
