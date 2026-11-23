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
