# SAF-K8S-0910-025 registry federation membership

Run `python3 lab.py test SAF-K8S-0910-025` from the control-lab directory.

The source registry runs in one owned Kind cluster. A separate owned peer
has two real CNCF Distribution instances. The fixture uses a fixed repository,
tag, and inert image. After the baseline transfer, it replaces only the
unapproved registry Pod behind the same fixture Service. A separate observer
confirms the destination is empty before retrying the exact request, and
checks the manifest and blobs again after the governed refusal. The approved
pair still succeeds and the observer reads and verifies the actual bytes.

Kubernetes RBAC separates writable active membership from immutable approvals.
The repair account can update active membership, and it receives HTTP 403 on
an approval-list write. The observer receives HTTP 403 on a membership write.
A bounded reconciliation removes the seeded unapproved active endpoint. The
lab covers this reconciliation and one fixed pair, with operational approval,
revocation, scheduling and transport identity requiring separate evidence.

- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [Kubernetes RBAC resource-name restrictions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources)
