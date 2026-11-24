# SAF-K8S-0910-031 initial registry endpoint approval

Run `python3 lab.py test SAF-K8S-0910-031` from the lab directory.

A case-owned source transfers an inert OCI image to a real peer Distribution
registry before the enrollment gate. After resetting that disposable
destination, the governed path refuses a missing approval, a different
approved source, and a different approved destination. Kubernetes RBAC
refuses the requester's attempt to write the approval. The separate approver
then grants the exact pair, and the observer reads back the approved manifest
and blobs. The case covers initial enrollment of one fixture pair.

- [Kubernetes RBAC named resource rules](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
