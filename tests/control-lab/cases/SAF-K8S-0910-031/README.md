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

## Owner claims before activation

The source and destination owners each publish a claim for the selected
endpoint and live Service UID using their separately scoped Kubernetes
identity. An exact pair approval with missing owner claims leaves the
destination empty. A valid owner claim bound to a different Service UID
also leaves the destination empty. The request author cannot change an owner
claim. After both correct claims and the independent approval are present,
the local Distribution transfer produces the exact inert manifest and blobs.

For an adoption, verify real endpoint ownership or the authorized tenant,
protected claim and reviewer history, alternate transfer paths, and rollback,
revocation, and destination-content evidence.
