# SAF-K8S-0803-003 RDMA policy evidence boundaries

A Kubernetes Job makes scoped decisions over owned inert records. A count-only check passes all records. A richer check distinguishes wrong trust boundaries, missing scope, an unapproved operation and stale evidence while retaining the intended approved record. The test creates no RDMA object and has no real key, remote memory, GPU or network fabric interaction.
