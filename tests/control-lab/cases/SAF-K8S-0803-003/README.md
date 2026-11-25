# SAF-K8S-0803-003 RDMA policy evidence boundaries

A Kubernetes Job makes scoped decisions over owned inert records. A count-only check passes all records. A richer check distinguishes wrong trust boundaries, missing scope, an unapproved operation and stale evidence while retaining the intended approved record. The test creates no RDMA object and has no real key, remote memory, GPU or network fabric interaction.

## Adopter verification

1. Record the actual RDMA device, driver, allocator and container-runtime path, workloads, device ownership, protection domain and approved operations.
2. With approved canaries on supported nodes, observe actual device assignment and protection-domain scope and verify the permissions and functional result under the least approved privileges. Include exact denied cross-tenant or unapproved operations without using workload data.
3. Retain workload and device identity, source and scope of approval, effective permissions, results and exceptions. Recheck on node, driver, capability, workload or fabric changes.
