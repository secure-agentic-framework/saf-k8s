# SAF-K8S-0801-009 local demonstration

The case writes a synthetic label on the owned Kind node. Revoking the fixture tenant's Node list permission blocks the whole Node API response while a designated operator retains access. The tenant still reads its own scheduled Pod and sees the placement field. No accelerator, real topology, or production node is inspected.

## Adopter verification

1. Inventory the topology sources available on the deployment, including Node labels, DRA ResourceSlice or claim APIs, vendor inventory, metrics, events and workload status.
2. For each tenant and operator role, verify actual API responses for supported reads with sanctioned identities. Include cluster-scoped inheritance and namespaces whose Pod placement legitimately remains visible.
3. Verify that topology or capacity data in dashboards, metrics endpoints and support interfaces has an independently authorized path. Record intended visibility, allowed and denied responses and authorized exceptions.
4. Retain effective identity and policy revisions together with sanitized results. Recheck after inventory, dashboard, RBAC and accelerator topology changes.
