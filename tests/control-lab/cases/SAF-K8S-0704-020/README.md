# SAF-K8S-0704-020 local demonstration

The local case models a node role and a separate workload identity using narrowly scoped Kubernetes RBAC and two owned marker ConfigMaps. It narrows the node-like role and verifies the revoked and preserved decisions against the real authorizer. No kubelet identity, cloud metadata, external credentials, or actual cloud API is used.
