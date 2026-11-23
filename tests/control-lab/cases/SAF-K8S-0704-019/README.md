# SAF-K8S-0704-019 local demonstration

A Kubernetes admission policy limits two inert owned Pods to their intended dedicated ServiceAccounts. The test proves admission before and after enforcement, then observes the actual running Pod specs for distinct subjects, explicit projections, and disabled default token mounts. It reads no token values and performs no cloud identity exchange or cloud API calls.
