# SAF-K8S-0704-015 Effective authorization mapping

The source principal is a synthetic inventory entry. It maps to explicit Kubernetes username and group attributes used to submit read-only requests for two owned fixture ConfigMaps. The API server's actual Kubernetes RBAC authorizer grants exactly the approved read only after the scoped RoleBinding is installed. The unrelated identity and additional object stay denied.

Managed-provider authentication, group resolution and any provider authorization policy require deployed evidence.
