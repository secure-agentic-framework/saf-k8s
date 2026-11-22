# Synthetic evidence E-API-01

Evidence class: synthetic fixture. Describes a review prompt, not an observed deployment.

Trust boundary: external identity provider and human clients cross into the Kubernetes API endpoint; authenticated API requests enter authorization, admission, audit, and persistence paths. Data flow: caller identity and object request -> API server -> admission/authorization -> etcd. The reviewer must confirm actual front door, authenticators, authorizers, admission chain, and audit sink from deployment evidence.
