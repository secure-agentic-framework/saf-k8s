# SAF-K8S-0909-009

Run `python3 tests/control-lab/lab.py test SAF-K8S-0909-009` from the repository root. The case uses a pinned Qdrant instance on Kind, a local persistent claim, TLS, and fixed synthetic vector markers.

A coarse read grant can retrieve both collections. Separate short-lived collection-scoped credentials can read and write only their assigned collections. The fixture checks both directions of cross-collection read and write denial, plus an unauthenticated read. It does not add a proxy in front of Qdrant.

Verify authentication and authorization on all production listener and API paths, through client, administration and replication routes. Verify the deployed issuer and credential lifecycle, and additional controls for other backend engines.

[Qdrant security and access control](https://qdrant.tech/documentation/security/)
