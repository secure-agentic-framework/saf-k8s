# SAF-K8S-0905-039 — Review and remove a Zot read grant

    python3 lab.py test SAF-K8S-0905-039 --docker-context desktop-linux

The runner host needs `htpasswd`. The case seeds an inert OCI manifest in Zot 2.1.23. An existing registry identity reads it before review. The case compares the effective repository grant with a simulated owner-approved inventory, removes only the stale grant, and verifies the deployed policy after replacing the registry Pod. The same identity must receive an authorization denial. An independent reader must retain the declared access and obtain the same manifest from the same bound claim.

Fixture data represents review age and owner approval. Actual periodic scope, identity and approver lifecycle, other registry products, organizational governance, and production revocation deadlines require their own evidence.

- [Zot authentication and authorization](https://zotregistry.dev/v2.1.23/articles/authn-authz/)
- [OCI Distribution v1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
