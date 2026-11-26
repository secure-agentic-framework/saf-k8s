# SAF-K8S-0405-024 Automatic emergency access retirement

Run `python3 tests/control-lab/lab.py test SAF-K8S-0405-024 --docker-context desktop-linux` from the framework checkout.

The record alone leaves the temporary grant effective. A scoped in-cluster Job reads the approved deadline and deletes only the named RoleBinding and empty Secret that anchors the short-lived fixture credential. The ordinary credential for the same account still authenticates but loses the named read. The API authenticator rejects the same bound credential, which previously performed that exact read. An independent approved reader retains access. The case imports temporary identity helpers from SAF-K8S-0405-020.

## Verify an adopting implementation

Inventory each emergency access path, credential authority, relying party, authorized operation, approval record and deadline. Document the actual credential validity, how the issuer invalidates it, the maximum propagation interval, and how sessions, offline verifiers and caches behave. Exercise the actual authorized reconciler on a scoped test grant. Observe the same operation before and after the deadline, distinguish authentication from authorization denial, and preserve an independent positive access check. Record the governing approval, sanitized timestamps and results, controller health and any missed or retried reconciliation in the approved evidence store.

Use the applicable mechanism for each issuer and credential type. The fixture tests a Kubernetes API credential bound to a marker Secret and native RBAC. When the actual authority cannot revoke immediately, verify that temporary authorization still ends at the approved boundary and document residual authenticating or cached access and its controls. Verify external providers, certificates and existing sessions through their actual relying parties.

- [Kubernetes v1.36 ServiceAccount bound token validation](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
