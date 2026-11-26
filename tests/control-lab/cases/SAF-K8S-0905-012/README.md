# SAF-K8S-0905-012 — Separate training and inference identities and resources

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-012 --docker-context desktop-linux` from the framework checkout.

The seven checks create isolated training and inference namespaces and scoped roles. Native admission refuses an inference Pod that names the fixture's training input while preserving the approved inference path. A stored inference Pod reads the expected inert local reference. Separate workloads use projected Kubernetes identities to make verified API requests. The API accepts only their own named reads and returns authorization denial on the cross-namespace comparisons. TokenReview confirms the exact fixture principal and namespace grouping, and the receipt retains stable status and identity predicates.

Complementary references demonstrate cross-environment Secret admission and metadata-only inventory in SAF-K8S-0402-011, and independently validated issuer, audience, exact subject and stage-role boundary in SAF-K8S-0904-014.

## Verify adopted environment boundaries

1. Inventory actual training, staging and inference scopes across namespaces, clusters, providers, workload identities and credential delivery routes. Record exact authorization policies, expected audiences, least-privilege scopes and service endpoints for each environment.
2. Compare permitted and refused operations through the actual Kubernetes and provider APIs with scoped synthetic identities. Verify intended issuer, audience and the exact subject and role, including controlled inference denial of training grants. Check session rotation, expiry and workload configuration provenance.
3. Exercise actual admission rules for environment-specific mounts and credential sources across each supported workload API and incoming render path. Confirm refused requests remained absent or unchanged, and authorized local workloads continue.
4. Reconcile metadata-only inventory and approved exceptions across static credentials, references and federation. Verify cloud-assumption and storage routes with the adopted provider, and capture sanitized evidence of identity, policy and scope.

- [Kubernetes ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
