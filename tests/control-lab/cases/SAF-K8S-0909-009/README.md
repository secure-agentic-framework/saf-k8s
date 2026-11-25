# SAF-K8S-0909-009 — Qdrant collection and administration permissions

From the SAF-K8S repository root:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0909-009 --docker-context desktop-linux
```

The runner creates a disposable Kind cluster and uses the digest-pinned open-source Qdrant v1.20.2 image. The fixture's HTTPS listener and two synthetic collections support five checks.

1. A coarse read grant returns markers from both collections.
2. The two collection-scoped JWTs can read and write their assigned collections. Opposite-collection operations and missing credentials are denied.
3. Both intended materialized results and exact point counts survive the refused operations.
4. A scoped reader and a scoped writer each receive HTTP 403 when they try to create the dedicated disposable metadata object. An independent read by the global manage identity confirms that each refusal left it absent. The manage identity can then create, inspect and remove that fixture object.
5. A signed reader past its configured expiration receives HTTP 403. A current token signed by the same fixture key for the same collection and permission returns the expected count over the same verified TLS route.

Credential values and private keys stay out of the receipts. The case operates on owned synthetic data and retains exact status and authorization observations.

## Adopter verification

- Inventory the deployed vector backends, identity boundaries, collection grants, exposed methods and routes. Test the actual direct listener and each in-scope proxy or gateway path with authorized fixture identities and harmless data. Review gRPC and distributed peers where deployed.
- Exercise current and missing or expired credentials. Compare each approved read, write and administrative action with the equivalent action from an out-of-scope identity. Verify denied actions leave the selected resource unchanged. Keep global management access with explicitly designated service or operator identities.
- Verify credential ownership, effective issuance and expiry, revocation or signing-key rotation, and intended-client recovery. For each separately controlled peer route, retain evidence of the actual peer identities and effective transport settings.
- Retain tested version, endpoint, principal role, allowed scope, before-and-after state, status, and time. Include externally managed paths and approved exceptions in the evidence inventory.

[Qdrant v1.20.2 access checks](https://github.com/qdrant/qdrant/blob/v1.20.2/lib/storage/src/rbac/ops_checks.rs) · [Qdrant authentication and JWT expiration](https://qdrant.tech/documentation/security/)
