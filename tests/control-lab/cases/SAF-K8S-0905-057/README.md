# SAF-K8S-0905-057 — Authenticated trust-signal review

This case preserves the current five assertions and adds three
assertions for a native OIDC reviewer path, for eight total. It has not been
run. It reuses the exact owned-issuer helper and Kubernetes AuthenticationConfiguration
approach from the retained 0905-051 reference.

Run from the framework checkout after copying these files into the registered
case directory:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0905-057 --docker-context desktop-linux
```

The original test still evaluates two inert dossiers with equally synthetic
provenance handoffs, stores explicit reasons, and exercises its original
ValidatingAdmissionPolicy and default workload identity check. The addition
creates a separate review ConfigMap and a Role restricted to that one record.
A case-owned loopback OIDC issuer authenticates a synthetic reviewer through
the native API server. A valid but unapproved OIDC identity is denied. The
reviewer identity patches and reads back one decision tied to the exact
eligible candidate digest and a hash of the evaluator's assessment record. A
second ValidatingAdmissionPolicy is added to the same `saf.example/workload=model`
Pod path as the existing policy, with the additional
`saf.example/trust-review-gate=required` selector. It denies an unreviewed
digest and admits the approved digest, while the original five checks and
their policy remain unchanged.

The new evidence contains only stable booleans. Tokens and private keys are
temporary, credentials are not passed as command arguments or written into
receipts, API requests use CA-verified HTTPS to the exact Kind loopback API,
and the API-server authentication config and issuer files are restored in a
`finally` path. The case temporarily restarts only the disposable
control-plane API server to load AuthenticationConfiguration. It does not
enable Kubernetes API audit logging; attributable durable audit delivery stays
an adopter requirement and is not claimed by the new assertions.

## Adopter checks

1. Define the decision criteria and acceptable signal evidence for each
   external source; retain source/version, exact model digest, rationale,
   decision time, reviewer identity and authority reference.
2. Authenticate the reviewer using the organization's approved identity
   provider. Confirm the authenticated identity is mapped to the authorized
   reviewer role and that publishers or workload identities cannot write or
   alter the approval record.
3. Bind the decision to the exact immutable artifact digest and criteria
   revision. Verify the actual deployment/promotion admission path reads that
   decision and rejects absent, rejected, stale or mismatched records while
   accepting the approved digest.
4. Preserve attributable approval and denial events in the governed audit
   destination; verify retention and review of signal updates, source changes,
   revocation and periodic reassessment separately.

This reference demonstrates a synthetic OIDC authentication and API
authorization path and exact digest-to-gate binding. It does not establish a
real human's identity or authority, truth or sufficiency of publisher and
community signals, ongoing supplier/model monitoring, production audit
retention, or consumer coverage outside the exact tested Pod label and
namespace.

- [NIST AI RMF 1.0](https://doi.org/10.6028/NIST.AI.100-1)
- [Kubernetes v1.36 AuthenticationConfiguration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes v1.36 RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes v1.36 ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
