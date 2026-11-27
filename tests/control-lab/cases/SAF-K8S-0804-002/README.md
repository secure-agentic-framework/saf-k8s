# SAF-K8S-0804-002 Attestation appraisal policy

OpenSSL verifies signed inert fixture claims. A Kubernetes Job evaluates subject, expected measurement, freshness, challenge and single-use policy over those claims. The authentic matching case is eligible and a repeated request is denied by the same process. This example includes only public fixture assets. It does not verify a hardware quote, cryptographic vendor collateral, online evidence exchange or distributed replay state.

## Cross-workload challenge consumption supplement

After the original three checks, two independent restricted Job workloads use
separate namespaced ServiceAccounts to appraise the same published inert signed
evidence bytes. Each Job verifies the signature with OpenSSL, checks the fixed
subject, reference and challenge, and evaluates the record at the fixture time
inside its signed validity interval. Only after that appraisal succeeds does
it make an authenticated Kubernetes API create for the same deterministic,
namespace-scoped ConfigMap name. Kubernetes accepts exactly one create; the
other request receives AlreadyExists and independently reads the immutable
state object. Both readers verify the same evidence digest and appraisal fields.

The fixture uses a dedicated disposable namespace. Each verifier Role grants
ConfigMap create in that namespace (Kubernetes RBAC cannot constrain `create`
by `resourceNames`) and `get` only for the exact challenge-state name. It grants
no list, update or delete. The assertion binds each result to its Job-owned Pod
and ServiceAccount, checks one create and one conflict, and records only
sanitized outcomes, evidence digest and scoped object/Pod identities. Runtime
service-account tokens are never printed or retained.

This adds a native cross-process, API-backed single-use demonstration for the
same inert appraisal input. It does not establish a hardware quote, vendor trust
chain or collateral, online freshness source, platform-specific trust policy,
authoritative nonce issuance, resistance to privileged namespace actors or
control of real workload execution. Those remain adopter evidence. The time
value remains the fixed fixture clock and the signed record remains synthetic.
