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

## Verifier-result and relying-party boundary supplement

After the published five checks, a separate case-owned Appraiser Job verifies
the existing signed inert evidence and publishes six signed, bounded fixture
result records into pre-created named slots. A distinct Relying Party Job
starts only after the Appraiser Job completes and has a different
ServiceAccount. It verifies the Appraiser signature and expected audience,
subject, request reference, challenge, measurement digest, approval status, and
current wall-clock validity interval before patching one harmless
pre-created ConfigMap marker. Other signed results vary approval status,
audience, subject, request reference, or expiry; the seventh result is absent
and is accepted as unavailable only on the exact Kubernetes NotFound status
for that ConfigMap name. All other use markers remain in their
not-authorized state.

Before binding writer Roles, server dry-run patches are denied for both
identities. After binding, the Appraiser can patch only its six named result
slots and the Relying Party can read those slots and patch only the approved
use marker. Crossed writes are denied by RBAC. The test removes both
RoleBindings after their respective phases and removes the temporary fixture
signing Secret after Appraiser completion. Evidence retains result digests,
timestamps, object identities, and minimized decisions, never private key
material.

The result envelope is a local synthetic test format, not an EAT token, RATS
Attestation Result profile, vendor quote, TPM quote, or platform-rooted claim.
The test key and public-key pin are generated for this run; their handling is
not a production trust-provisioning design. This supplement demonstrates a
portable verifier-to-relying-party decision boundary and a harmless use gate
only. It does not prove hardware-backed evidence, vendor collateral appraisal,
TEE measurement semantics, online challenge issuance, deployed confidential
resource access, or runtime renewal/revocation. Those require the selected
platform, verifier, workload integration, and adopter evidence.

## Archived Intel TDX quote

A separate restricted Kind Job runs the pinned Go TDX verifier against the
historical quote published with the verifier's own regression tests. At the
reference evaluation time, it verifies the quote signature and Intel PCK
certificate chain and matches the known REPORT_DATA and MR_TD hashes. At a
later fixture time it rejects the expired PCK certificate. An independent
policy check rejects incorrect expected bindings for the same signed quote.
Enabling strict checks against the archived Intel collateral rejects this
quote because it has no matching TCB level.

Require Go 1.21 or later on the operator machine to compile the companion
Job. The Go dependencies are pinned by the included module and checksums.
The receipt records only check outcomes, reference dates, and the quote
digest. The bundled upstream test data stays local to the ephemeral test
image. This exercise covers historical verification. Live trusted time,
a fresh hardware challenge, current collateral/revocation, and the adopter's
workload and relying-party policy require separate evidence.

- [Pinned Go TDX release](https://github.com/google/go-tdx-guest/releases/tag/v0.3.1)
- [Upstream fixture and collateral checks](https://github.com/google/go-tdx-guest/blob/v0.3.1/verify/verify_test.go)

## Archived Intel collateral and revocation verification

The same Kind Job also appraises a public TDX quote captured on October 6,
2026. The host verifies the published archive digest and downloads Intel's
root certificate separately. The Job pins the root certificate's SHA-256
fingerprint and checks the exact quote and expected REPORT_DATA and MR_TD.
It evaluates the quote at 04:00 UTC on the capture date. An offline getter
supplies the Intel-signed TCB information and QE identity with their issuer
chains, the platform CRL with its issuer chain, and the root CRL. The
verifier performs signature, status and revocation checks. The fixture
checks that each archived collateral validity interval includes the pinned
time and that all four collateral objects were consumed.

The same quote is rejected when the evaluation time is after the archived
TCB information expires, and again when the platform CRL is withheld at
the capture time. `tdx-signed-collateral.json` retains the source and quote
digests, trust anchor fingerprint, evaluation times and minimized outcomes.
The capture and certificates stay in the disposable image. This exercise
covers historical collateral. Current collateral, an independently issued
live challenge, verifier outage policy and actual workload use require
their own evidence.

Run the standard control-ID test with Go and curl installed. The initial
build fetches the pinned public capture, Intel root and Go modules.

- [TDX capture and experiment provenance](https://untrustsecurity.com/evidence/#gcp-c3-standard-4-intel-tdx-quote)
- [Intel provisioning and collateral recovery](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html)


## Live Confidential Space reference

Google Cloud Attestation issued the workload token using a custom challenge. STS accepted the expected challenge and denied a different one. In a separate paired check, STS accepted the original token, rejected the same token with only its signature changed, then accepted the original again.

[Shared reproducer and evidence](../../references/gcp-confidential/README.md)
