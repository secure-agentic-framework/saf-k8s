# SAF-K8S-0802-008 Module trust evidence decision

OpenSSL checks inert marker signatures against two public fixture keys. A real Kubernetes admission policy uses the trusted result alongside modeled kernel enforcement and boot evidence. The approved observation must match the exact workload digest. The fixture includes only public keys, detached signatures, and inert marker bytes.

The additive fourth check binds a named fixture submitter to `get` on only the exact synthetic parameter ConfigMap so kubectl can perform its client preflight. An actual attempted patch must receive the Kubernetes `Forbidden` status for `patch` on that ConfigMap; an independent API readback must retain the same UID and data. Authorized test-harness updates and the three original checks remain. This is a fixture trust-record authorization check only.

This requires OpenSSL on the lab runner. It does not access host credentials, boot firmware, GPU hardware, kernel modules, or platform keyrings. Actual Secure Boot and module admission remain separate evidence obligations.

The boot-reference check keeps the same workload and digest while the fixture
operator supplies a stale boot reference, omits it, and then supplies the
expected current reference. Kubernetes denies the first two and admits the
third. These are inert review records. Replaying the live A100 host and
provider evidence requires a separate hardware run.

The [A100 reference](a100-reference/README.md) preserves evidence of two
loaded Canonical-signed NVIDIA modules and one verified Shielded VM boot.

## Live A100 signed-module admission reference

Two boots of the same A100 VM passed Google's early and late integrity
evaluations. On each boot, the loaded NVIDIA modules matched the approved
Ubuntu package signatures and the kernel reported active lockdown. The
Kubernetes case first admitted the wrong-signature-digest request with
policy absent. It then denied the wrong digest and an unreviewed node,
ran the approved witness on the reviewed node, and confirmed that the
submitter could not change the reviewed evidence.

[Reviewed live receipt](a100-reference/signed-admission-reference.json) ·
[Case-by-ID hardware replay](../../references/gcp-a100/campaign/README.md)
