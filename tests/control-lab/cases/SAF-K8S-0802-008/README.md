# SAF-K8S-0802-008 Module trust evidence decision

OpenSSL checks inert marker signatures against two public fixture keys. A real Kubernetes admission policy uses the trusted result alongside modeled kernel enforcement and boot evidence. The approved observation must match the exact workload digest. The fixture includes only public keys, detached signatures, and inert marker bytes.

The additive fourth check binds a named fixture submitter to `get` on only the exact synthetic parameter ConfigMap so kubectl can perform its client preflight. An actual attempted patch must receive the Kubernetes `Forbidden` status for `patch` on that ConfigMap; an independent API readback must retain the same UID and data. Authorized test-harness updates and the three original checks remain. This is a fixture trust-record authorization check only.

This requires OpenSSL on the lab runner. It does not access host credentials, boot firmware, GPU hardware, kernel modules, or platform keyrings. Actual Secure Boot and module admission remain separate evidence obligations.

The [A100 reference](a100-reference/README.md) preserves evidence of two
loaded Canonical-signed NVIDIA modules and one verified Shielded VM boot.
