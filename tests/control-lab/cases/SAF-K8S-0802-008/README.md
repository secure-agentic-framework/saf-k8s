# SAF-K8S-0802-008 Module trust evidence decision

OpenSSL checks inert marker signatures against two public fixture keys. A real Kubernetes admission policy uses the trusted result alongside modeled kernel enforcement and boot evidence. The approved observation must match the exact workload digest. The fixture includes only public keys, detached signatures, and inert marker bytes.

This requires OpenSSL on the lab runner. It does not access host credentials, boot firmware, GPU hardware, kernel modules, or platform keyrings. Actual Secure Boot and module admission remain separate evidence obligations.
