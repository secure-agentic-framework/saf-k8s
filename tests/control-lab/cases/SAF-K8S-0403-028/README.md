# SAF-K8S-0403-028 Exposed credential revocation and replacement

Run by ID on fresh Kind. A controlled public exposure report names
fixture lifecycles without containing a credential. Its disappearance
does not affect the actual issuer. A scoped Vault operator revokes
two fixture credentials, verifies each denial, and records distinct
replacement and retirement decisions. A live Kubernetes fixture
consumer continues using its required replacement.

Credentials are issued only inside the lab. The retained evidence
contains decisions and elapsed seconds. Verify each production issuer,
credential class, escalation threshold and dependent consumer separately.

- [NIST authenticator invalidation](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Vault token API](https://developer.hashicorp.com/vault/api-docs/auth/token)
