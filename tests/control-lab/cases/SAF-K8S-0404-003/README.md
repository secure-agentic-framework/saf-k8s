# SAF-K8S-0404-003 Mutual TLS and authorization

Run by control ID on fresh Kind. Two real Kubernetes workloads complete
TLS 1.3 where both identities are expected. The service rejects missing
and untrusted client certificates, and the client rejects an incorrect
server name. A separate service decision rejects an authenticated
neighbor while allowing its intended client.

The case uses public test data and an isolated CA. Certificates are
stored only in disposable fixture locations. Production handshake,
identity issuance, rotation, equivalent channels and exception
evidence need independent review.

- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [SPIFFE X.509 SVIDs](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/)
