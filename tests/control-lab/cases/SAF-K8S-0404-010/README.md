# SAF-K8S-0404-010 Secure recovery on the replacement certificate

Run by ID on fresh Kind. A verifier checks a real application request
and the observed leaf fingerprint. An issued replacement by itself
leaves the live endpoint stale. A revocation-aware client rejects the
old leaf and confirms both the expected replacement and the correct
response after routing switches. An independent endpoint retains access.

The test uses a case-only CA and fixtures. Assess actual rollover
paths, consumer trust, recovery targets, and durable evidence separately.

- [OpenSSL CA and CRL operations](https://docs.openssl.org/3.0/man1/openssl-ca/)
- [Kubernetes Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
