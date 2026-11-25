# SAF-K8S-0404-009 Certificate revocation and replacement

Run by ID on fresh Kind. A case-owned CA issues an original certificate
and a replacement using a distinct key. A live service still accepts
the first certificate until the CA records its revocation and the
service consumes the current signed CRL. The same verifier keeps
accepting the approved replacement and an independent peer.

This synthetic case verifies a CRL-capable relying party. Assess actual
issuer actions, unsupported revocation paths, propagation, and response
targets separately.

- [OpenSSL CA and CRL operations](https://docs.openssl.org/3.0/man1/openssl-ca/)
- [Python TLS verification flags](https://docs.python.org/3/library/ssl.html#ssl.VERIFY_CRL_CHECK_LEAF)

## Verify an adopting implementation

Identify issuer revocation mechanisms and every
relying party, including control-plane and application consumers. Under the
approved change process, revoke an inert certificate and publish/distribute
the current CRL or equivalent status. Retain evidence each verifier rejects
the exact old leaf and accepts a replacement and unaffected peer. Measure
propagation, record issuer retirement and residual cached sessions, and assign
owners for any consumer that cannot enforce revocation.
