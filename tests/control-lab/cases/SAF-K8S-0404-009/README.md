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
