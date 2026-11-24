# SAF-K8S-0910-030 registry replication channel authentication

Run `python3 lab.py test SAF-K8S-0910-030` from the lab directory.

The synthetic source reads a fixed OCI manifest and its blobs from its own
Distribution registry. The peer uses a narrow TLS 1.3 receiver in front of
a separate digest-pinned Distribution instance. The client verifies both
the destination DNS name and its exact URI. The peer requires a trusted
client certificate and, with policy enabled, the approved client URI.

The baseline allows a different client URI under the same CA. With scoped
authentication, the peer rejects that URI, a missing certificate and a
wrong destination name. A separate observer container with no TLS private
key reads the actual peer Distribution manifest and blobs. The test uses
disposable issuer material and case-owned endpoints.

- [TLS 1.3 authentication messages](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
