# Discover and verify an OCI SBOM

```sh
python3 lab.py test SAF-K8S-0604-003 --docker-context desktop-linux
```

This fixture attaches CycloneDX documents to two exact image manifest digests
with pinned ORAS. The Kind Pods retrieve and verify an approved inventory from
an authenticated Zot TLS registry using the Referrers API, and independently from a
legacy TLS registry that returns 404 to that query. The legacy read resolves
the standard referrers tag. The consumer detects a different subject, bytes
that differ from the published descriptor, and a correctly associated
attachment outside its approval list.

The Zot repository admits a fixture publisher and a read-only user. It
rejects anonymous discovery and denies writes and deletion to the reader.
The examples need the pinned fixture images, OpenSSL and htpasswd. They
exercise a bounded response from the owned repository. Production identity
and repository permissions, additional
registry implementations, paginated results, retention and producer identity
need their own evidence.
