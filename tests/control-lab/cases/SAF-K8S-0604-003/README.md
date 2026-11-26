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

## Adopter verification

The reference uses pinned fixture images, OpenSSL and htpasswd. For each governed registry and approved alternate, record the service and client versions, authenticated publisher and reader identities, and supported discovery path. Identify whether the governed subject is an image manifest or an OCI index and use its exact digest at publication and consumption. Verify discovery and bytes through each required path and retest after the required retention interval. Record the exact subject, SBOM descriptor, checked byte digest, discovery response, access decision and retention evidence.

Approve the SBOM producer and inventory content through an independent review. Verify that the approved source and release correspond to the exact subject, including child manifests where policy requires that coverage. Confirm each governed reader, publisher and deletion authority with an owned artifact. Validate pagination or the approved fallback when the service uses it.
