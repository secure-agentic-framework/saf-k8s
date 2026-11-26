# Verify OCI integrity metadata co-retention

    python3 tests/control-lab/lab.py test SAF-K8S-0601-011 --docker-context desktop-linux

The case compares independent expiry with a cohort policy that preserves an
artifact and its exact signature, attestation and SBOM referrers. The
digest-pinned Distribution and Zot fixtures exercise fallback and native
OCI discovery, signature checking, and digest-preserving copies. The
Distribution case also verifies removal of unreferenced bytes after garbage
collection while it preserves a live reference.

A Kubernetes CronJob applies the Distribution cohort policy to five
repositories seeded with equivalent artifacts. It retires the eligible
cohort referrers first. An observer verifies the actual absence and
continuing readback for the four protected cohorts.

The Zot case preserves held and retention-active cohorts and retires
eligible referrers before the subject. It observes absence, then re-pushes
the original inert fixture bytes. The restored digests match the originals
and the DSSE signature binds to the exact subject.

For each adopted registry, verify the discovery mechanism, required
metadata types, retention and holds, allowed and denied retirement,
physical garbage collection, copies, recovery and evidence retention.
Where covered integrity records form part of required EU AI Act technical
documentation, verify the applicable retention period and access by the
competent authority as separate evidence.

- [OCI Distribution 1.1.1](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [Distribution filesystem garbage collection](https://github.com/distribution/distribution/blob/v3.0.0/docs/content/about/garbage-collection.md)
- [EU AI Act Article 18](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-18)
