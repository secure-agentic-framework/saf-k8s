# SAF-K8S-0904-014 SeaweedFS case

This self-contained case targets the lab's default Kind v1.36.1 suite. Its
backend is the upstream SeaweedFS 4.53 multiarch image pinned to
`docker.io/chrislusf/seaweedfs:4.53@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0`.
The Python 3.13 client image is digest-pinned. The SigV4 client uses only the
Python standard library and disables proxy use.

## Access phases

The fixture creates two buckets (`saf0904014-stage-a` and
`saf0904014-stage-b`) and writes a distinct fixed public marker under each
`artifacts/` key prefix. Two static stage identities use fixed, inert fixture
credentials. Under the broad configuration each identity has `Read` and `Write`
across both buckets. The red probes have each identity GET both seeded markers
and PUT a fixed cross-stage object.

The case then changes only the two stage identities' `actions` in the mounted
SeaweedFS S3 config: stage A receives `Read/Write` only for the stage-A bucket;
stage B only for the stage-B bucket. The admin seeder identity, identity names,
credentials, data, image digest, Pod UID, and Service ClusterIP remain fixed.
The scoped file is projected, the same container process is restarted in the
same Pod to reload its static config, and the case checks that both seeded
objects still round-trip. It repeats the same cross-stage GET and PUT requests
with the same access keys and expects HTTP 403. Each stage must still GET its
own seeded marker and PUT/read back an own-stage marker. Admin reads verify that
the previously allowed cross-stage writes were not overwritten by the denied
requests.

The store runs `weed mini` in a single case-owned Pod with `emptyDir` data. The
container restart preserves the Pod-scoped `emptyDir`; the case verifies this
through the Pod UID and successful marker readbacks. It does not claim durable
storage. The client receives the config map only because all S3 credentials are
explicitly public, non-production test fixtures.

## Lifecycle policy scope

The scoped phase writes and reads back distinct S3 Lifecycle configurations on
the two stage buckets. Both rules select `artifacts/`; stage A is configured for
one day and stage B for two days. This demonstrates provider configuration
storage and GET readback for distinct stage rules. It does not wait for either
rule to expire an object. A real expiry check needs the applicable SeaweedFS 4.53 expiration execution path
(per-write TTL and/or lifecycle worker) to be active and the configured window to
elapse. The fixture does not establish which path `weed mini` activates, and it
does not shorten time, inject timestamps, or call an internal test-only clock.
Therefore physical expiration, object deletion, and storage-byte reclamation
remain unproven.

SeaweedFS 4.53 tagged source implements S3 lifecycle `PUT` and `GET` handlers
that store/read the XML; its handler rejects enabled `Transition` and
`NoncurrentVersionTransition` rules because transition infrastructure is not
implemented. This fixture uses only enabled `Expiration.Days` and a prefix
filter. The narrow readback evidence does not establish timed enforcement.

## Boundaries

This is a backend IAM and lifecycle demonstration. It does not prove workflow
controller stage-to-identity assignment, Kubernetes projected identity, OIDC or
cloud identity federation, multi-tenant production isolation, encryption at
rest, archival, legal hold, retention compliance, external object-store
semantics, or timed expiry. Credentials and markers are inert public fixture
values and must never be reused.
