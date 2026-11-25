# SAF-K8S-0101-003 — API resource encryption and wildcard coverage

Run the disposable Kubernetes v1.36.1 kind profiles.

```sh
python3 lab.py test SAF-K8S-0101-003
```

The same synthetic Secret and zero-replica Deployment are written through
each API server. Stock etcd storage contains both public fixture markers.
A temporary Secretbox configuration using `*.` encrypts the core Secret and
leaves the Deployment's grouped record unchanged. The same configuration
with `*.*` encrypts both. Authorized API reads return the original markers
in all profiles.

The read evaluates two exact fixture keys and reports only marker presence
and the expected encryption prefix. It does not retain etcd values or keys.
The configured key is randomly generated for each local profile, stored only
in a mode-0600 temporary file and removed at cleanup.

## Existing object rewrite

A separate disposable API server starts with identity storage and creates
one named synthetic Secret. After flipping the first writer to Secretbox,
the case waits for the native successful reload metric and confirms the
old etcd record remains byte-for-byte unchanged. One exact authorized API
update rewrites it, and the verifier sees the expected encryption prefix
and preserved authorized read. Key and object data stay out of evidence.

## Adopter verification

1. Pin the Kubernetes and provider release. Inventory intended resource
   classes, exact exceptions and effective provider order on each API
   server. Verify the configured provider and document approved key
   ownership, health, rotation and fault recovery.
2. Check both new and pre-existing records for each intended class through
   an approved sanitized inspection or version-specific provider evidence.
   Verify exact ciphertext metadata and authorized read behavior with inert
   fixtures. Keep keys and plaintext payloads outside the evidence.
3. Preserve a controlled read-compatible transition and schedule the
   approved rewrite workflow. Confirm each intended version changed, and
   remove legacy decryption or identity fallback only after the inventory,
   successful recovery and authorized reads have been verified.
4. For KMS v2, review the plugin and external key protection, key identity,
   availability and access controls. The companion
   [native KMS v2 case](../SAF-K8S-0403-019/README.md) exercises a real
   plugin protocol bridge and cold-start unwrap. The
   [KMS least-privilege case](../SAF-K8S-0403-020/README.md) exercises
   restricted key operations. Collect actual provider custody, policy
   and version-specific attestation for deployed environments.
5. Track counts and scoped outcomes with an owner. Retain any unsupported
   resources, exceptions, recovery limits and unverified provider fields
   alongside the completed observations.

- [Kubernetes v1.36 encryption at rest](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Kubernetes v1.36 KMS provider and per-object keys](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
