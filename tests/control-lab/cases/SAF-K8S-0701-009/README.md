# SAF-K8S-0701-009 — Retain precise training and model artifact versions

```sh
python3 lab.py test SAF-K8S-0701-009 --docker-context desktop-linux
```

A digest-pinned Versity S3 gateway and AWS CLI run in an isolated Kubernetes
cluster. The gateway stores temporary bytes in an emptyDir, the client uses
only the gateway's in-cluster address, and throwaway credentials stay inside
the fixture. The mutable baseline overwrites and deletes an ordinary object.

The test separately exercises a synthetic dataset and a model artifact.
For each, a COMPLIANCE lock protects the original object version. A same-key
PUT creates a new current version while the original version remains readable
with the exact original digest. The same credential permanently deletes a
separate unlocked version and is refused permanent deletion of the locked
version. A simple delete adds a marker that hides the current key; an explicit
lookup of the retained version still recovers its bytes.

Use exact version IDs and digests for immutable inputs. Create-only names or
controlled publication can address changes to logical references. Verify
production retention, authorized changes to logical references, durability,
replication, and storage administrator controls in the intended backend.

[Versity S3 gateway v1.9.0](https://github.com/versity/versitygw/releases/tag/v1.9.0) ·
[Amazon S3 Object Lock semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) ·
[Amazon S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html)

## Adopter verification

1. Identify exact immutable-version support, retention policy and every
   writer, reader, retention administrator and provider ownership boundary.
2. In an approved fixture, write a new version and retrieve the exact
   retained version and digest. Verify the effective refusal to
   permanently delete or overwrite required retained data.
3. Review actual version pins and authorized reference updates for every
   consumer. Record signed lineage, replication and provider audit evidence.
4. Exercise key recovery, retention expiry and approved disposition for
   the selected store. Preserve expected data, authority, and recovery result.
