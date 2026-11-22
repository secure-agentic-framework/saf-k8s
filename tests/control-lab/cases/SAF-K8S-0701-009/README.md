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
