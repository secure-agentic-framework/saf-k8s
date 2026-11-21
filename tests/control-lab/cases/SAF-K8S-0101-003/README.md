# SAF-K8S-0101-003 — API resource encryption and wildcard coverage

Run three disposable Kubernetes v1.36.1 kind profiles.

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

The lab covers new writes. Pre-existing object rewrite, a live KMS v2 plugin,
managed encryption and actual production resource coverage require separate
evidence. KMS v2 derives a fresh data encryption key for each encryption
from a secret seed.

- [Kubernetes v1.36 encryption at rest](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [Kubernetes v1.36 KMS provider and per-object keys](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kms-provider/)
