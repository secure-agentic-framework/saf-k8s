# SAF-K8S-0901-004 — Training fault tolerance and security

This case exercises a narrow synthetic recovery path for the pinned control.
It creates two named immutable snapshot ConfigMaps in `saf-test`, each carrying
the canonical fixture record and its checked-in SHA-256 digest. The case reads
both back through the Kubernetes API, changes a case-owned mock recovery target,
and uses one bounded restore function for negative and positive outcomes.

The same function rejects a candidate with changed bytes and a retry request
above its two-attempt policy without changing the target. It then restores
snapshot B and compares the API-observed data, labels, and annotations with the
approved fixture. A pair of short Jobs supplies independent workload evidence:
the modified snapshot fails its digest check with `backoffLimit: 0`, and the
approved snapshot completes. Both Job specs disable service-account token
automount and use a digest-pinned official Python image. No actual ML or attack
actions, credentials, external data, feeds, or targets are involved.

## Run and inspect

The supervisor should execute the case from the SAF-K8S control-lab root using
the lab's usual disposable-cluster runner and a valid local Docker context:

```sh
python3 lab.py test SAF-K8S-0901-004 --docker-context desktop-linux
```

The current public receipt records a passed run with five matched checks across
red, positive, and green phases. The case also writes
`recovery-integrity.raw.json` under the run evidence directory. It
contains the fixture snapshot names and digests, sanitized Job status, Job
logs, and the exact API-observed target fields; it does not collect Secrets,
tokens, or kubeconfig contents. The lab's command log captures API requests and
responses for the disposable namespace.

## Receipt observations

| Phase | Recorded result |
| --- | --- |
| Red | Altered bytes produce `digest-mismatch`; the target remains unchanged. |
| Red | `attempts=3` is refused under the explicit maximum of 2; the target remains unchanged. |
| Positive | The bad-check Job has a `Failed` condition, `backoffLimit: 0`, one failed Pod, and a digest-mismatch log. |
| Positive | The approved-check Job has a `Complete` condition, `backoffLimit: 0`, one succeeded Pod, and a verified log. |
| Green | Snapshot B restores the exact fixture data, labels, and annotations observed through the Kubernetes API. |

The Kubernetes Job's `backoffLimit` bounds failed Pods for that Job; it is not
the local restore function's retry counter. This case deliberately keeps both
limits explicit and records the actual Job condition and Pod count.

## Scope and unresolved claims

The control's integrity-check, bounded-retry, and exact rollback concepts are
represented by fixture SHA-256 verification, input-attempt rejection, and API
readback of the approved ConfigMap state. The snapshots are carried through
immutable Kubernetes ConfigMaps, so the case demonstrates this Kubernetes API
handoff only. SHA-256 detects changes against the trusted fixture digest; it
does not establish who approved that digest or protect it if the trust source
is compromised.

This does not establish behavior of a training operator, framework checkpoint
hook, data re-ingestion path, distributed worker coordination, external object
store, PersistentVolume backup, independent backup domain, post-restore model
validation, or production rollback process. The control's backup-diversity,
training-job-controller, and validation-pass implementation claims remain
unverified by this case. Real snapshot authorization, key custody, retention,
and organizational recovery approval need separate evidence.

## Fixture boundary

`fixtures/snapshots.json` contains exactly two reserved synthetic snapshot IDs,
`SYNTH-SNAPSHOT-0901-004-A` and `SYNTH-SNAPSHOT-0901-004-B`. Their payloads,
metadata, approval references, and dataset URNs are inert `example` values.
The recovery target and all Kubernetes names are case-specific mocks. The
workload verifier only parses the mounted JSON and compares SHA-256 values.

## Primary references

- [Kubernetes v1.36 Jobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/) — Job failure handling, `backoffLimit`, terminal conditions, and retained Job/Pod status.
- [Kubernetes v1.36 ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/) — immutable ConfigMaps and read-only projected volumes.
- [Kubernetes v1.36 API concepts](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/) — API resource updates and `resourceVersion` conflict handling.
- [NIST FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — SHA-256 digest definition and change-detection purpose.
- [Docker Official Python Image](https://hub.docker.com/_/python) — official image family used with a digest-pinned `3.13-slim` reference.
- [kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start) — Kind cluster usage and node image context.
