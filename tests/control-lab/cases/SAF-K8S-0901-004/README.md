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

The current public receipt records six matched checks across red, positive, and
green phases, including the PVC transfer and fresh-volume readback. This scratch
candidate adds one bounded Job retry continuation check. The case also writes
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
hook, production data re-ingestion path, distributed worker coordination, external object
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

## File-backed PVC backup and fresh-volume restore

After the five ConfigMap and verification Job checks, the case creates a source
and a separate backup PVC. A bounded
tokenless Job writes the exact inert checkpoint JSON from snapshot B to the
source claim and copies it to the backup claim. After this Job completes, the
case creates a third PVC for restore. A second Job copies backup bytes to that
fresh volume, and an independent read-only Job verifies both backup and
restored bytes against the fixture content and expected SHA-256. The check
also requires three distinct PVC UIDs and bound PV names in the same Kind
cluster.

This covers a local synthetic file transfer and restore on the selected
cluster storage class. It does not prove storage-provider independence,
external backup durability, encryption, immutable retention, RPO/RTO, or
training framework/operator integration. Adoption must test actual
provider-specific failure domains, retention and restore against approved
data, then validate the recovered model state in its training workflow.

## Bounded Job retry and checkpoint continuation supplement

After the PVC transfer check, the case creates one case-owned PVC and a
single-completion Job with `restartPolicy: Never`, `backoffLimit: 1`, and a
90-second active deadline. Its first Pod writes the exact synthetic checkpoint
from snapshot B to the claim and exits with code 42. The retry Pod must have a new
Pod UID, retain the same Job owner UID, read and verify those exact checkpoint
bytes, and derive the next epoch from the stored checkpoint. A separate read-only Job then
mounts that same claim and independently verifies the exact continued bytes
and SHA-256. The Kubernetes PV's claim reference must match the PVC UID.
`job-retry-continuation-raw.json` records Job and Pod UIDs, exit codes, bounded
retry status, logs, claim and PV identities, digests, and the verifier result.

This witness covers a native Kubernetes Job retry over one same-cluster PVC
with inert synthetic data. Adoption evidence covers the selected training
framework, distributed recovery, storage failure domains, backup durability,
retry and recovery objectives, and model validation.

## Synthetic dataset re-ingestion retry supplement

The isolated scratch candidate preserves the seven existing assertions and
adds two focused checks. Two bounded Jobs each use one PVC and the same exact
checkpoint bytes. In the positive path, attempt one verifies an inert fixed
dataset shard, persists the checkpoint and exits to force Kubernetes retry;
attempt two re-reads and verifies the same shard before advancing the
checkpoint. A separate read-only Job verifies persisted bytes. In the negative
path, attempt one persists the same checkpoint, while attempt two receives a
different harmless shard with the same declared example identity. It must
reject the digest mismatch, leave the checkpoint unchanged, and produce the
same result under independent read-only verification.

The two added assertions cover only digest-checked synthetic shard
re-ingestion and checkpoint continuity in one disposable Kind cluster. They
do not exercise production datasets, training operators or frameworks,
distributed workers, external stores, independent failure domains, or
organizational retry, retention, approval, and recovery decisions. Raw Job,
Pod, ConfigMap and verifier observations are written to
`training-data-reingestion.raw.json` in the case evidence directory. The
scratch candidate has nine total checks: the seven prior checks plus the
positive and changed-shard checks.

[Kubernetes v1.36 Job retry and termination](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/job/)
