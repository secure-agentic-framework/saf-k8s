# SAF-K8S-1001-027 — Tamper-resistant retention for Kubernetes audit backends

```sh
python3 lab.py test SAF-K8S-1001-027 --docker-context desktop-linux
```

The harness creates a disposable Kubernetes v1.36.1 Kind cluster. The case configures the native kube-apiserver file audit backend, creates one synthetic ConfigMap, selects its exact `ResponseComplete` Metadata event by namespace and object name, and stores the original newline-terminated JSONL bytes and digest as evidence.

A digest-pinned Versity v1.9.0 S3 gateway and AWS CLI fixture run entirely inside the cluster. In a case-owned bucket, the fixture writes identical audit bytes to an unlocked version before setting a three-day default `COMPLIANCE` retention rule, then writes a protected version after the rule is active. The required window is a synthetic two days. The probe independently reads the bucket default and effective object retention, successfully permanently deletes the unlocked version, confirms early deletion and shortening of the protected version are denied, and retrieves the original exact version after a benign successor becomes current.

The runner stores the selected audit JSONL bytes, their SHA-256, and the probe's sanitized raw JSON result. The probe never prints credential values or complete API error bodies. Credentials are random and scoped to the disposable local gateway. Images are pinned by digest.

## Coverage and limits

This is an integration demonstration for the pinned Versity S3 gateway's local POSIX backend and one synthetic Kubernetes API audit event. The unlocked control version is created before the bucket default is configured, to demonstrate that a bucket default protects newly written versions rather than retroactively locking old objects. Passing does not establish production audit ingestion or coverage of AI workload logs, deployed S3-compatible provider behavior, administrator separation, bucket-policy protections, multi-region copies, retention beyond the two-day synthetic requirement, capacity planning, or survival of volume/cluster loss. The conditional AU-9 crosswalk covers protection of the selected retained audit bytes and versions from premature deletion or shortening.

## Adopter evidence

1. Inventory every audit backend and event class, approved evidence window, retention start point, storage administrator and authorized deletion/change roles. Identify managed-provider responsibilities and collect authoritative provider guarantees for the exact product, mode, region and version.
2. Capture effective object/version-level retention and immutability state from the provider API or control plane. Check existing versions as well as defaults; a newly corrected default may not retrofit prior objects.
3. In approved nonproduction, retain a benign representative audit record, retrieve the exact version and compare it with an independently held digest. Verify the ordinary cleanup identity is denied early deletion or retention reduction, and that a benign successor does not replace the protected version's exact bytes.
4. Verify authorization separation, administrative override controls, change alerts, backup/replica behavior, and any applicable recovery paths with the accountable storage/security owners. Retain results for both the protected record and the permitted comparator.
5. Document exceptions, lock mode, lifecycle policy, legal/organization-defined period, monitoring and expiry behavior. Do not treat the local Versity result or its synthetic duration as Amazon S3/provider equivalence or as evidence of a legal retention schedule.

## Primary sources

- [Kubernetes v1.36 audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) — audit event structure, stages, and file backend.
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) and [Object Lock configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html) — version-specific retention, bucket defaults, and COMPLIANCE semantics used as the S3 API reference. The case does not claim Versity is equivalent to Amazon S3.
- [Versity Gateway v1.9.0 release](https://github.com/versity/versitygw/releases/tag/v1.9.0) — exact fixture version. Version 1.9.0 includes the upstream fix that stores default retention on each newly written object version; this is why the case pins this release.
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — AU-9 identifies safeguards for audit information against unauthorized access, modification and deletion.
