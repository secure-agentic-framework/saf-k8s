# SAF-K8S-1001-036 — Effective audit retention configuration

```sh
python3 lab.py test SAF-K8S-1001-036 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The Kubernetes v1.36.1 Kind fixture captures a native API audit record and stores its exact bytes on a pinned Versity S3 gateway using a local-path PVC.

Separate checker Jobs read the live Object Lock configuration and report the missing default or a measured one-day default below the fixture's two-day minimum. The gateway applies the one-day default to the earlier audit version. After the default changes to three days, a new copy inherits the corrected period. The same checker flags the earlier version despite the bucket's corrected default. The fixture verifies each uploaded version ID, retrieved digest, and retention interval using the backend's LastModified and RetainUntilDate fields.

The two-day minimum is a synthetic test input. Production retention schedules, exception handling, continuous monitoring and coverage across actual audit backends require separate evidence.

[Kubernetes audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [GetObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html) · [Versity default retention behavior](https://github.com/versity/versitygw/discussions/2521)

## Adopter verification

1. Obtain owner-approved minimum retention periods by audit class, jurisdiction and operational purpose; document the authoritative schedule, date basis and exception authority.
2. Inventory each deployed audit backend and capture effective policy. Where policy defaults do not retroactively govern existing objects, inspect version-level retention dates directly.
3. Run the approved checker against deployed configuration and a non-sensitive representative old object. Verify missing, below-minimum and grandfathered versions are surfaced.
4. After any correction, verify newly created versions inherit the intended period and existing versions remain protected or follow an authorized remediation path. Confirm alert routing and closure evidence.
5. Retain the checker version and inputs, measured provider settings, version IDs and dates, exceptions and review approval. AU-11 supports the retention-duration requirement; the fixture’s two-day threshold is not a real legal minimum.

[NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
