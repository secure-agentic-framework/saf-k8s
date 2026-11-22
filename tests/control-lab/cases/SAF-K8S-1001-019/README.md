# SAF-K8S-1001-019 — AI artifact and provenance retention

```sh
python3 lab.py test SAF-K8S-1001-019 --docker-context desktop-linux
```

From the SAF-K8S checkout, use `python3 tests/control-lab/lab.py` with the same arguments. The runner creates a fresh Kubernetes v1.36.1 Kind cluster with a digest-pinned Versity S3 gateway and a persistent volume. It stores versioned synthetic model, attached provenance, and human-oversight artifacts in three separate buckets.

The test detects that a one-day default falls short of the fixture's five-, four-, and three-day thresholds. Explicit COMPLIANCE retention meets all three thresholds on new versions. The test also extends the protection on the original version IDs. An ordinary early-cleanup request deletes the unlocked comparator and receives AccessDenied for each protected version. Retrieval confirms the protected versions still contain the original bytes.

The thresholds come from the fixture policy. Approved production schedules, record coverage, lifecycle execution, cleanup privileges, and exception handling require deployment evidence.

[S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) · [Versity gateway v1.9.0](https://github.com/versity/versitygw/releases/tag/v1.9.0)
