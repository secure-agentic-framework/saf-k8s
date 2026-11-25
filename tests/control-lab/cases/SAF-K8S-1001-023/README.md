# SAF-K8S-1001-023 — Scheduled retrieval of native Kubernetes audit records

```sh
python3 lab.py test SAF-K8S-1001-023 --docker-context desktop-linux
```

From the SAF-K8S checkout, run `python3 tests/control-lab/lab.py` with the same arguments. The fresh v1.36.1 Kind cluster writes a scoped Metadata audit log. The case correlates three real API response Audit-Ids with the exact native audit lines and archives the original bytes in two gzip JSONL bundles. A separately mounted, immutable index records the lookup target and compressed SHA-256.

An unchecked reader follows a readable wrong target and returns the wrong historical event. The checked reader identifies that digest mismatch and reports a missing archive object separately. A healthy comparator retrieves a different expected record. Two Kubernetes CronJob executions each use a new Pod to retrieve the same previously archived record and digest. The evidence retains both Job schedule timestamps, Job and Pod UIDs, the actual index, and the compressed archive bytes.

The fixtures use immutable ConfigMaps for the archive and index within one disposable cluster. Production storage redundancy, format migration and retrieval coverage over the actual retention window require deployment evidence.

[Kubernetes audit events](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [CronJob scheduling and timestamps](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/) · [Immutable ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/#immutable-configmaps)

## Adopter verification

1. Inventory regulated audit archive classes, required retention ages, approved formats, index/query paths, and accountable owners for every deployed backend.
2. Retrieve approved non-sensitive records at representative ages, including the oldest required period, using the actual production index or query path.
3. Verify event identity and integrity against an independently retained digest. Exercise wrong-target, missing-object and format/index migration handling.
4. Run the scheduled retrieval job in the approved recovery environment and bind each result to its schedule, workload identity, source object and timestamp.
5. Preserve evidence of storage redundancy and restore across relevant provider or failure domains. The NIST AU-11(1) row is supporting coverage for long-term retrieval; the case does not prove a production retention window.

[NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
