# SAF-K8S-0403-024 — Credential lifecycle metrics and metadata freshness

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0403-024 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The case uses a pinned Prometheus and an in-cluster-only exporter. Its fixed
reference events exercise issuance rate, mean TTL, orphan rate and approved
scope exceptions. Prometheus independently checks the exact aggregate values,
the duplicate and unapproved events, and the allowed series and labels.

The native inventory path separately reads the known type and allowlisted
classification, expiry and observation metadata from empty Kubernetes
Secrets. It publishes bounded aggregates through a separate scrape job.
Prometheus verifies the baseline stale, expired and missing-expiry records,
then observes the actual metadata update and the cleared owned inventory.
Source object names, identities and values are absent from metric series.

## Verify the adopted metric workflow

1. Define the credential families, issuer and inventory sources, workload
   coverage, approved exceptions, scrape and freshness intervals, and the
   review owner. Record the provider identity and permissions used for
   each source, and the independent completeness checks.
2. Agree how to calculate each metric. Count unique approved issuances per
   observed window. Calculate mean TTL from known lifetimes and surface
   missing TTL separately. Divide orphan records by the inventoried population
   for the same period. Count only current approved scope exceptions.
3. Configure dashboards and monitoring for the adopted equivalents of
   `saf_credential_issuance_rate_per_second`,
   `saf_credential_ttl_mean_seconds`,
   `saf_credential_orphan_rate` and
   `saf_credential_approved_scope_exceptions`. Include counts, data age and
   source failures so reviewers can distinguish zero from incomplete coverage.
4. Use approved fixture records to compare a duplicate, blocked issuance,
   orphan, expired or missing lifetime, and approved exception with an
   independent issuer or inventory snapshot. Verify the observed dashboard
   data and the update delay. Review allowed series and prevent values,
   identifiers and unbounded labels from leaving the approved source.
5. Retain dated publication and review evidence, corrected exceptions,
   reviewer ownership and thresholds for follow-up. Recheck the source
   and label policy when the issuer, credential type or metrics change.

[Prometheus query API](https://prometheus.io/docs/prometheus/latest/querying/api/).
