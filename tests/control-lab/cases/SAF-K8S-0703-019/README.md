# Verify synthetic GPU showback generation and retrieval

```sh
python3 lab.py test SAF-K8S-0703-019 --docker-context desktop-linux
```

A Kubernetes Job calculates an informational report from synthetic usage and
rates and an ownership snapshot from fixture namespaces. It records shared,
unallocated and unpriced categories and preserves the input digest. Each
fixture identity can read its own report from the API and receives a denial
when requesting the other team's report.

The test uses invented amounts. Separate evidence is needed for deployed
sources, report distribution, owner review and finance-controlled chargeback.

## Adopter verification

1. Identify the approved report inputs and owners, including actual
   telemetry, provider charges, namespace/workload ownership and shared
   allocation rules. Verify the exact reporting window and source lineage.
2. Review how the report represents allocated, shared, unallocated and
   unpriced quantities. Reconcile representative rows to authorized
   source totals and record exceptions and owners.
3. Verify delivery to the approved recipients. Exercise an authorized
   team view and representative refusal for a different team, using the
   selected distribution mechanism.
4. Record the finance review and decision, report version, active cadence,
   corrections and approved evidence retention.
