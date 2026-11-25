# SAF-K8S-1001-033 centralized log aggregation and export

Run from the SAF-K8S framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-033 --docker-context desktop-linux
```

Fluent Bit 5.1.2 reads already-collected fixture logs representing container,
node, provider and accelerator sources. Loki v3.5.0 initially receives
only the separate comparison stream, although Fluent Bit consumed all
inputs. Enabling the scoped export makes all four main records available
in Loki. The test queries the actual backend for the original records,
expected source labels and export label. Both query responses are retained.

The comparison stream has a separate configured retention rule. This test
checks its separate label and delivery. Expiration, approved enterprise
backends, actual provider exports and deployed fleet coverage need separate
evidence.

- [Fluent Bit Loki output](https://docs.fluentbit.io/manual/data-pipeline/outputs/loki)
- [Loki query and ingestion API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)

## Adopter verification

1. Inventory already-collected node, container, managed-service, and AI
workload streams, their source owners, approved aggregation targets, and
provider export paths.
2. In an approved rehearsal, emit identifiable synthetic records per source.
   Query the actual central backend and prove each record arrives with the
   expected source labels. Include an unapproved/disabled route comparison.
3. Reconcile expected source counts and delivery lag against backend results.
   Verify retry, outage, and recovery behavior under the service's approved
   limits, and check that access follows the intended monitoring roles.
4. Retain provider/onboarding configuration, source inventory, query and
   completeness evidence, delivery/alert ownership, and exceptions. Assess
   retention under the separate retention control.
