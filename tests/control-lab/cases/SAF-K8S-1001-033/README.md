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
