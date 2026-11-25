# SAF-K8S-1001-015 — Minimize inference logs before storage

```sh
python3 lab.py test SAF-K8S-1001-015 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py`.
The test starts digest-pinned Fluent Bit 5.1.2 and Loki 3.5.0 on local
Kubernetes v1.36.1. The same JSONL fixture goes to both Fluent Bit paths.
The names, identifiers and keys in the fixture are invented.

The baseline Loki query returns the full synthetic request and response,
the benign comparison, and the raw line the JSON parser rejects. With the
filter active, Loki stores only the permitted fields and masked sentinel
patterns. It stores a fixed diagnostic marker for the malformed line.
The positive check confirms that permitted metadata and clean text remain
queryable. Both queries preserve the stored labels and exact log lines.

The [pinned control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-1001-015.md)
covers wider inference data handling. This fixture covers one pre-storage
path, two invented token formats, two structured fields, and one malformed
line. Production work includes classification and detector coverage, other
logging paths, access to restricted samples, and retention governance.
See [Fluent Bit Lua](https://docs.fluentbit.io/manual/data-pipeline/filters/lua),
[Fluent Bit 5.1.2 Tail source](https://github.com/fluent/fluent-bit/blob/v5.1.2/plugins/in_tail/tail_file.c),
and [Loki query_range](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-logs-within-a-range-of-time).

## Adopter verification

1. Classify request/response fields and enumerate every application logger, sidecar, collector, queue, backend, replica, and export path that may receive inference payloads.
2. In an approved rehearsal, send synthetic canary identifiers through each path. Query raw source and every storage destination to verify prohibited fields and patterns are absent before persistence while approved operational metadata remains useful.
3. Exercise malformed, nested, alternate-encoding, and benign inputs under the approved detector suite. Verify restricted forensic samples use an authorized identity and bounded retention.
4. Retain redacted configuration, test corpus IDs (not sensitive values), destination query results, detector coverage, reviewer approval, and historical retention/access decisions.
