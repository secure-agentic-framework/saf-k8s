# SAF-K8S-1002-006 — Sensitive metric redaction

```sh
python3 lab.py test SAF-K8S-1002-006 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. The test runs Prometheus v3.5.0 and a synthetic metrics endpoint on Kubernetes v1.36.1 Kind.

The recording rule emits the expected cohort summaries. The three original series and their invented GPU and training labels are still queryable. The test then updates metric relabeling and reloads the existing Prometheus process. Newly scraped detail is absent, the independent safe summaries track changed values, and the original detail remains available in a historical query against the same Pod.

Production validation should cover the required ingestion paths and tenant access, safe label transformations, historical retention, and any replicated downstream stores.

[Prometheus v3.5.0 configuration](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/configuration.md) · [Prometheus v3.5.0 recording rules](https://github.com/prometheus/prometheus/blob/v3.5.0/docs/configuration/recording_rules.md)

## Adopter verification

1. Inventory every production metric source and path: scrape jobs, exporters,
   Pushgateway, managed monitoring, remote-write destinations, replicas, and
   query APIs. Identify GPU topology, training configuration, model behavior,
   and inference details that the organization classifies as sensitive.
2. Capture the effective Prometheus configuration and the owner-approved
   transformation for each source. Verify relabeling is applied before new
   samples enter the intended store. Check retained labels for collisions and
   confirm any approved summaries preserve the needed cohort and time-window
   distinctions.
3. In a production-approved rehearsal, use synthetic canary series with
   distinct safe and sensitive dimensions. Show the detailed series is
   removed or minimized on every required ingestion route while the approved
   summary changes with the canary. Retain query decisions and configuration
   revision, not unrelated metric values.
4. Query both current and historical windows using the actual tenant and
   operator identities. Demonstrate authorized access to approved summaries,
   denied access to detailed data for unauthorized readers, and the approved
   exception path. If sensitive history was already stored, show the chosen
   retention, deletion, or access-restriction action and verify it at replicas
   and remote stores.
5. Attach dated, redacted configuration and query evidence, identity/role
   scope, source inventory, storage destinations, policy owner approval, and
   any unresolved source or historical-data exception to the deployment
   record.

The fixture's safe-summary continuity and retained-history result are
complementary: ingestion-time filtering does not retroactively erase samples
already stored. Production retention, access controls, external metric APIs,
and all replicated destinations need their own evidence.

The published case pins Prometheus v3.5.0 and links its versioned configuration
and recording-rule documentation for the specific relabeling and aggregation
behavior under test.
