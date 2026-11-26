# SAF-K8S-0906-004 — Verify bounded data quality before release

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-004 --docker-context desktop-linux` from the framework checkout.

Three grouped checks use fixed synthetic data to observe permissive storage before gating, then test holds for declared mean shifts, outliers, values outside configured bounds and an unsupported schema version. The otherwise approved numeric payload with the wrong schema is held. A separate reader verifies the exact within-limit digest on the approved path and confirms held cases did not appear there.

## Verify an adopted quality gate

1. Inventory actual training intake and refresh paths and the approved versioned baseline for each. Record authorized owners, schema, bounds and statistical checks, sampling method and baseline change review.
2. Validate the configured thresholds and uncertainty against representative approved and held samples. Record sensitivity, tolerances, sample coverage and limitations. Recheck separately when the population, pipeline or baseline changes.
3. Exercise controlled schema, bounds, drift and outlier comparisons and verify actual holds at the governing release boundary. Independently read back the allowed artifact and verify identity, digest and tracking of held versions.
4. Trace governance of exceptions, independent cause investigation, authorized release and evidence retention. Use separate provenance, storage integrity and access controls for actual data and scope.

- [European Commission AI Act Service Desk, Article 15](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15)
