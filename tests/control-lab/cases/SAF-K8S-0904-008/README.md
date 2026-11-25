# SAF-K8S-0904-008 pre-consumption feature validation

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0904-008 --docker-context desktop-linux
```

The Kubernetes Job executes the validator in its init container. The fixture
compares approved deterministic timestamps, declared feature bytes and a
separately supplied digest. The stale and digest-mismatch inputs stop before
the consumer starts. The accepted input runs at the exact age boundary.
A freshness-only comparison exposes why the digest check is needed.

A separate comparison uses the same fresh synthetic sample and correct digest
on both arms. When the value range is absent, the consumer receives the sample.
When the independent bounded range policy is configured, the outlier is
rejected before the consumer starts. The receipt records the validator's
anomaly decision. This is a fixed numerical outlier rule for one synthetic
feature. Production thresholds and dataset provenance require their own basis.

## Verify an adopting implementation

1. Inventory governed feature definitions, timestamp sources, offline and
   online pipelines, and every trainer or inference consumer. Pin the accepted
   input identity, canonical integrity record, rule version and permitted age.
2. Derive value or distribution bounds from approved reference data and
   document intended coverage. Verify a fresh and digest-correct approved
   canary is consumed and a fresh and digest-correct out-of-policy sample
   stops before consumption.
3. Repeat with stale and mismatched synthetic records in each implementation.
   Retain effective configuration, timestamps, reason codes, evidence of
   non-consumption, alert routing, and ownership for remediation or review.
