# SAF-K8S-0703-022 — Accelerator activity monitoring and policy-context triage

Run `python3 tests/control-lab/lab.py test SAF-K8S-0703-022 --docker-context desktop-linux`
from the framework checkout.

The first three checks run the pinned Prometheus rules against case-owned
synthetic activity and policy-context metrics. An activity-only threshold also
flags the explicitly approved high-activity sample. The context-aware rules
report missing context and policy mismatch separately and keep approved high
activity observable without a review alert.

The fourth check supplies expected workload and device pairs and their
synthetic sample timestamps. The fresh approved sample stays visible. One
separate sample is older than the fixture window, another expected pair lacks
a sample, and a separate in-cluster scrape target is unavailable. Prometheus
reports those three conditions separately and preserves the initial review
decisions. The receipt records stable states and identifiers.

For adoption, verify actual hardware and exporter coverage against the
approved inventory, timestamp and clock trust, joins to governed workload
and policy identities, protected alert delivery, and authorized review.
Record the disposition and evidence quality for each investigated alert.

- [Prometheus 3.5 query functions](https://prometheus.io/docs/prometheus/3.5/querying/functions/)
- [Prometheus 3.5 vector matching](https://prometheus.io/docs/prometheus/3.5/querying/operators/)
