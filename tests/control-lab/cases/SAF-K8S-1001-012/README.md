# SAF-K8S-1001-012 — AI workload anomaly indicator validation

Run from the framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-012 --docker-context desktop-linux
```

The Kubernetes v1.36.1 Kind fixture checks six detection predicates with one alerting example and one benign comparison each. The fabricated records cover unexpected model-serving creation, GPU use without training, a non-owner training job change, inference request rate, model storage egress outside an approved window, and an audit-policy configuration change. A separate check reads native metadata and logs for the owned mock Pod and corroborates its identity through Kubernetes Events and Node metadata. A UID join pairs this Pod with its observed Event records and excludes an inert unmatched record and an out-of-scope Pod comparison. The fixture uses no actual AI data or credentials.

For adoption, map each enabled rule to the actual source and version, field and identity transformations, threshold and time window, approved suppression, and owner. Use an approved evaluation environment or SIEM replay facility to send benign positive and negative events. Confirm receipt and correlation, check ingestion health under SAF-K8S-1001-029, and retain the matched rule revision and timestamp, event and alert identifiers, and the analyst disposition. The native Pod input and static predicates demonstrate these specific cases. Actual SIEM rules, inference and GPU signals, model storage flow data, owner mappings and end-to-end alert handling require adopter evidence.

[Kubernetes v1.36 audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Kubernetes v1.36 Events v1 API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/events/event-v1/)

## Independent native producer comparison

The fifteenth check creates a second
tokenless benign Pod with the same fixed workload marker in the owned namespace.
The case independently reads each Pod's immutable UID, one-line container log,
and actual Kubernetes Event records. The join must correlate the primary Pod
only with Events carrying its UID and the comparator only with its own Events;
the comparator's observed Events must not appear in the primary result. Both
sources remain case-owned and harmless. The original synthetic unmatched-UID
and out-of-scope comparisons remain intact; this adds an independently
observed near-miss producer alongside them.

The added result is a local correlation reference, not SIEM integration or
cross-tool evidence. For deployment, retain actual source/product/version,
field transformations, correlation keys and windows, positive/negative
replay results, ingestion and delivery health, alert identifiers, analyst
disposition, and the deployed rule revision. Keep GPU, inference, storage,
audit-policy, incident-tracking, and human-response claims tied to their real
deployed evidence.

### Map an audit record to an active policy change

Retain the source object or file revision and the deployment mechanism that
binds it to the API server's effective audit policy. Compare benign audit
behavior before and after the governed revision. Treat an isolated ConfigMap
change event as a candidate modification signal until this evidence connects
it to the active audit configuration and audit results.

- [Kubernetes v1.36 auditing and audit policy](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

## Authenticated local alert-delivery comparison

The additive sixteenth check starts a case-owned HTTPS receiver with a per-run
short-lived certificate and fixture-only Basic credentials. A tokenless,
case-owned sender evaluates the same bounded inference-rate predicate against
one fixed synthetic positive and one below-threshold benign comparator. It
sends only the positive alert over TLS with CA and DNS-name verification. A
separate tokenless observer reads the receiver's stored records and requires
the exact positive alert to be present while the benign comparator is absent.
Evidence records only statuses, booleans, IDs and record counts; key and
credential values are not logged, and no external destination is contacted.

This demonstrates one local detector-to-receiver path and exact negative
suppression. It does not demonstrate SIEM integration, production identity,
real inference/GPU telemetry, actual anomaly detection effectiveness, durable
retention, or human response. Adoption still requires an approved replay with
the deployed source, rule version, thresholds, forwarding identity, receiver,
ingestion health and analyst disposition.
