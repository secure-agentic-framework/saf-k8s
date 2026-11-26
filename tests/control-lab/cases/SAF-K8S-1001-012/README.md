# SAF-K8S-1001-012 — AI workload detection rule validation

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
