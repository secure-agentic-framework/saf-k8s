# SAF-K8S-1001-012 — AI workload detection rule validation

Run from the framework root.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-012 --docker-context desktop-linux
```

The Kubernetes v1.36.1 Kind fixture checks six detection predicates with one alerting example and one benign comparison each. The fabricated records cover unexpected model-serving creation, GPU use without training, a non-owner training job change, inference request rate, model storage egress outside an approved window, and an audit-policy configuration change. A separate check reads native metadata and logs for the owned mock Pod and corroborates its identity through Kubernetes Events and Node metadata. A UID join pairs this Pod with its observed Event records and excludes an inert unmatched record and an out-of-scope Pod comparison. The fixture uses no actual AI data or credentials.

For adoption, map each enabled rule to the actual source and version, field and identity transformations, threshold and time window, approved suppression, and owner. Use an approved evaluation environment or SIEM replay facility to send benign positive and negative events. Confirm receipt and correlation, check ingestion health under SAF-K8S-1001-029, and retain the matched rule revision and timestamp, event and alert identifiers, and the analyst disposition. The native Pod input and static predicates demonstrate these specific cases. Actual SIEM rules, inference and GPU signals, model storage flow data, owner mappings and end-to-end alert handling require adopter evidence.

[Kubernetes v1.36 audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Kubernetes v1.36 Events v1 API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/events/event-v1/)
