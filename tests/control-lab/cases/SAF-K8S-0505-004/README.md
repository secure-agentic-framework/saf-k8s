# SAF-K8S-0505-004 — API server audit observations

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0505-004 --docker-context desktop-linux
```

The Kubernetes v1.36.1 Kind API server writes native Metadata audit events. Three case-owned ConfigMap reads compare a permitted request, an explicitly excluded request, and an RBAC authorization denial. The detector starts with no rule and then matches the exact 403 Audit ID without flagging the ordinary request.

A separate TLS-verified request with an inert invalid bearer value goes to the owned loopback API. The fixture compares the returned 401 and Audit-Id with the native ResponseStarted event, verifies it has no authenticated actor or payload objects, checks the recorded peer context, and verifies only the enabled 401 rule produces the matching finding. The 403 comparator uses ResponseComplete. Evidence contains stable assertions rather than the bearer string or audit IDs.

The repeated-request case issues four permitted reads of one owned ConfigMap from one service account and one read from a separate service account. The detector groups exact native completed read events by actor in a bounded 60-second window. With the rule disabled, neither actor produces a finding. When the fixture threshold of three is enabled, only the repeated actor produces a finding. Choose deployment thresholds using approved traffic baselines and replay harmless representative patterns.

For adoption, inventory the API endpoints, policy rules and event stages across managed and self-hosted control planes. Confirm each expected event reaches the approved destination. Validate the source address trust chain at direct, proxy and load-balancer paths before using an address to attribute a request. Replay representative benign denied and admitted requests and verify rule thresholds, duplicates, alert delivery, responder access, and retention with redacted evidence. Record the alert destination, delivery time, deduplication behavior and disposition at the assigned reviewer.

[Kubernetes v1.36 audit logging](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [Kubernetes v1.36.1 API request filters](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/server/config.go)
