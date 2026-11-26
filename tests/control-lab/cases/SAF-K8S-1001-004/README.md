# SAF-K8S-1001-004 — Audit volume management

The file-backend fixture compares a broad audit baseline with a selective policy on two fresh,
single-control-plane Kubernetes v1.36.1 Kind clusters. The existing runner creates the red
cluster. case.py creates and deletes one green comparison cluster during the same normal
runner entry point:

    python3 lab.py test SAF-K8S-1001-004 --docker-context desktop-linux

## Fixture and expected comparison

Each cluster receives the same seven measured operations:

| Synthetic operation | Count | Red policy | Green policy |
| --- | ---: | --- | --- |
| List the two owned poll ConfigMaps | 5 | RequestResponse | Metadata |
| Create an inert RoleBinding granting the synthetic workload view | 1 | RequestResponse | RequestResponse |
| Attempt a ConfigMap create as a synthetic unprivileged user | 1 | RequestResponse | RequestResponse |

The red policy records all stages for the selected fixture resource types at RequestResponse. The green policy omits the
RequestReceived stage, records the five repeated ConfigMap list reads at Metadata, and
keeps the two security-relevant writes at RequestResponse. The checks compare the number
of ResponseComplete operations, audit stage counts, level/body presence, and stable
RoleBinding request/response fields. Both denied writes must return 403 and remain present
in the audit trail. The comparison saves each matched JSONL line, audit-file byte counts,
selected-line byte counts, and the configured rotation settings in the runner evidence
directory.

The fixture is small and fixed: five reads and two writes per cluster. It is a functional
positive comparison for policy behavior, not a throughput or capacity experiment. No
meaningful loss rate, API-server latency, backend service rate, buffer behavior, or alert
threshold can be inferred from this run. It does not generate AI traffic.

A separate check makes two authorized reads from an owned Pod using its projected ServiceAccount credential. The first audit rule lists a prefix ending in `*` under `users` with `level: None`. The following exact username rule records the first read at `Metadata`. The exact namespace ServiceAccount group separately selects the second read. Both reads succeed and emit exactly the selected Metadata event.

## Kubernetes v1.36.1 policy and backend syntax

The policy uses apiVersion: audit.k8s.io/v1, kind: Policy, ordered rules, level,
resource groups/resources, verbs and policy-wide omitStages. Kubernetes documents None,
Metadata, Request, and RequestResponse; it evaluates rules in order and takes the first
match. Metadata retains request metadata without request or response bodies;
RequestResponse retains both bodies. The tagged v1.36.1 audit API source defines those
levels, the stage names, and the ordered policy fields:

- [Kubernetes v1.36.1 audit API source: types.go](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/apis/audit/v1/types.go)
- [Kubernetes v1.36 auditing guide](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 audit policy reference](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)

For this disposable file-backend fixture, the kube-apiserver args are
--audit-policy-file, --audit-log-path, --audit-log-format=json,
--audit-log-maxsize=10, --audit-log-maxbackup=2, and --audit-log-maxage=7.
The policy and log paths are mounted into the API-server container. The v1.36
[kube-apiserver command reference](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
and [auditing guide](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
document those flags and the JSONL file backend.

Webhook tuning is a separate backend choice. The v1.36 auditing guide documents
--audit-webhook-config-file, --audit-webhook-mode,
--audit-webhook-batch-buffer-size, --audit-webhook-batch-max-size,
--audit-webhook-batch-max-wait, --audit-webhook-batch-throttle-enable,
--audit-webhook-batch-throttle-qps, and --audit-webhook-batch-throttle-burst.
These batching parameters apply in batch mode. For the log backend, the guide documents
the corresponding --audit-log-mode, --audit-log-batch-buffer-size,
--audit-log-batch-max-size, --audit-log-batch-max-wait,
--audit-log-batch-throttle-enable, --audit-log-batch-throttle-qps, and
--audit-log-batch-throttle-burst; batching is disabled by default for that backend,
and the guide says batching is not recommended for it. The case deliberately leaves the
backend in explicitly selected blocking mode and makes no tuning recommendation from fixture bytes.

## Follow-up work kept separate

- **Policy design:** tune ordered rules and omitted stages against the actual API-operation
  inventory, required fields, and forensic use cases; verify wildcard and subresource
  coverage before using any policy outside this fixture.
- **Backend and deployed capacity:** separately measure event byte rates and backend write
  service rates under representative sustained traffic; size buffers, batching, storage,
  rotation, retention, and forwarding for the chosen file or webhook backend.
- **Loss and backpressure monitoring:** verify the metrics and labels exposed by the
  deployed Kubernetes build, alert on apiserver_audit_event_total and
  apiserver_audit_error_total behavior plus backend-specific queue/drop/error signals,
  and exercise documented alert paths. The v1.36 auditing guide names the first two
  metrics; the control's apiserver_audit_requests_rejected_total should be checked
  against the deployed build rather than assumed to be a standard metric.

## Limits

This only demonstrates policy effects for seven case-owned API operations on fresh local
fixtures. It does not establish production completeness, cluster-wide audit coverage,
service-account exclusion safety, sustained AI training or inference traffic behavior,
backend capacity, Prometheus scraping, alert correctness, loss-free delivery under failure,
or any deployed sizing. The generated logs contain synthetic objects only.

The same command also runs a third fresh Kind cluster with a case-owned TLS audit
webhook. Five measured synthetic events must each arrive once under their observed
Audit-ID. The receiver returns one HTTP 503 before storing a scoped event, then
accepts its retry. Evidence includes the effective batching and throttle settings
and the observed native counter values. See [webhook fixture details](webhook-audit.md).
