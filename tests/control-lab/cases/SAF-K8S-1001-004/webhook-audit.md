# saf-lab-1001-004.1 local evidence candidate

This directory is a runner candidate for supervised execution. It has not been
run. It creates one fresh, single-node Kind cluster using the pinned Kubernetes
v1.36.1 node image, a namespace-scoped audit policy, and a case-owned TLS
receiver. The API server's webhook URL is a fixed ClusterIP inside the Kind
cluster. There are no host port mappings, port forwards, public endpoints, or
external audit destinations.

## Fixture and bounded behavior

The case performs exactly five measured API operations: creates of five uniquely
named ConfigMaps with inert synthetic values in `saf-test`. The audit policy
selects only those ConfigMap creates and records only `ResponseComplete` at
`Metadata` level. Before each create, the candidate captures the `Audit-Id`
returned for that API request. It then waits at most 45 seconds for the receiver
to retain exactly one event with that ID, resource, namespace, name, verb, stage,
level, and successful response code. Duplicate IDs, missing IDs, extra selected
fixture events, or bodies in the metadata event fail the case.

Before the first measured create, the receiver is armed to answer its next
webhook POST once with HTTP 503 without retaining that request body; it accepts
the subsequent retry normally. The case records the receiver's status and
Audit-IDs for both attempts. It requires one 503 attempt and a later successful
attempt carrying the exact expected event. Delivery and selected metrics have
bounded waits. If retries do not recover, the case stops with a failure rather
than expanding the fault or sending elsewhere.

The API server explicitly selects batch mode, batch buffer size 16, batch
maximum size 1, batch maximum wait 500ms, throttle enabled, throttle QPS 10, and
throttle burst 2. The runner records those live arguments from the kube-apiserver
static Pod. It captures raw metric lines before and after the fixture and checks
the native `apiserver_audit_event_total` increase against the five delivered
events, plus presence and values of `apiserver_audit_error_total` for the
`webhook` plugin and `apiserver_audit_requests_rejected_total`.

The injected 503 is recovered by the webhook retry path. A successful retry is
not expected to increment the terminal audit-error counter; the required
observable error evidence is the receiver's recorded 503 followed by a 200,
along with the native counter samples and exact recovered delivery. The case
records the counter delta without asserting that a transient attempt failure is
a terminal audit error. In batch mode, API requests may complete before webhook
delivery; the case's exact-delivery wait checks the backend separately.

## Scope limits

Five small operations, one injected transient HTTP response, and one local
single-node cluster do not measure throughput, sustainable service rate,
buffer saturation, event loss under load, latency objectives, storage sizing,
retention, multi-node behavior, alert delivery, or production capacity. They
cannot support production tuning recommendations. The receiver and ConfigMaps
contain no credentials, external data, or active workload.

The separate production validation remains on `saf-lab-1001-004.2`. No cluster
was started, no Docker state was changed, and no checkout or Bead was modified
while preparing this candidate.

## Reviewed case and issue sources

- Published baseline: `saf-k8s-publish/tests/control-lab/cases/SAF-K8S-1001-004/README.md`
  and `case.py`. That demonstration is a file-backend red/green audit-policy
  comparison; it explicitly does not exercise the webhook backend, native
  backend failure response, or backend capacity.
- Existing TLS receiver example: `saf-k8s-publish/tests/control-lab/cases/SAF-K8S-1001-026/`
  (`case.py`, `receiver.py`, `audit-policy.yaml`). This candidate reuses the
  documented fixture pattern of an API-server webhook to an in-cluster TLS
  receiver, without its PVC lifecycle scenario.
- Issue text: local `.beads/issues.jsonl`, issue `saf-lab-1001-004.1`, title
  “Verify Kubernetes audit backend tuning and health telemetry.” Its stated
  acceptance asks for v1.36 backend sources, bounded low-volume fixture,
  exact deliveries, native counters/alerts, preserved flags, and exact gaps;
  the parent and sibling `.2` keep deployed capacity separate. `bd --sandbox
  show` was attempted but could not open the Beads database because the managed
  sandbox denied its lock-file access. The checked-in issue record was read
  directly; the Bead was not changed.

## Version-pinned implementation and documentation

The implementation URLs below are pinned to the Kubernetes `v1.36.1` tag.
They identify the source paths reviewed for event counters, plugin errors,
webhook retry and batch behavior, and kube-apiserver audit flags:

- [`staging/src/k8s.io/apiserver/pkg/audit/metrics.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/audit/metrics.go)
- [`staging/src/k8s.io/apiserver/pkg/audit/audit.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/audit/audit.go)
- [`staging/src/k8s.io/apiserver/plugin/pkg/audit/webhook/webhook.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/plugin/pkg/audit/webhook/webhook.go)
- [`staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go)
- [`staging/src/k8s.io/apiserver/plugin/pkg/audit/buffered/buffered.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/plugin/pkg/audit/buffered/buffered.go)
- [`staging/src/k8s.io/apiserver/pkg/server/options/audit.go`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/server/options/audit.go)
- [`test/instrumentation/documentation/documentation-list.yaml`](https://github.com/kubernetes/kubernetes/blob/v1.36.1/test/instrumentation/documentation/documentation-list.yaml)

The v1.36 static documentation specifies webhook batch mode, the selected
batch/throttle flags, and the semantics of `apiserver_audit_event_total` and
`apiserver_audit_error_total`:

- [Kubernetes v1.36 auditing guide](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 metrics reference](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/)
- [Kubernetes v1.36 kube-apiserver flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

The native audit metrics are ALPHA in the v1.36 metrics reference. This case
records what the pinned local API server actually exposes; it does not treat
their existence as a production alert or monitoring proof.
