# SAF-K8S-1001-010 — Kubernetes audit levels and stages

With the SAF-K8S runner, execute:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1001-010 --docker-context desktop-linux
```

The case compares the runner's ordinary local kind API server (with no audit
flags and no case audit file) to one separately created case-owned kind v1.36.1
cluster. The latter mounts `audit-policy.yaml` and a temporary case-owned audit
file through `kind.yaml.in`. Both sides receive the same synthetic object
fixtures. The serving Deployment has zero replicas and the training Job is
suspended, so neither starts a workload container. Their pod templates carry
small CPU and memory requests to make the workload shapes explicit.

The configured policy gives a Job `Request` level before an intentionally
overlapping `RequestResponse` rule. Deployment creates use `RequestResponse`;
ConfigMap and an empty metadata-only dummy Secret use `Metadata`. Globally,
`RequestReceived` is omitted. The case checks successful API responses, exact
resource/name/verb matches, audit IDs, levels, body-field presence, and stages.
It then opens a real watch-only ConfigMap request and looks for its
`ResponseStarted` event. The local evidence file `audit-observations.json`
correlates response `Audit-Id` headers with observed audit events and records
body-field presence. The fixture Secret has metadata only.

## Expected runner observations

- Red: the default API accepts the same requests while its audit flags and
  case audit file are absent.
- Positive: all corresponding API writes succeed in the audited cluster.
- Green: each exact audit ID has the policy-selected level and expected body
  fields; normal creates have `ResponseComplete` and omit `RequestReceived`.
- Green: the watch has `ResponseStarted`, no `RequestReceived`, and neither
  body field. Cancellation may or may not yield a later completion event, so
  the assertion does not require its absence.

Production policy adequacy and admission, authorization and backend capacity
require evidence from the deployed environment.
[Kubernetes v1.36 audit documentation](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/).
