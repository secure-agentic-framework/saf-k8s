# SAF-K8S-0902-003 — Inference request validation

Run through the control lab harness:

```sh
python3 lab.py test SAF-K8S-0902-003 --docker-context desktop-linux
```

The harness creates a fresh disposable Kind v1.36.1 cluster. This case deploys a
single restricted Pod with three separate case-owned processes: a mock gateway,
a mock model service, and a backend recorder. All use the digest-pinned Docker
Official Python 3.13 slim image. Services are ClusterIP only; the case opens
temporary loopback port-forwards for its own checks and stops them at completion.

## Checks and evidence

`fixtures/policy.json` defines an exact JSON object schema with only string
`request_id` and `input` keys and a 128-byte cap. Each of the gateway and model
processes enforces both rules. The case submits only:

- One ordinary valid, schema-conforming synthetic request.
- One benign typed object with `input` as an integer, to show schema rejection.
- One schema-conforming object whose compact JSON body is exactly 129 bytes.

For each rejected gateway and model request, the case queries the backend's
separate `/state` endpoint before and after and requires that its accepted-call
counter does not change. For each accepted request, the endpoint must show the
expected request ID and one additional call, while the caller receives the
exact marker `SAF-K8S-0902-003-MOCK-ACCEPTED`. Evidence records statuses,
byte counts, marker equality, and backend counters; it omits request bodies.
The mock services suppress request logging and expose no external connections.

The `red` phase means expected negative-input rejection. `green` records
gateway acceptance of the valid request. `positive` contains deployment
readiness, initial recorder state, and the separate model-side checks. The
gateway and model are reported independently so a gateway result cannot stand
in for a model result.

## Coverage boundary and unresolved claims

This demonstrates exact schema and bounded body-size checks in case-owned mock
gateway and model processes on a disposable cluster. It does not demonstrate a
commercial or production gateway configuration, a real inference server,
adversarial-input detection, sanitization semantics, injection prevention,
model robustness, HTTP/gRPC equivalence, batch or streaming paths, or
organization-wide enforcement. No injection examples, attack procedures,
attack payloads, real feeds, or real targets are used. These broader source claims
remain unresolved by this case and require separate safe evidence.

## Primary references

- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) explains
  node image selection and digest pinning.
- [Kubernetes v1.36 Services](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
  documents Service routing to selected Pods.
- [Kubernetes probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/)
  documents readiness behavior used to gate the test.
- [Docker Official Python image](https://hub.docker.com/_/python) identifies
  the upstream Python image family. The case pins the image by digest instead
  of relying on a moving tag.

The disabled comparator first sends both benign boundary fixtures and
confirms that the backend records them. After enabling the controls on a
fresh Pod, the same requests are rejected and the backend count stays
unchanged. A valid request exactly at 128 bytes still succeeds.
