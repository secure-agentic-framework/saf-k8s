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

## Verify an adopting interface

## Reference evidence

The current local case makes 13 checks on disposable Kubernetes v1.36.1 Kind clusters. Separate lab and framework runs passed all 13 checks and were deleted. The owned mock gateway and model each reject one benign wrong-typed JSON object and a valid object one byte above the 128-byte limit, accept the valid boundary request, and show rejected requests did not reach the independent backend recorder. This is reference behavior for those fixtures; it does not validate a deployed product.

## Owner procedure

1. Inventory each deployed inference entry point and its request formats: gateway, model endpoint, and each claimed HTTP, gRPC, batch, or streaming route. Record release/configuration identity, effective schema, body limit, and where each check is enforced.
2. At an approved test boundary, submit harmless synthetic requests: one valid request at the permitted boundary, one wrong-typed object, and one otherwise-valid request just over the configured byte limit. Avoid real prompts, sensitive content, attack strings, and production data.
3. Retain response status and stable error category, request byte count, and backend/handler counter delta. Confirm invalid requests are rejected at each claimed enforcement layer and are not forwarded; confirm the valid boundary request succeeds and reaches the intended handler.
4. Repeat for each ingress/protocol path in scope. Preserve effective configuration, version, test time, route identity, and sanitized observations. Do not count a gateway result as proof of the model's independent validation.

This procedure verifies schema and size behavior only. It does not establish semantic input sanitization, adversarial-input or injection detection, model robustness, output filtering, privacy behavior, transport encryption, or organization-wide enforcement. Those need separate controls and evidence. The open adopter child `saf-lab-0902-003.1` remains necessary for real stacks and deployed path coverage.

## Mapping correction boundary

The accompanying scratch mapping plan removes only NIST SP 800-53 Rev. 5 AC-22: this case is ClusterIP-only and does not review content published on a public-facing system. The other 25 rows have not been certified by this pass and remain for clause-level review before the parent control can be called framework-ready.

Primary source: [NIST SP 800-53 Rev. 5 final publication](https://csrc.nist.gov/pubs/sp/800/53/r5/final), AC-22 Publicly Accessible Content. The bounded input-validation proof is described in the control lab's exact [case README](../saf-k8s-control-lab/cases/SAF-K8S-0902-003/README.md).

## Reviewed mapping scope

The mapped Article 15(5) cybersecurity duty is broader than one interface
validator. The revised relationship is limited to the input-size and request
shape contribution. AI RMF MAP 2.2 concerns documented AI system knowledge
limits, intended operating context and human oversight. The request fixture
does not supply that documentation.

- [Regulation (EU) 2024/1689 as published](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
