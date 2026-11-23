# SAF-K8S-0908-005: isolated marker detection

This case is a repeatable, local Kind fixture for one narrow detection sub-capability: a deterministic request marker produces a minimal attributed alert that is delivered over HTTP to a separate receiver. A fixed ordinary request is tolerated. The model response is synthetic.

## Scope and safety

- Uses only the fixture pods and Services in the runner's isolated `saf-test` namespace.
- Uses two fixed benign JSON records in `fixture_service.py`; there is no generated attack, extraction, evasion, or inference workload.
- Contains no public endpoint, production host, external monitoring, concurrency, or scan logic.
- Does not run Docker or Kubernetes as part of this authoring session. The shared runner's `load_runtime(lab)` helper is imported dynamically from `../SAF-K8S-0908-001/case.py` when the runner invokes `run(lab)`.
- The helper must be available at that path in the runner workspace and provide the pinned local Python image expected by the fixture.

## Fixed request schema

Each model request is a JSON object with exactly these fields:

```json
{
  "request_id": "req-normal-001",
  "principal": "fixture:principal:reviewer",
  "model_id": "fixture-model-v1",
  "marker": "none",
  "features": {"signal": 0.25, "context": 0.75}
}
```

`features.signal` and `features.context` must be numeric values from 0 through 1. The second fixed request has ID `req-marker-001` and marker `review`; its feature values are also fixed and benign. Both requests receive the same synthetic success response in the baseline. Under the detector, only `marker == "review"` emits rule `fixture.marker.review.v1`; it does not block or alter the inference response.

The principal is a fixture field, not a cryptographically authenticated Kubernetes identity. The emitted alert attributes the fixed record's principal, request ID, and model ID. Production attribution must bind those fields to authenticated caller identity at the serving boundary.

## Deterministic checks

The runner reports three named checks using `lab.check`:

1. **red / baseline:** both fixed records return HTTP 200 and the alert sink has no events before the marker rule is active.
2. **green / routed alert:** the selected marker still returns HTTP 200; the separate receiver's Kubernetes pod log contains exactly one expected alert with the fixed principal, request ID, model ID, marker, rule ID, and alert ID. The detector returns success only after the receiver answers HTTP 202.
3. **positive / tolerated normal:** the normal record returns HTTP 200 under the detector and does not add a second alert.

`lab.evidence/model-marker-detection.json` records those Boolean checks and the sanitized alert after the runner completes. It excludes both feature values and request bodies. `evidence/expected-sanitized-observations.json` records the expected deterministic result as **not run**; it is not execution evidence.

Run this through the SAF Kind runner that supplies the `lab` object and invokes `run(lab)`. No standalone command is provided because cluster creation and evidence paths are controlled by that runner.

## Logs and outputs

HTTP access logging is disabled. The receiver writes only the alert envelope. Probe output includes only HTTP status and the small synthetic response. The runner evidence includes check booleans and the alert envelope, not input features. The fixture makes no claim about production log retention, access controls, transport encryption, identity provenance, receiver durability, or operational alert acknowledgment.
