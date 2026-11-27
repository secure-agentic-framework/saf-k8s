# SAF-K8S-0903-001 — Serving-layer input rejection and explanation access

    python3 lab.py test SAF-K8S-0903-001 --docker-context desktop-linux

The fixture sends the same fixed benign request through a Service with a deterministic rejection rule disabled and enabled. A backend counter proves whether the request reached the inference stand-in. The enabled rule records a fixed ID and reason. A clean request still reaches inference.

The fixture compares two Pods against the same explanation listener before and after a namespace- and label-scoped NetworkPolicy. The monitoring Pod can still read a fixed synthetic explanation. The inference listener has no explanation route. Running the case requires a Kubernetes network implementation that enforces NetworkPolicy.

The case requires separate deployment evidence for detector effectiveness, explanation fidelity and rate limits, label and identity governance, alternate routes, production redaction and evidence retention. The lab and independent framework runs passed on separate Kubernetes v1.36.1 kind clusters. The framework retains the passing receipt under tests/control-lab/verified/.

The supplemental checks use the same pinned image and inputs. The monitoring
Pod reads the fixed explanation twice and receives a stable HTTP 429 on the
third read. This demonstration caps disclosures within one serving process.
It records responses and the number of disclosures in
`explanation-policy-observations.json`.

The gateway then checks its independent in-cluster validation Service before
forwarding to the model stand-in. Scaling the owned validator Deployment to
zero produces a stable HTTP 503 for a previously accepted input, and the
independent backend count stays fixed. After the validator returns, the
accepted input reaches the backend and the fixed negative still produces HTTP
422. `validation-failure-recovery.json` retains endpoint readiness, responses,
and independent backend counts. The checks use fixed benign inputs. Real
model evaluation, deployed authorization, alternate paths, distributed
quotas, and audit retention require evidence for the adopted deployment.
