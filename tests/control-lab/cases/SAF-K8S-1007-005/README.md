# SAF-K8S-1007-005 — Synthetic deployment change gate and rollback

Run from the SAF-K8S framework checkout with the existing control-lab runner:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-005 --docker-context desktop-linux
```

The runner provisions the disposable Kind v1.36.1 cluster using its configured digest-pinned node image. This case uses the runner-created `saf-test` namespace and creates one case-owned, single-replica Deployment. The only container is the official Python mock image pinned by digest; it sleeps and performs no model inference, network access, or external requests. Synthetic release and model-digest labels are metadata placeholders and do not identify real artifacts.

`fixtures/change.json` supplies a fixed fake clock, a bounded deployment window, two reserved synthetic approval roles, a risk limit, an explicit fixture approval bound to a SHA-256 fingerprint of the proposed change, and a low-risk candidate. The local gate is deterministic and makes no calls to an approval service. First, the case changes the approved candidate's risk score and removes explicit approval; it records a red assertion that the gate rejects this request and that a live API read still matches the baseline. It then evaluates the exact approved fixture. If accepted, it applies the metadata-only release change, waits for rollout, and captures the API-observed Deployment and ReplicaSet objects. Finally, it uses `kubectl rollout undo` to return to the captured baseline revision and verifies the restored release, digest placeholder, readiness, and observed generation from the Kubernetes API.

The runner records command output in its per-run evidence directory. This case additionally writes `baseline-deployment.raw.json`, `rejected-change.raw.json`, `approved-rollout.raw.json`, and `rollback-deployment.raw.json`. They contain only this case's Kubernetes Deployment/ReplicaSet objects and synthetic fixture gate results; the case creates no Secret objects. The raw API snapshots intentionally preserve server-generated UIDs, revisions, generations, status, and conditions so a supervisor can independently inspect the red, rollout, and rollback outcomes.

## Coverage and limits

Demonstrated within this disposable fixture: deterministic gate behavior with fake time; explicit approval and exact-change fingerprint checks; required synthetic approver-role checks; deployment-window enforcement; strict below-limit risk enforcement; digest syntax and exact mock-image allowlisting; rejection without API mutation; a ready API-observed Deployment revision after the approved metadata-only change; and API-observed rollback to the previous synthetic release.

The case does not establish an organization's actual approval workflow, separation of duties, deployment schedule, pipeline enforcement, or production change-management practice. It does not validate image or model provenance, registry trust, a real model artifact, inference quality/accuracy, canary traffic, latency or service health metrics, availability impact, production rollback readiness, or a production cluster. The fixture digest syntax and mock image allowlist are local test inputs, not trust claims. The control's broader rationale about security validation of models and its crosswalk claims remain unresolved by this case.

## Primary references

- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/) documents Deployment revisions, rollout history, and rollback behavior.
- [Kubernetes v1.36 rolling update task](https://v1-36.docs.kubernetes.io/docs/tasks/run-application/update-deployment/) documents rollout status checks and rollback verification.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting the Kubernetes node image; the lab pins its v1.36.1 image by digest.
- [Docker Official Images Python manifest](https://github.com/docker-library/official-images/blob/master/library/python) is the primary metadata source for the official Python image family. The pinned mock image reference is reused from a neighboring synthetic case; this case makes no claim about registry identity or image provenance beyond the reference being digest-shaped.

The same submit path enforces the approval before mutating the Deployment. Separate
negative controls cover an out-of-window request and a missing approval role. The
positive rollout and rollback also read the two exact fixture markers from the
Ready Pod.
