# SAF-K8S-1007-005 — Synthetic deployment change gate and rollback

Run from the SAF-K8S framework checkout with the existing control-lab runner:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1007-005 --docker-context desktop-linux
```

The runner provisions a disposable Kind cluster. One case-owned Deployment
serves two fixed linear model fixtures in sequence through the same Kubernetes
Service. The digest-pinned Python process loads a read-only immutable ConfigMap
and verifies the exact SHA-256 before becoming ready.

The local change gate checks a fixed deployment window, fixture approval,
required synthetic roles, configured risk limit, exact approval fingerprint,
and allowed image. The first requests are refused for invalid approval,
a mismatched change, late submission, or a missing approval role. The case
verifies that the running baseline stays unchanged. An approved rollout
serves the candidate model. `kubectl rollout undo` then restores the exact
baseline file and its served predictions. A separate tokenless Pod uses the Service DNS name to check
three fixed inputs before the change, after refusal, after approved rollout,
and after rollback. Raw observations are in `served-model-predictions.json`.

## Adoption

Collect the actual approval decision, roles, deployment window, governed
pipeline record, and artifact digest. In an authorized representative
release, verify readiness, model behavior and acceptable quality and latency.
Where traffic is staged, verify the selected candidate receives the intended
fraction of traffic. Record the known-good digest, rollback result and
post-rollback health and quality checks.

## Primary references

- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/) documents Deployment revisions, rollout history, and rollback behavior.
- [Kubernetes v1.36 rolling update task](https://v1-36.docs.kubernetes.io/docs/tasks/run-application/update-deployment/) documents rollout status checks and rollback verification.
- [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/) documents selecting the Kubernetes node image; the lab pins its v1.36.1 image by digest.
- [Docker Official Images Python manifest](https://github.com/docker-library/official-images/blob/master/library/python) is the primary metadata source for the official Python image family. The pinned mock image reference is reused from a neighboring synthetic case; this case makes no claim about registry identity or image provenance beyond the reference being digest-shaped.

## Crosswalk evidence

The current crosswalk retains four conditional contributions. Bind actual
release history to the applicable provider documentation, require evidence of
separate authorized approval where dual approval applies, preserve the previous
configuration and include the observed change and rollback in the applicable
monitoring plan.

[NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
