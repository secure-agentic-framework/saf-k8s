# SAF-K8S-0905-025 — Model promotion separation of duties

Run from the SAF-K8S control-lab checkout with Kubernetes v1.36.1:

```sh
python3 lab.py test SAF-K8S-0905-025 --docker-context desktop-linux
```

The case uses Kubernetes `ValidatingAdmissionPolicy` to protect one inert
ConfigMap release record. It first proves the case developer's authenticated
self-approval persists without policy, resets the same release to pending,
then checks that policy denies the same request and allows a distinct
authenticated reviewer to persist the same fixed release decision. Short-lived
ServiceAccount bearer tokens are used only in temporary mode-0600 kubeconfigs;
the runner's temporary directory removes them after the run. Token bytes are
not written to evidence or command logs.

This is Kubernetes admission evidence for a synthetic approval record. It does
not demonstrate a production model registry or promotion controller, human
identity federation, reviewer quorum, tenant separation, audit retention, or
artifact execution. `review.json` records the catalog discrepancy and those
boundaries. No live case execution has been performed in this scratch review.
