# SAF-K8S-0902-010 role-boundary fixture

This case exercises one narrow application boundary inside a disposable Kind cluster. It
creates an immutable ConfigMap, one Python Deployment, and one ClusterIP Service. The
digest-pinned Python image is already used by other control-lab cases. The fixture has no
model, model SDK, classifier, external call, or prompt-injection test content. Its recording
sink is local fixture state and returns the fixed answer `4`.

## Supervised run

From the control-lab checkout, after copying this directory to
`cases/SAF-K8S-0902-010/` and reviewing it, the harness entry point is:

```sh
python3 lab.py test SAF-K8S-0902-010
```

The harness must report `red`, `green`, and `positive` checks. Infrastructure failures are
reported as blocked and are not passing evidence. This scratch package does not create a
cluster; the user supervises the live run. The harness's node image is pinned in `lab.py`.

## Evidence boundary

* **Red, policy off:** one fixed ordinary request includes an extra `metadata` object with a
  benign `system: sample` label. The open schema accepts it, ignores it, and the local sink
  records only the trusted system/developer roles and user content.
* **Green, policy on:** an unknown role, a public `developer` field, and a public `system`
  field each receive HTTP 400. The recording sink remains at zero dispatches after those
  rejections.
* **Positive:** the ordinary user request succeeds; server-owned fixed context constructs
  system, developer, and user messages and increments the local sink once.

The green test is structured role construction and request-schema enforcement in this
fixture. It does not test content classification, detection accuracy, model execution,
production middleware, API gateway policy, upgrade lifecycle, or generalization to arbitrary
content. Kubernetes supplies the Pod and Service runtime, while the application code owns
request interpretation.
