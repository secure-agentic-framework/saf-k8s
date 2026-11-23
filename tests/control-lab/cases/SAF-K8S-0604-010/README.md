# Verify runtime patching against an unchanged model

```sh
python3 lab.py test SAF-K8S-0604-010 --docker-context desktop-linux
```

The fixture assembles three harmless OCI runtimes and publishes them to a
temporary TLS registry. Each deployed runtime mounts the same immutable model
object. The candidate with a different computation is available for testing
but fails compatibility. A matching candidate needs an approval for its exact
runtime and model digest before the Deployment changes. The test measures the
rollout, then rolls back the runtime and checks the original model identity.

The demonstration uses a fictional runtime patch and model. Actual dependency
triggers, runtime and model compatibility, approver identity, workload
performance and production delivery require separate evidence.
