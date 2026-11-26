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

For an adopted pipeline, generate a rebuild decision from a reviewed update to
an approved base or dependency. Record the update and build input identities,
candidate and approved model digests, required compatibility checks and
authorized release decision. Check the actual running runtime and model after
promotion. Exercise hold and recovery using an authorized test release and
retain evidence of the recovered runtime-model combination. Verify accelerator
compatibility, Flaw Remediation scheduling and actual patch inventory in the
adopted environment.

- [Kubernetes v1.36 Deployments and rollback](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [NIST SP 800-53 Release 5.2.0](https://csrc.nist.gov/news/2025/nist-releases-revision-to-sp-800-53-controls)
