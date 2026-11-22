# SAF-K8S-0904-015 — MLflow experiment access control

This case targets the catalog's MLflow example only. It starts the official
MLflow 3.17.0 full image in `saf-test`, enables the versioned basic-auth RBAC app,
and creates two fixed fixture identities and two inert experiment/run pairs.
Each identity initially has `EDIT` on every experiment. The case records
actual MLflow API listing, reads, run searches and metadata writes, then
replaces the wildcard grant with `EDIT` on that identity's exact experiment.
It repeats the same requests and checks filtered listings, exact 403 denials,
and successful reads and writes to the principal's own fixture.

The experiment is the tested project boundary. A run's experiment is its
container: MLflow 3.17 requires readable access to that experiment for run
operations, and a run-tier permission can override the experiment permission
for the operation when configured. This fixture grants no run-tier permission,
so run reads/writes inherit the experiment's exact permission. MLflow does not
provide native per-run identity isolation from an accessible experiment by
this policy; there is no claim of general tenant isolation. Artifacts, external
object-store permissions, production user provisioning, TLS/ingress, backups,
audit logging, and integrations with Kubernetes ML platforms require separate
deployment evidence.

The lab runner creates all resources in its default `saf-test` namespace.
The app uses ephemeral SQLite files, performs no model training or artifact
transfer, disables telemetry, and has no background fixture traffic. Run only
through the lab runner after review; this artifact was not run during authoring.

Pinned inputs and scope sources:

- [MLflow 3.17.0 authentication documentation](https://mlflow.org/docs/3.17.0/self-hosting/security/basic-http-auth/)
- [MLflow 3.17.0 RBAC documentation](https://mlflow.org/docs/3.17.0/self-hosting/security/role-based-access-control/)
- [Official MLflow image package versions](https://github.com/mlflow/mlflow/pkgs/container/mlflow/versions)
- [MLflow 3.17.0 release](https://github.com/mlflow/mlflow/releases/tag/v3.17.0)
