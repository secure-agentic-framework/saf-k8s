# SAF-K8S-0905-015 — Enforce model lifecycle controls by lifecycle profile

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-015 --docker-context desktop-linux` from the framework checkout.

The twelve checks cover local classification scopes and native admission for CREATE and UPDATE, release metadata and template checks, trusted signature and exact image digest verification, and a post-start check of the model file. A fixture HTTPS verifier accepts an approved inert Deployment reference and rejects a wrong signature and an image digest changed independently of its signed statement. Zero replicas keep the reference from being pulled. A separate owned workload reads safe fixture bytes. The test confirms an actual post-start file change is detected, denies an unapproved template-only update, and accepts an authorized update that changes the release and template together.

## Verify an adopted lifecycle

1. Inventory model workloads and profile labels across the namespaces and controllers in scope. Verify who can change those labels. Record the actual artifact registry and digest policy, signing trust and custody, key rotation, and all relevant CREATE and UPDATE entry points.
2. Verify with an approved release that the configured verifier binds its signature to the exact model artifact resolved from the registry. Test controlled missing and incorrect signatures, digest mismatch, and changes made through any updater or controller path. Record the admitted artifact and deployment revisions without retaining credentials.
3. For continuous updates, follow an authorized updater from its approval through the exact new signed artifact to the reported model version, protected audit record and observed workload state. Exercise controlled rejected changes and verify that deployed telemetry surfaces runtime drift, with ownership and evidence retention documented.

- [Kubernetes ValidatingAdmissionPolicy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
