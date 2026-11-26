# SAF-K8S-0905-015 — Model lifecycle profile enforcement

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-015 --docker-context desktop-linux` from the framework checkout.

The fixture exercises native admission for two declared lifecycle profiles,
observes ordinary workload execution under both, and verifies a protected release
update identity, pinned artifact signature and separately observed runtime drift.

The continuous-learning supplement starts an inert workload on an immutable
baseline and installs a selected UPDATE verifier. An authorized updater's proposed
change with invalid signature is rejected without replacing the original Pod.
The same identity then authorizes the fixture with valid signed provenance and
an exact immutable artifact reference. The new Pod's initializer, independent
reader and drift monitor each report the expected digest of the loaded bytes.

For adoption, inventory the approved update and release identities, trusted
signing and artifact authorities, active enforcement paths and actual model
loaders. Verify that an allowed change consumes the exact signed artifact,
that ineffective or unauthorized changes preserve the previous workload, and
that approved release decisions and later drift observations are retained.
Verify signer and artifact custody, monitoring, and protected audit retention
in the adopting environment.

- [Kubernetes v1.36 admission control](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes v1.36 Deployments](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/deployment/)
