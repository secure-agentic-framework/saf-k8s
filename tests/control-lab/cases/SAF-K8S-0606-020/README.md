# Verify Helm merged values and dependency integrity

```sh
python3 lab.py test SAF-K8S-0606-020 --docker-context desktop-linux
```

Helm installs only local synthetic charts that create inert ConfigMaps. The
values schema refuses a disallowed marker from the normal CLI override path.
Rebuilding the fixture dependency at the same declared version preserves
`Chart.lock` while producing different package bytes. An independent archive
digest check refuses those bytes. The approved package installs with the
allowed CLI value and the original dependency marker.

The case illustrates a local release gate. Actual deployed dependency sources,
authentic package provenance, security-sensitive values and controller policy
require separate verification.

## Security-relevant rendered values

A separate render-only comparison rejects a requested service account token automount through the merged-values schema and verifies the approved value renders as `spec.automountServiceAccountToken: false` in the exact inert Pod. Its manifest is never submitted to the API. The local dependency comparisons retain the distinction between version resolution and package byte integrity.

## Adopter verification

1. Inventory chart and dependency sources, including mirrors, transitive dependencies, and every supported values input (defaults, `-f` files, `--set`, environment/automation inputs, and controller-specific overrides). Define the security-sensitive values and the permitted values for the deployed chart versions.
2. Enforce the merged-value policy at the actual deployment boundary. Test rejected overrides before any API object or release is created; demonstrate approved normal overrides still render and deploy correctly.
3. Resolve and review `Chart.yaml` / `Chart.lock`; retain exact resolved names, versions, repository/source, and the lock digest. Helm documentation describes `dependency build` as reconstructing dependencies from `Chart.lock`; the lock is resolution metadata and must not be treated as proof that retrieved archive bytes are authentic.
4. For every consumed direct and transitive dependency, verify the exact archive bytes against an independently approved digest or signature, and bind that expectation to approved supplier/repository identity. Fail closed on missing or mismatched evidence. Record the verifier, policy/key version, artifact digest, source, and denial result without retaining secret material.
5. Repeat the negative and positive comparisons with the deployed Helm/client/controller versions and actual CI/GitOps paths. Review source and mirror permissions, update/key rotation, exceptions, and evidence retention. Registry verification, OCI charts, GitOps reconciliation, and organizational trust/key lifecycle are not established by this local case.
