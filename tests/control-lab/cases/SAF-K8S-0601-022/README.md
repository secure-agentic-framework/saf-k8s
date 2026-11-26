# SAF-K8S-0601-022 — Deliver private-image pull credentials

Run the case from the lab root.

```sh
python3 lab.py test SAF-K8S-0601-022 --docker-context desktop-linux
```

The case confirms that ServiceAccount admission supplies a name-only reference
to a same-namespace pull Secret and that the admitted public-image probe
completes. It then installs the pinned External Secrets Operator v2.15.0 chart
in disposable Kind. A local HTTPS provider serves a per-run registry credential
at the approved route and returns HTTP 403 at the denied route. The approved
ExternalSecret becomes Ready, owns the exact namespace-local
`kubernetes.io/dockerconfigjson` Secret, and leaves a provider HTTP 200
observation. Kubernetes rejects direct changes by the test identity. The denied
ExternalSecret remains unready and leaves no target Secret.

The wrong-credential Pod receives a registry HTTP 401 and never starts. The
positive Pod references the ESO-owned Secret, pulls the exact private repository
digest, and produces the expected marker. Evidence includes provider status,
object ownership, authorization outcomes, digest and marker. The generated
credential and Secret payload stay in the case-local provider and private
comparison commands.

## Verify an adopting deployment

1. List approved registries, image consumers, CI systems, and credential
   owners. Record the source secret or workload identity, scope, destination
   namespace or CI job, approval and provider access rules.
2. Inspect the approved workload, Dockerfiles, and CI definitions for
   name-only credential references and approved build-secret delivery.
   Confirm the CI system keeps values out of environment declarations, logs and
   artifacts. Keep one sanitized comparison that distinguishes the approved
   reference from an embedded value.
3. For each external provider path, retain the effective controller identity
   and provider authorization, authenticated transport and TLS trust, keyed
   read scope, target Secret ownership and Ready status. Confirm an explicitly
   denied key or namespace produces the expected refusal.
4. Use a harmless approved image in an authorized staging environment. Verify
   that the workload or CI runner uses the intended credential and exact
   repository digest, and that the denial probe is recorded by the approved
   registry and audit consumers. Include each relevant node and cache policy.
5. Retain identity, target, registry, decision and date while excluding secret
   material. Track automatic credential rotation under SAF-K8S-0601-023.

- [External Secrets Operator v2.15.0](https://github.com/external-secrets/external-secrets/releases/tag/v2.15.0)
- [ExternalSecret API](https://github.com/external-secrets/external-secrets/blob/v2.15.0/apis/externalsecrets/v1/externalsecret_types.go)
- [Kubernetes v1.36 private registry pulls](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)

## Scratch candidate: native literal-value guard

The candidate appends three checks and preserves the existing nine: both fixed
proposals are accepted before the policy; after a fail-closed, namespace-scoped
ValidatingAdmissionPolicy is active, a Pod with the public inert marker in the
exact `REGISTRY_AUTH` environment value is rejected, while an ordinary
name-only `imagePullSecrets` reference remains accepted. These are
server-side dry-runs only. The marker is not a credential, no Pod is persisted,
and the check makes no arbitrary-secret discovery claim.

The policy covers only a non-empty literal value under `REGISTRY_AUTH` in
regular or init container environment fields in the one owned namespace. It
does not inspect Dockerfiles, CI environment declarations, other env names,
indirect values, all namespaces, deployed manifests, or actual registry
credentials. The existing adopter steps remain necessary for those sources.

Expected total: 12 assertions (the original 9 plus 3 bounded admission
comparisons). No Kubernetes run was performed for this scratch candidate.
