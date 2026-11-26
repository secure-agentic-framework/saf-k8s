# SAF-K8S-0904-014 — Scope workflow artifact access and retention by stage

Run `python3 tests/control-lab/lab.py test SAF-K8S-0904-014 --docker-context desktop-linux` from the framework checkout.

Fifteen checks verify stage-scoped operations on a pinned disposable SeaweedFS 4.53 store. The case compares broader fixture access with restricted bucket access, confirms own-stage operations and separate lifecycle rule readback, and then uses real Kubernetes TokenRequest projections. An authenticated init process retrieves only public issuer metadata and keys from the owned Kubernetes API. A case HTTPS service serves that exact snapshot through an ephemeral CA and verified name. SeaweedFS validates the configured audience at its OIDC provider and the exact issuer and subjects in its role trust rules. The tests observe two stage-scoped short-lived sessions, wrong audience, subject and stage-role denials, and native refusal of the same session after its real expiration. Session values stay in the fixture processes.

## Verify an adopted workflow

1. Reconcile the actual workflow stage, controller, workload ID and identity with allowed buckets and artifact operations. Observe project or job isolation, approved access and refusal across controlled stages. Confirm the relying party checks intended audience, issuer, subject and accepted key updates.
2. Verify real session issuance, refresh, expiration and withdrawal at the workload's actual provider, retaining sanitized evidence. Check storage endpoints and use the production transport and identity trust model.
3. Exercise actual lifecycle enforcement for one approved artifact and verify the decision at the applicable time boundary. Check alternate artifacts, backups, retained copies, legal holds and approved archival/retention rules. Retain rule identity and observed disposition separately from successful configuration readback.
4. Record actual producer and consumer coverage, service authorization, key custody and rotation, exception handling, and workflow history. Test each applicable managed or external storage path separately.

- [Kubernetes ServiceAccount issuer discovery](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [SeaweedFS 4.53 OIDC audience validation](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/iam/oidc/oidc_provider.go#L718-L750)
- [SeaweedFS 4.53 role trust context](https://github.com/seaweedfs/seaweedfs/blob/4.53/weed/iam/integration/iam_manager.go#L1924-L2003)

A separate owned bucket holds one inert due marker and one nonmatching comparator. The case checks both exact objects before manually invoking one bounded SeaweedFS lifecycle worker pass. It observes removal of the due marker and retains the exact comparator digest. The manual pass demonstrates selected expiration behavior. Verify automatic scheduling, versions, replicas, retention exceptions and physical reclamation in the actual provider environment.

## Workflow stage identity

The pinned namespace-scoped Argo controller reconciles two serial Workflows.
Each task Pod's owner UID and effective stage ServiceAccount must match the
exact Workflow. The task uses an audience-scoped projected token to obtain
temporary SeaweedFS credentials. It reads its own fixed marker and receives
a 403 for the other stage marker. The separate executor ServiceAccount has
only the named workflow result permissions used by this fixture.

The pinned Argo version uses a Kubernetes executor token Secret for this
fixture. The token stays inside the disposable cluster and presence checks
emit only a Boolean. Verify the adopted executor model, live workflow and
provider identities, credential lifecycle and classification-aligned
retention with the applicable release and operational policy.

[Argo workflow RBAC](https://argo-workflows.readthedocs.io/en/release-3.7/workflow-rbac/)

The controller fixture is rendered from namespace-scoped Argo Workflows v3.7.6
manifests with the server excluded and both images pinned. Verify the staged
upstream inputs and render with `python3 fixtures/verify_argo_inputs.py` from
the case directory.

[Upstream release](https://github.com/argoproj/argo-workflows/tree/v3.7.6/manifests/namespace-install) · [Upstream license](fixtures/argo-v3.7.6/LICENSE)
