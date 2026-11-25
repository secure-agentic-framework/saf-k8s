# SAF-K8S-0103-010 — Leader election and Lease authorization

```sh
python3 lab.py test SAF-K8S-0103-010 --docker-context desktop-linux
```

In disposable kubeadm kind on Kubernetes v1.36.1, check the controller-manager
and scheduler's effective leader election settings and advancing Lease renewal
times. Derive each client certificate's public subject and compare it with the
stock User role binding. Only the certificate's public field leaves the
owned node for parsing. The case never modifies the actual leader Leases.

For each real component, the case also makes one excluded warm-up and five
measured, named read-only Lease GETs through that component's in-node kubeconfig.
The two components are alternated at one request per second, with a three second
API timeout and five second process timeout. The fixture guard is derived from
the observed retry period and renew deadline as
`min(retry_period / 4, renew_deadline / 10)`. At the kubeadm defaults this is
500 ms. Raw RTT samples, medians, maxima, and the computed guard are written
only to `leader-election-api-latency-raw.json`; `result.json` records the stable
sample count and whether all samples met that fixture-local guard. The guard is
an example for this disposable fixture. Production thresholds use the
adopter’s measured API path. These samples time only GET requests. Advancing
`renewTime` separately demonstrates that fixture renewals succeeded.

Use impersonated case-owned service account identities to get and update their
own fixture Lease and verify explicit Forbidden responses for the other exact
Lease name. With a synthetic Role whose create rule contains a resource name,
attempt server-side dry-run creation for both the listed and unlisted fixture
name. Both fail because a top-level create request has no name at RBAC
authorization. Granting collection-level create to the same synthetic identity
lets both dry-run requests proceed. Cleanup removes all synthetic bindings,
subjects and Leases.

The component bootstrap roles reference named get and update, and grant create
separately. Effective access can include other bindings, privileged identities,
and list/watch. Deployment-specific principal, timing and failover validation,
cloud controller-manager, administrative exceptions, and creation recovery
remain separate obligations.

- [Kubernetes v1.36 RBAC resource names](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/#referring-to-resources)
- [Kubernetes v1.36.1 bootstrap RBAC source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go)
- [Kubernetes v1.36 controller-manager flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [Kubernetes v1.36 scheduler flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)

## Effective authorizer comparison

The runner reads only the public client certificate fields used by each real
kubeadm component to derive its user and authenticated groups. It submits
local SubjectAccessReviews for get and update on each owned and other named
Lease. In the stock v1.36.1 fixture, both identities can access both names.
The authorizer attributes the cross-name decisions to the built-in namespace
Role and RoleBinding. Independent synthetic identities demonstrate narrower
allowed and denied named access without changing bootstrap permissions.

Collection list, watch and top-level create are observed separately. Inventory
all effective authorizers, named and collection grants, default namespaced
roles, administrator exceptions and any required coordination function. Test
authorized current permissions and exact denials with representative approved
identities. Use representative read and write latency, including tail behavior
under expected load, to set deployment-specific margins against the approved
lease timing plan. The bounded fixture sample does not establish that
deployment evidence. Include external/cloud-controller identities where
applicable.

- [Kubernetes v1.36.1 namespaced bootstrap Roles and bindings](https://github.com/kubernetes/kubernetes/blob/v1.36.1/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/namespace_policy.go#L99-L130)

## Adopter verification

1. Identify each enabled election participant, its actual user and groups
   or ServiceAccount, its coordination namespace and Lease name, and its
   effective lease duration, renew deadline, and retry period. Include any
   external cloud controller that participates.
2. Resolve every granting authorizer and effective binding per identity.
   Review the original namespaced bootstrap grants along with the named
   roles. In an approved rehearsal, retain an allowed own-Lease request
   and a denied other-Lease request through the effective identity. Check
   the required create and collection operations separately.
3. Record representative API read and update latency under ordinary and
   expected peak load. Compare tail latency and observed renewals with
   the approved timing margins. Document the required request budget and
   repeat the measurement whenever the API path or timing policy changes.
4. Rehearse the applicable recovery or leader-replacement procedure.
   Confirm continued coordination and record administrative exceptions,
   their permitted actions, scope, and owner.
