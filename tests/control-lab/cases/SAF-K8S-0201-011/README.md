# SAF-K8S-0201-011 — Kubelet webhook authorization for monitoring

Run on an isolated Kubernetes **v1.36.1** kind node:

```sh
python3 lab.py test SAF-K8S-0201-011 --docker-context desktop-linux
```

The case keeps the bearer-token monitoring checks and verifies the node's public
kubelet serving certificate and hostname for every direct HTTPS probe. It then
creates a fresh client key on the disposable node, requests a short-lived
certificate using the native `kubernetes.io/kube-apiserver-client` signer, and
explicitly approves only that purpose-labeled CSR. The resulting ephemeral
X.509 identity must be denied at `/healthz` before the case grants `get` on
`nodes/healthz` for the single named node; afterward it can read `/healthz` but
remains denied at `/metrics`. Keys, bearer tokens, and signed credentials stay
out of command logs and evidence, and node-side temporary files and the CSR are
removed during cleanup.

The fixture uses Kubernetes v1.36.1. Fine-grained kubelet authorization is
stable in v1.36. Record the API-server and per-node kubelet versions and verify
the effective settings of each applicable node pool.

- `authentication.webhook.enabled: true` for bearer TokenReview authentication.
- `authorization.mode: Webhook` for authorization through SubjectAccessReview.
- Anonymous authentication disabled, and approved X.509 client CA trust source
  recorded when client certificates are used.
- Serving TLS enabled with the expected public chain and node hostname.

For kubelets configured with command-line flags, the corresponding effective
settings include `--authentication-token-webhook=true`,
`--authorization-mode=Webhook`, and `--anonymous-auth=false`; when approved
client certificates are used, verify `--client-ca-file` points to the intended
trusted client CA. Confirm the effective configuration on each node because
providers may supply it through a config file or managed interface instead.

## Endpoint-specific authorization review

Use a read-only audit identity to check each monitor identity against each
actual node. The kubelet v1.36 mapping is:

| Request path | SAR resource attributes |
| --- | --- |
| `GET /healthz` | `verb=get`, `resource=nodes`, `subresource=healthz`, `name=<node>` |
| `GET /metrics` | `verb=get`, `resource=nodes`, `subresource=metrics`, `name=<node>` |
| `GET /stats/summary` | `verb=get`, `resource=nodes`, `subresource=stats`, `name=<node>` |
| `GET /configz` | `verb=get`, `resource=nodes`, `subresource=configz`, `name=<node>` |
| API proxy fallback | `verb=get`, `resource=nodes`, `subresource=proxy`, `name=<node>` |

For example, this asks the API server to evaluate the exact health endpoint
attributes for an X.509 monitor (replace both values with the deployed identity
and node):

```sh
kubectl auth can-i get "nodes/$NODE" --subresource=healthz \
  --as="$MONITOR_USER" --as-group=system:authenticated
```

Repeat for `nodes/metrics`, `nodes/stats`, and all unused endpoint subresources.
For ServiceAccounts, also pass their authenticated groups, such as
`--as-group=system:serviceaccounts --as-group=system:serviceaccounts:<namespace>`.
Review inherited RoleBindings, ClusterRoleBindings, aggregation, wildcard rules,
and `nodes/proxy`: the effective policy must allow only approved node/endpoint
pairs, and monitoring should not inherit proxy access. Retain the effective authorization results and separate configuration,
TLS, and network observations for the same endpoint and node.

## Provider and GPU scope

Include every production node pool and sensitive connected non-production pool;
record per-node kubelet versions and exceptions for versions before v1.36.
GPU scheduling does not change kubelet authentication or endpoint authorization,
so GPU nodes remain in scope. Assess their device plugins, node agents, and
vendor management interfaces separately. For managed services, obtain provider
evidence tied to the specific service, version, and node pool that covers
effective kubelet authn/authz settings and their audit/change controls. The kind
fixture establishes no provider implementation, GPU behavior, network boundary,
or deployed client-CA trust claim.

- [Kubernetes v1.36 kubelet authentication and authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Kubernetes v1.36 KubeletConfiguration v1beta1](https://v1-36.docs.kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
- [Kubernetes v1.36 fine-grained kubelet authorization GA announcement](https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/)
