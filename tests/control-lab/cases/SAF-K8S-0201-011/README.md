# SAF-K8S-0201-011 — Kubelet webhook authorization for monitoring

Run on an isolated Kubernetes v1.36.1 kind node.

```sh
python3 lab.py test SAF-K8S-0201-011
```

The case sends GET requests to the node's loopback kubelet listener and
records only HTTP status. With no credential, health returns 401. A dedicated
service account's short-lived bearer token authenticates, but requests for
health, metrics and stats return 403 until the account receives
node-specific `get` permissions on `nodes/healthz`, `nodes/metrics` and
`nodes/stats`. Repeat the same requests to observe 200. The monitor's direct
request to `/configz` remains forbidden. SubjectAccessReview checks confirm
that unused endpoint subresources, `nodes/proxy` and metrics access to another
node remain denied. The service account never receives the broad proxy grant.

Fine-grained kubelet authorization became stable and locked on in v1.36.
The kubelet checks the specific health, pods and configuration permissions
before falling back to the broader proxy permission. Metrics and stats have
dedicated permissions. Grant only the subresources the monitor needs and
review effective authorization, including permissions inherited through
other bindings.

A client certificate trusted by the kubelet can also authenticate. Webhook
token authentication and webhook request authorization are separate
configuration fields. Live coverage here is the bearer-token and monitoring
RBAC path. Trusted client CA deployment, kubelet serving TLS, other node
types, provider-managed hardening and network boundaries require their own
evidence.

- [Kubernetes v1.36 kubelet authentication and authorization](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [Kubernetes v1.36 fine-grained kubelet authorization announcement](https://kubernetes.io/blog/2026/04/24/kubernetes-v1-36-fine-grained-kubelet-authorization-ga/)
