# SAF-K8S-0103-017 — Legacy serving removal and secure health reachability

```sh
python3 lab.py test SAF-K8S-0103-017 --docker-context desktop-linux
```

Use the component binaries in the pinned kind v1.36.1 control plane to
check current help and the parser's rejection of the two removed
`--port` and `--address` flags. Inspect each component's effective
arguments and confirm that neither historical insecure port has a listener.

The two isolated profiles bind the secure component ports to loopback
and to a wildcard, respectively. For each component, check the configured
listener and compare the same fixed HTTPS `/healthz` route through loopback
and the node's own non-loopback address. The probe discards the response
body and captures only status and reachability. The open-loopback health
response demonstrates why TLS serving alone cannot establish that a route
requires an authenticated caller.

The case keeps component ports on its disposable nodes. Health and metrics
checks record only their HTTP status and connection outcome.

- [Kubernetes v1.24 change log](https://github.com/kubernetes/kubernetes/blob/v1.24.0/CHANGELOG/CHANGELOG-1.24.md)
- [Kubernetes v1.36 controller-manager flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [Kubernetes v1.36 scheduler flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)

## Authorized secure metrics

The approved loopback profile mounts a fixture-issued certificate into each
owned component and waits for the actual replacement mirror Pod to become
Ready. Local curl validates the exact loopback IP against the fixture CA and
discards every response body. The unauthenticated metrics request is refused.
A short-lived synthetic ServiceAccount with a separate `GET /metrics` grant
receives `200`. Existing health and listener comparisons remain. No external
port is published.

For adoption, inventory the effective listeners and permitted routes for every
replica, approved monitoring identities and certificate trust. Exercise the
intended approved scrape and denied non-monitoring request. Verify health
exceptions and the IPv4 or IPv6 address scope the deployment uses. For managed
components, record the evidence source and provider/customer responsibility.
