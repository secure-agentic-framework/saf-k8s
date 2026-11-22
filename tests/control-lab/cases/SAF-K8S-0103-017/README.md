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

There are no published component ports, external targets, or metrics
requests. The lab deletes both clusters. Fleet bindings, authenticated
monitoring, allowed health paths, and approved network access still need
deployment-specific review.

- [Kubernetes v1.24 change log](https://github.com/kubernetes/kubernetes/blob/v1.24.0/CHANGELOG/CHANGELOG-1.24.md)
- [Kubernetes v1.36 controller-manager flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [Kubernetes v1.36 scheduler flags](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
