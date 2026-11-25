# SAF-K8S-0103-016 — Controller-manager and scheduler loopback bind address

This case uses the lab's pinned Kubernetes v1.36.1 kind image. It compares two
case-owned, isolated Linux nodes: one where kubeadm configures both secure
listeners to `127.0.0.1`, and one deliberately misconfigured to bind `0.0.0.0`.
Neither kind configuration publishes a host port. The red node's broad bind is
used only as a bounded negative control and is deleted after the check.

The case checks effective mirror Pod arguments and the actual TCP listening
address for ports 10257 and 10259. It sends only HTTPS `GET /healthz` from the
node itself to loopback and to that node's Docker-network IPv4 address. `curl`
discards response bodies; checks retain only HTTP status and connect success.
No metrics, profiling, debug, or other routes are requested. Health responses
are intentionally anonymous, as permitted for health checks by component
authorization configuration; this case performs no unauthenticated metrics
extraction.

On the loopback profile, both real TLS health checks must return 200 through
`127.0.0.1`, while the node's non-loopback IPv4 address must not connect to
either listener. On the wildcard profile, each listener must show a wildcard address,
and both addresses must return 200. The wildcard observation establishes the
expected red condition: a TLS health endpoint on the secure port is reachable
through the node's non-loopback interface when bound to all IPv4 interfaces.

Run from the lab root:

```sh
python3 lab.py test SAF-K8S-0103-016 --docker-context desktop-linux
```

The resulting `result.json` records the catalog revision, the control digest,
both profiles' observed results, and the cleanup status.

## Version-matched primary references

- [Kubernetes v1.36 kube-scheduler command-line reference](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/) — `--bind-address`, secure port, and listener behavior.
- [Kubernetes v1.36 scheduler hardening guide](https://v1-36.docs.kubernetes.io/docs/concepts/security/hardening-guide/scheduler/) — recommends localhost binding when external access is unnecessary.
- [Kubernetes v1.36 kube-controller-manager command-line reference](https://v1-36.docs.kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/) — secure HTTPS serving and port 10257.
- [Kubernetes v1.36 kubeadm implementation details](https://v1-36.docs.kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/) — control-plane static Pods and local component/API context.
- [Kubernetes v1.36.1 shared secure-serving options source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/apiserver/pkg/server/options/serving.go) — default `0.0.0.0`, all-interface wildcard semantics, flag registration, and listener creation.
- [Kubernetes v1.36.1 kube-scheduler options source](https://github.com/kubernetes/kubernetes/blob/v1.36.1/cmd/kube-scheduler/app/options/options.go) — constructs and applies shared secure-serving options.

## Verification boundaries

The case validates IPv4 on the pinned Linux kind image. A successful request to
the node's own non-loopback address shows address reachability in that isolated
network; it does not prove exposure from a separate host or cluster node. No
ports are published, no external host probe is attempted, and no claim is made
about IPv6 dual-stack behavior or address-specific platform semantics. Managed
provider configuration and production firewall/routing controls also require
their own evidence.

## IPv6 comparison

The case owns an independent Docker bridge and confirms Docker enabled its
requested IPv6 subnet. Kind retains an IPv4 host-loopback API endpoint and
runs the case's component probes from inside the owned IPv6 node. The runner
checks the effective `::1` bind and the allowed loopback health request and
requires refusal on the node's assigned non-loopback IPv6 address. After an
owned static Pod replacement it checks the `::` wildcard and confirms the
same non-loopback request reaches the health route. Only HTTP status and
listener findings are retained. The harness deletes its exact cluster and
bridge. Adopters must verify all actual IP families, monitoring routes and
provider responsibility. The fixture requires Docker support for an IPv6
bridge in the selected environment.
