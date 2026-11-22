# SAF-K8S-0702-022 Virtual cluster isolation guarantees and residual risk

Run the by-ID case on a local Docker Unix socket with kind, kubectl, and Helm.
Helm downloads the official vCluster 0.37.7 archive and the case verifies its
SHA-256. The shared-node control planes use digest-pinned images. Both API
ports are forwarded only on loopback and all requests require verified TLS.

```sh
python3 lab.py test SAF-K8S-0702-022 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0702-022.md)
requires a documented tenant boundary, including its guarantees, assumptions,
and residual risks. In this example, two virtual control planes share one
disposable host. An ordinary create repeats a CRD in tenant A and gets
`AlreadyExists`. The two tenant APIs accept identical CRD names and hold
separate markers for the same namespaced ConfigMap and custom resource.
The host API returns `NotFound` for the virtual CRD.

## Example boundary record

| Review item | Fixture evidence and residual scope |
| --- | --- |
| Tenant API objects | Each owned virtual API persists and reads its own record under the same name. The tested CRD is absent from the host API. |
| Host and administration | Both control planes run on one kind node with a shared kernel, under the host cluster's administrators. Document who can administer the host and how that access is controlled. |
| Synchronization | Default chart sync can create selected real objects in the host cluster. List applicable resource kinds/selectors and host-side permissions for the deployed configuration. |
| Other tenant boundaries | Document the deployed workload, network, storage, node and shared-resource protections, the accepted residual risks, their owners and the review cadence. |

Fixture owner credentials generated for the two disposable APIs stay in
temporary mode 0600 files. The lab deletes its host cluster and those files.
This evidence applies to the bounded API object behavior. A production
architecture record and review must establish the deployed boundaries.

- [vCluster isolation layers](https://www.vcluster.com/docs/vcluster/overview/isolation)
- [vCluster resource synchronization](https://www.vcluster.com/docs/vcluster/configure/sync/)
- [vCluster fixture kubeconfig export](https://www.vcluster.com/docs/vcluster/configure/access/export-kube-config)
