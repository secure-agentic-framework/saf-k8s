# SAF-K8S-0601-022 — Kubernetes image pull Secret delivery

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0601-022 --docker-context desktop-linux
```

The disposable Kubernetes v1.36.1 case observes a Pod without a pull Secret reference, links a namespace-local Secret to the ServiceAccount, and verifies admission injects the exact name and the public-image fixture still completes.

A case-owned, digest-pinned registry and image run on a temporary isolated Docker network. For the same exact image digest, a wrong credential produces an HTTP 401 in the registry's access log and a kubelet image-pull error. The container never starts and the image is absent from the node cache. A correct same-namespace Secret allows the manifest GET, creates the exact CRI repository digest, and runs a harmless marker command. The registry uses synthetic credentials and a loopback-bound host port. The evidence retains status and assertions.

For adoption, test each approved registry and workload namespace with a harmless private image and dedicated fixture identity over the approved TLS path. Verify the external Secret manager delivers the correct Secret type, namespace and reference. Check allowed and denied pulls, exact digest, failed delivery, reconciliation, CI/CD references and redacted logs. Confirm actual authorization and cache behavior on each applicable node profile. Verify credential rotation under SAF-K8S-0601-023.

[Kubernetes v1.36 image pull Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod) · [Distribution v3.0.0 registry access logging](https://github.com/distribution/distribution/blob/v3.0.0/registry/registry.go)
