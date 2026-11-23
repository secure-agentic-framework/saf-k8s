# SAF-K8S-0501-009 — Model download path isolation from training data paths

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0501-009 --docker-context desktop-linux
```

The runner creates a fresh Kind v0.32.0 and Kubernetes v1.36.1 cluster with its bundled kindnet. Two synthetic HTTP clients test the intended and crossed connections to separate model-mirror and training-data endpoints. The model, training, and shared-listener workloads occupy three case-owned namespaces. These connections carry fixture markers over TCP/8080.

- **Red.** Both clients can reach both endpoints and see the correct marker before egress policies exist.
- **Green.** The model client times out for the training endpoint and the training client times out for the model endpoint. Check that policies contain the exact source selectors, namespace and destination Pod selectors, and port. Every green connection must have worked with the same client and server before policy.
- **Permitted.** Each client still reaches its own endpoint. The model client can also retrieve both paths served by one allowed listener on the same IP and port. HTTP path controls require an application-aware enforcement point or separate network identities.

For deployment evidence, inspect actual registry, mirror and dataset routing, CNI behavior, other in-use address families and protocols, artifact approval, and any policy on shared HTTP endpoints.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
