# SAF-K8S-0502-005 — AI workload data path encryption in transit

From the framework repository, run:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0502-005 --docker-context desktop-linux
```

Use Kind v0.32.0, Kubernetes v1.36.1 and a local OpenSSL-compatible CLI for temporary fixture certificates. Two fixed-marker Services represent a training data store and a model registry. Each has plaintext and TLS listeners. All keys belong to the synthetic fixture. The runner removes the temporary directory and disposable cluster.

- **Red.** The client retrieves the exact marker over plaintext from each Service before policy.
- **Green.** Egress policy permits DNS and the TLS port. Requests to both plaintext ports time out. The client also rejects the wrong service name and an untrusted CA.
- **Permitted.** The client verifies the expected service name and trusted CA and retrieves both markers over TLS before and after the negative certificate checks.

This verifies protocol-level transport and identity for the two synthetic paths. Production NCCL, CNI encryption, network storage, registry and serving routes, RDMA and throughput need separate evidence.

[Kubernetes v1.36 NetworkPolicy](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) · [Python 3.13 SSL peer authentication](https://docs.python.org/3.13/library/ssl.html)
