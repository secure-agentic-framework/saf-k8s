# SAF-K8S-0606-021 manifest signing before promotion

Run from the SAF-K8S framework checkout with OpenSSL and the usual Kind prerequisites.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0606-021 --docker-context desktop-linux
```

Two fixture CI Jobs create separate temporary RSA keys in memory-backed
volumes and sign exact Kubernetes manifest bytes. The runner retains public
keys and signatures and checks each with its corresponding manifest.

A promotion Job verifies the input through an init container that has no API
credential. Kubernetes starts the promotion container only after verification.
The authentication API confirms the intended ServiceAccount identity before
that container submits the exact signed bytes as an inert ConfigMap.

The verifier rejects an unsigned manifest, changed bytes with the original
manifest's signature, and a modified manifest signed by the comparison key.
Only the approved key and matching bytes produce the case-owned ConfigMap.

This demonstrates one scoped signing and promotion path. Production CI signer
authorization and approval, key custody, protected configuration and production
deployment coverage require separate evidence.

- [OpenSSL 3.3 digest and signature commands](https://docs.openssl.org/3.3/man1/openssl-dgst/)
- [Kubernetes v1.36 init containers](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/pods/init-containers/)
- [Kubernetes v1.36 ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)

## Adopter verification

Identify the exact manifest and source revision, authorized signing workflow and signer, and the verification material available to the intended consumer. Record the approved signer and algorithm, public key identifier, key access and rotation, and the source-to-signature binding. In an approved test, present an unsigned manifest, changed bytes, and a signature from a different signer. Verify each is rejected before promotion. Independently confirm the signed bytes and digest seen by the approved deployment identity. Retain only public signature evidence and the approval or change record.
