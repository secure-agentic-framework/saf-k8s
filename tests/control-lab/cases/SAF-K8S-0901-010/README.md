# SAF-K8S-0901-010 — Encrypted inter-worker gradient transport

## Scope and method

The pinned control says multi-node distributed training jobs must protect inter-worker gradient communication using encryption supported by the communication framework. This case tests a narrower transport primitive: two disposable mock Python workers send one fixed, harmless synthetic marker over plaintext and authenticated TLS 1.3 in a Kind v1.36.1 cluster. It does not run or model gradient math.

The receiver logs only the request mode, exact fixture marker readback, negotiated server-side TLS version, and whether a client certificate was presented. The sender records exact application readback, TLS version, successful CA and DNS-name verification, and its own TLS outbound TCP bytes. A case-owned local relay in the sender observes only that sender-to-receiver stream; the marker and all bytes are synthetic fixture data. Raw sender and receiver receipts are retained by the harness as evidence.

The red counterfactual proves that the same marker appears in the plaintext request bytes and is read by the receiver. Green requires the TLS receiver to read back the exact marker, TLS 1.3 to be negotiated on both ends, and the marker bytes not to appear in the sender-owned outbound TLS stream. Positive checks separately confirm the receiver's CA and DNS identity, matching marker readbacks, and that the server did not request a client certificate. Encryption and server authentication are evidenced separately from mTLS client identity controls.

## Limits and unresolved claims

This case does not establish that NCCL, MPI, TensorFlow gRPC, another training framework, a training engine, a cloud provider, or a physical GPU encrypts real gradient traffic. It does not show that a production job is configured to use encryption, that all inter-worker paths are protected, or that TLS is enforced cluster-wide. It does not exercise mTLS, certificate issuance or rotation, tamper detection, a production CNI, or a physical network/fabric. Those claims require framework-specific configuration evidence and a framework-originated data path in a separately authorized environment.

The case uses ephemeral locally generated server credentials. No private key bytes are emitted to evidence; the Kubernetes Secret creation output is restricted to the resource name. No real feed, endpoint, workload, or target is accessed. The supervisor is responsible for running the lab on its disposable cluster and reviewing both control outcomes.

## Official sources

- [Python 3.13 `ssl` documentation](https://docs.python.org/3.13/library/ssl.html) describes `SSLContext`, certificate validation, and TLS sockets. This fixture uses authenticated sockets and a bounded owned relay.
- [Kubernetes v1.36 NetworkPolicy documentation](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) describes pod traffic filtering and states that NetworkPolicy does not provide TLS functionality. This case therefore tests transport encryption at the worker application layer.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) publishes the Kubernetes v1.36.1 node image digest used by the harness. [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python) is the source for the pinned Python worker image reference. This case does not create or select a custom Kind profile.

The two fixtures are pinned to separate Kind nodes. The sender observes the plaintext and TLS bytes only through its own local fixture relays.

## Verify an adopting implementation

Enumerate actual worker communication paths and configure the training
framework itself to use the authenticated TLS mode. Verify CA and peer-name
validation on all endpoints, capture a bounded benign framework-originated
exchange, and show no marker in the actual wire capture. The case proves a
mock Python transport using TLS 1.3, not NCCL, MPI, gRPC, or GPU gradients.
