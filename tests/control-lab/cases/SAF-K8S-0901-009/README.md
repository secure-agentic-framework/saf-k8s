# SAF-K8S-0901-009 — Multi-node training worker mutual authentication

Run from the control lab repository with the supervisor's local Docker context:

```sh
python3 lab.py test SAF-K8S-0901-009 --docker-context desktop-linux
```

The case creates one disposable Kubernetes v1.36.1 Kind cluster with one
control-plane node and two workers. It places the synthetic server and client
on different workers. Both Kind's node image and the official Python fixture
image are pinned by digest. `worker.py` contains only a fixed local TLS exchange
and the exact harmless marker `SAF-K8S-0901-009 synthetic gradient marker
51c8d2`; it accepts no caller-supplied host, URL, feed, or target.

Each run generates short-lived local CAs and leaf certificates. Their private
keys are mode-restricted in the runner's private temporary directory, passed
to the disposable cluster as Secret files, then removed from the runner before
the peer probes. Secret volumes are read-only and group-readable only by the
fixture process. Evidence contains no certificate or key bytes. The peers
exchange data only with the server Pod IP recorded by the runner.

## Independently observed outcomes

- **Red comparator:** a TLS server that verifies its own server certificate
  accepts the exact marker from a client that sends no certificate. Client
  output and a server event record the missing client identity.
- **Green rejection:** the mTLS listener rejects a missing certificate and a
  client certificate signed by a separate local CA during the TLS handshake.
  It also rejects a trusted certificate whose URI identity is not the one
  authorized for the fixture. No rejected attempt is logged with marker bytes.
- **Positive exchange:** the client validates the local CA and server DNS
  identity. The server validates the client certificate chain and exact URI
  identity. Both sides report the peer identities and the server records the
  exact synthetic marker.
- `peer-events.raw.jsonl` retains the bounded server observations. Check
  results retain client outcomes, worker node names, and a marker hash; no
  private credentials or TLS diagnostic text are retained.

A NetworkPolicy requests peer-only ingress and egress. Kind's default network
implementation may not enforce NetworkPolicy; this case does not claim that
external egress is technically blocked. The fixture has no external endpoint
or network operation, and the run does not access external feeds or targets.

## Coverage limits

This validates one Python/OpenSSL fixture exchange on two Kind worker nodes.
It does not validate PyTorchJob, MPIJob, or TFJob controllers; production
certificate issuance, rotation, revocation, or identity-to-worker enrollment;
framework gradient transport; real training data; or production network policy
enforcement. Production proof needs the deployed worker configuration and
operator lifecycle, identity authorization rules, and observed peer decisions.

## Primary sources

- [Kind cluster configuration and multi-node clusters](https://kind.sigs.k8s.io/docs/user/configuration/)
- [Python 3.13 `ssl` module](https://docs.python.org/3.13/library/ssl.html)
- [Kubernetes v1.36 NetworkPolicy concepts](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Official Python container image](https://hub.docker.com/_/python)

## Verify an adopting implementation

Map each training worker to a unique authenticated identity. Issue short-lived client certificates from the approved workload CA. Enforce the intended URI/SAN allow policy and server-name validation on every worker transport. Verify authorized peer exchange, rejection of missing, untrusted, and trusted-but-unapproved peers, rotation, revocation, and that rejected requests carry no training payload. The fixture proves a fixed two-worker TLS exchange, not a training operator or certificate lifecycle.
