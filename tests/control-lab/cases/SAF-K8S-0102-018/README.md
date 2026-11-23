# SAF-K8S-0102-018 case

## Scope

This case runs only against the fresh ephemeral Kind cluster created by
`reference/lab.py`. It inspects that cluster's live etcd static Pod command, then
uses its node-local etcd sockets on ports 2379 (client) and 2380 (peer). The
certificate-less probes are TLS 1.3 handshakes that verify etcd's server
certificate against the cluster CA and expect the TLS `certificate required`
alert. The allowed read uses kubeadm's existing etcd health-check certificate.
The positive control reads Kubernetes API `/readyz`.

The case does not change etcd settings, create/delete application data, run
against any pre-existing cluster, or prove peer-to-peer traffic between members.
A single-member cluster has no remote etcd member. It also does not prove every
possible production listener, certificate rotation/revocation, managed-service
provider controls, authorization by etcd RBAC, or production compliance.

## Run

The supplied `reference/lab.py` discovers cases under `cases/<control-id>/`,
while this assignment requires the reviewed draft under `case/`. To execute it
through that harness, first stage this reviewed directory at
`cases/SAF-K8S-0102-018/` in the framework checkout. Then, from that checkout's
root, with the catalog index entry and a local Docker Unix-socket context, run:

```sh
python3 reference/lab.py test SAF-K8S-0102-018
```

The lab creates a uniquely named fresh Kind cluster, makes the checks, and
deletes that cluster in its `finally` cleanup. It records its result under
`evidence/SAF-K8S-0102-018/`. Do not run this case against a manually selected or
existing cluster.

## Bounded prerequisites

- Docker Engine on a local Unix socket; the lab rejects non-local Docker contexts.
- `kind`, `kubectl`, Python 3, and OpenSSL in the pinned Kind node image.
- Permission to pull the digest-pinned Kind image and create/delete ephemeral
  containers. No outside etcd endpoint, credentials, token, or cluster is used.
- Enough disk, memory, and time for the lab's fixed cluster startup and command
  timeouts. A failed prerequisite is an infrastructure block, not a control
  failure.

OpenSSL runs inside the digest-pinned Kind node, so it probes the node-local
listener directly without adding an unpinned TLS-client image. The case retains
only normalized receipt fields; it discards the volatile OpenSSL transcript.

The peer probe uses the disposable control-plane node's own InternalIP.
A successful handshake with the stock peer leaf checks the permitted path,
alongside the certificate-less TLS alert and the permitted health client.
