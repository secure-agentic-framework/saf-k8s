# SAF-K8S-0901-005 — Federated participant isolation

## Executable scope

This case exercises the participant namespace boundary in a disposable Kind v0.32.0 cluster using Kubernetes v1.36.1. It creates two synthetic participant namespaces and a third namespace containing one approved local aggregation mock. Each pod runs a case-owned Python HTTP responder from a digest-pinned image. The only application request is an ordinary `GET /healthz` that returns a fixed synthetic marker.

The red baseline sends each participant's health request to the other participant's Pod IP and requires two exact marker readbacks before policy. The green checks repeat those same requests after participant ingress and egress isolation policies are installed and require no response. Positive checks independently require both participants to reach the same approved aggregation Service ClusterIP, port, path, and exact response marker after policy. Thus a healthy positive request exercises the same source namespaces and cluster destination while the peer paths are isolated. The policy uses exact namespace and pod selectors. DNS is not used or tested.

The harness retains bounded raw health observations, fixed-path server event logs, the applied NetworkPolicy API objects, raw case-owned Pod and Service objects, participant and Service addresses, pinned image references, and a scope receipt. These objects contain fixture metadata only. The fixtures suppress request-line logging and never collect headers, credentials, secrets, models, updates, gradients, or arbitrary request bodies. No Docker/Kubernetes execution is part of authoring; the supervisor is expected to run and verify both executions.

## Coverage and unresolved obligations

The live result can establish only that, in this disposable Kind cluster and its observed network plugin, fixed health requests between these two case-owned participant pods were reachable before isolation and not reachable after the policies, while both could reach the approved local mock aggregation Service. The case does not establish security of a federated learning algorithm, production namespace governance, actual workload placement, or protection against model inversion.

The following control claims remain separate evidence obligations:

- **Secure aggregation:** no aggregation protocol or participant value is implemented; the local Service returns a constant health marker. Verify a protocol implementation, threat model, dropout behavior, and server-visible output in a separate reviewed workload. See the original [Practical Secure Aggregation paper](https://acmccs.github.io/papers/p1175-bonawitzA.pdf).
- **Differential privacy:** no model update, clipping, noise, epsilon/delta accountant, or privacy budget exists in this case. Verify algorithm parameters, implementation, accountant, and release policy independently.
- **Byzantine-resilient aggregation:** no update values or aggregation algorithm run. Algorithmic resilience is distinct from Kubernetes network isolation; the original [Krum paper](https://papers.neurips.cc/paper/6617-machine-learning-with-adversaries-byzantine-tolerant-gradient-descent.pdf) describes a particular algorithm and its stated assumptions, not a Kubernetes control.
- **Authenticated enrollment:** no participant identity provider, enrollment registry, SPIFFE/SPIRE, client certificate, or cross-cluster authentication is exercised. Validate participant identity issuance, authorization, revocation, and enrollment lifecycle separately.
- **Federated fabric:** this is one local cluster and one local service. It does not verify cross-cluster mTLS, service mesh, CNI behavior outside this Kind cluster, production network routing, or framework-specific participant/aggregator communication.
- The source rationale names gradient inversion, model inversion, and poisoning. This case performs none of these procedures and contains no attack simulation. It cannot validate or refute those source claims.

Kubernetes documents NetworkPolicy as L3/L4 pod traffic control and requires a network plugin that enforces it. Selector combinations are material: a combined `namespaceSelector` and `podSelector` selects the named pods in the selected namespace. This case uses those combined selectors and checks live reachability rather than inferring enforcement from policy objects alone. See [Kubernetes v1.36 NetworkPolicy concepts](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/) and [Kubernetes v1.36 multi-tenancy guidance](https://v1-36.docs.kubernetes.io/docs/concepts/security/multi-tenancy/).

## Pinned images and sources

- Kind node: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`, published in the [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0).
- Python fixture: `docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90`, using the [Docker Official Images Python metadata](https://github.com/docker-library/official-images/blob/master/library/python).
- The mock uses Python's standard-library [`http.server`](https://docs.python.org/3.13/library/http.server.html) and [`urllib.request`](https://docs.python.org/3.13/library/urllib.request.html); neither fixture accesses a network location outside the case-owned cluster.


## Flower workflow under NetworkPolicy

This isolated case wrapper first calls the exact published `SAF-K8S-0901-005` implementation and
retains its eight checks unchanged. It then runs the pinned Flower 1.29.0 image pinning and workflow
runner from the local `flower/` folder. The weighted supplement changes only fixed per-round sample
counts, run count and expected aggregate; it preserves the three fixed vectors and verifies local
companion file hashes before loading the workflow.

Before the Flower CLI starts, the wrapper adds a small fixed-marker HTTP sidecar to each of the three
case-owned SuperNode Pods. The same two participant-to-participant health paths must first return
the exact expected markers. An exact NetworkPolicy then selects only these SuperNode Pods and
allows egress to the case-owned SuperLink Fleet Service on TCP 9092 plus CoreDNS on TCP/UDP 53.
The same two peer paths must time out twice, while each target sidecar remains healthy on localhost.
Only after that gate passes does the exact Flower companion run one two-round workflow. Its equal
weight receipt assertion and additive 1-2-3 weighted aggregate assertion must both pass, demonstrating
that the pinned workflow uses the allowed SuperLink path under the active policy. The four Flower Pods
are retired before a separate fixed-input release fixture starts. That fixture initializes the
existing scoped identity/share records without running its four unrelated lifecycle assertions, then
checks exact digest approvals for both aggregate-only round receipts in one grouped assertion. The
case-owned NetworkPolicy and health ConfigMap are deleted in cleanup.

The composed runner records 12 checks: eight from the published network case, one peer-flow policy
gate, two actual Flower round checks, and one grouped release check that retains the six original
release facts and adds weighted-digest refusal and release facts. The release fixture uses five small
support Pods only after the four Flower Pods are deleted. It reuses the exact published
`SAF-K8S-0908-001/case.py` runtime image helper, copied into the candidate and checked against SHA-256
`262a254a36143a1c5760777a3435555cd5ca53168c68900168aabc8608668257`; it does not run that case's
unrelated assertions.

This supplement exercises one in-cluster Flower path and a selected participant egress policy. The
three synthetic participants and aggregation service share one namespace in the Flower companion;
the base eight checks separately exercise namespace-level isolation. This is not proof of production
namespace governance, authenticated enrollment, TLS, cross-cluster transport, differential privacy,
Byzantine resistance, or the security of Flower SecAgg+. It uses only fixed synthetic vectors and
fixed health markers, with no actual training data or attack procedures. The paired workflow and
release checks use only fixed synthetic vectors and exact receipt digests.


## Selecting compatible aggregation controls

The pinned workflow supplies the aggregate through the selected Flower
interface. Check each method's required inputs and outputs against that
boundary. A conventional robust method that scores individual updates
requires a reviewed composition that preserves update confidentiality and
Byzantine resilience together. The adopter verifies the selected threat
model, differential-privacy accounting, robust aggregation, participant
identity and real transport paths. This case supplies two scoped Flower
workflow rounds, exact-digest release observations, and participant-network
observations.

- [Flower secure aggregation workflow API](https://flower.ai/docs/framework/ref-api/flwr.server.workflow.SecAggPlusWorkflow.html)
- [Original Krum paper](https://proceedings.neurips.cc/paper_files/paper/2017/hash/f4b9ec30ad9f68f89b29639786cb62ef-Abstract.html)
- [Original secure aggregation research](https://research.google/pubs/practical-secure-aggregation-for-federated-learning-on-user-held-data/)

## CPU reference for private aggregation

The standard control test also runs a bounded binary composition using
the pinned MP-SPDZ v0.4.4 malicious honest-majority backend. Three
enrolled Pods use separate certificates. Each computes the sign of one
local synthetic logistic update for a fixed unit-feature example. Their circuit computes the median privately. It flips
that bit only when two fresh secret bits are both one, and releases a
single noisy aggregate.

A separate calibration circuit takes fixed public inputs and checks
all 32 input and noise combinations. Two agreeing honest contributions
determine the median when the third bit differs. For replacement of
one participant bit, the binary release has a maximum likelihood ratio
of three, giving ε = ln(3) and δ = 0 in the ideal release mechanism under
independent uniform coins. The runner reserves one release and treats
aborts as failed runs. The claim assumes the completed one-shot release,
a trusted fixture enrollment and Kubernetes authority, at most one
corrupted peer, and no per-input observables or selective retries.
Production gradients, broader Byzantine resilience, and full output and
abort guarantees require separate evidence.

The runner builds the case-local image from the checksum-pinned upstream
release. The current reference uses the upstream Linux x86-64 executable
and a pinned Debian runtime. On ARM64, the container host needs x86-64
emulation. The normalized receipt is `bounded-private-aggregation.json`.
[MP-SPDZ v0.4.4](https://github.com/data61/MP-SPDZ/releases/tag/v0.4.4) ·
[NIST differential privacy guidance](https://csrc.nist.gov/pubs/sp/800/226/final)

The case also runs a separate two-round, two-coordinate
quantized route after the preserved one-bit checks. Its exact finite claim and
evidence limits are documented in
`mpc-reference/quantized-two-round/INTEGRATION.md`.

## Flower Fleet transport across two Kind clusters

The standard case-by-ID run also uses an owned secondary Kind cluster for the
pinned Flower 1.29.0 workflow. A SuperLink runs in the primary cluster and
three SuperNodes run in the secondary cluster. The actual Fleet gRPC stream
crosses the Kind Docker bridge over TLS 1.3 with peer authentication. Each
Flower endpoint uses loopback inside its own Pod. Its relay authenticates the
remote transport. Only the gateway's dynamically assigned NodePort is used
across the bridge. The participant egress policy selects that exact address
and port.

The test generates an ephemeral fixture authorization list and separate
client certificates. It verifies the server's certificate and DNS identity
and authorizes the exact fingerprint of each enrolled participant leaf.
A connection without a client certificate fails TLS. A CA-signed leaf
without an enrollment is refused before connection to Flower, and a wrong
server hostname fails verification. Both actual fixed-vector Flower rounds
must produce the expected aggregate and a count of three participants.
The gateway must observe bytes in both directions for every enrolled leaf.

The fixture places mutual TLS on the relay channel between Pods. Flower
uses its local loopback connection on either side. The receipt covers
the three fixture identities, two aggregate results and deletion of the
secondary cluster. Production enrollment, revocation, trust-provider
lifecycle, deployed networks, and the adopter's composition assumptions
require separate evidence. The test needs Docker capacity for two Kind
clusters and OpenSSL for temporary fixture certificates.

## Participant withdrawal on the live Fleet route

After the existing two pinned Flower rounds finish, a transport-only probe
from the enrolled participant C opens a TLS 1.3 connection through the same
Fleet gateway and receives the real Flower server's HTTP/2 SETTINGS. The
harness removes that leaf's enrollment with a resource-version-checked
Kubernetes API update. The gateway reads the projected roster and closes
active connections for withdrawn leaves. The probe observes its existing
connection close. A new connection using the same CA-valid leaf is denied
before it can reach Flower, while participant B still receives the Flower
server's HTTP/2 SETTINGS. The gateway Pod UID, container IDs and restart counts
stay the same.

The roster is a separate ConfigMap mounted as a directory in the gateway.
Kubelet projection and relay reload must be observed before the result counts.
The test demonstrates authorization withdrawal at the fixture relay, and the
TLS certificate remains valid. It does not establish a production revocation
SLA, CA-level revocation, enrolled leaf rotation or Flower's native
public-key enrollment lifecycle. The probe sends only HTTP/2 transport
negotiation and acknowledgments. The normalized receipt
`flower-participant-retirement.json` retains outcomes without credential
material or participant data.

- [Kubernetes ConfigMap volume updates](https://kubernetes.io/docs/concepts/configuration/configmap/#mounted-configmaps-are-updated-automatically)
- [Flower 1.29 SuperNode authentication](https://flower.ai/docs/framework/1.29/en/how-to-authenticate-supernodes.html)
