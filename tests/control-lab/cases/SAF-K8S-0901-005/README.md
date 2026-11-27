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
retains its eight checks unchanged. It then imports the pinned `SAF-K8S-0908-006` Flower 1.29.0 image
pinning and workflow runner; it does not reimplement Flower or change its fixed vectors. The runner verifies the companion file hashes from the adjacent SAF-K8S-0908-006 case before loading the workflow.

Before the Flower CLI starts, the wrapper adds a small fixed-marker HTTP sidecar to each of the three
case-owned SuperNode Pods. The same two participant-to-participant health paths must first return
the exact expected markers. An exact NetworkPolicy then selects only these SuperNode Pods and
allows egress to the case-owned SuperLink Fleet Service on TCP 9092 plus CoreDNS on TCP/UDP 53.
The same two peer paths must time out twice, while each target sidecar remains healthy on localhost.
Only after that gate passes does the exact Flower companion run one round. Its existing receipt
assertion must also pass, demonstrating that the pinned workflow uses the allowed SuperLink path
under the active policy. Case-owned NetworkPolicy and health ConfigMap are deleted in cleanup.

This supplement exercises one in-cluster Flower path and a selected participant egress policy. The
three synthetic participants and aggregation service share one namespace in the Flower companion;
the base eight checks separately exercise namespace-level isolation. This is not proof of production
namespace governance, authenticated enrollment, TLS, cross-cluster transport, differential privacy,
Byzantine resistance, or the security of Flower SecAgg+. It uses only fixed synthetic vectors and
fixed health markers, with no actual training data or attack procedures. The two new checks are the
participant peer-flow gate and the Flower companion's existing actual-workflow check, for ten total.
