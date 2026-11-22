# SAF-K8S-0103-018 — Control-plane replica distribution and etcd quorum topology

Run from the SAF-K8S control lab directory with a local Docker context:

```sh
python3 lab.py test SAF-K8S-0103-018 --docker-context <local-unix-socket-context>
```

## Sources and catalog basis

- Pinned local catalog index: revision `133a8698a45e2b335b51728bf4c62f7bda98d15f`; control digest `a89d65de77be30e70cdf4a4705c938538ffbeaddc916f97d5f8e174351e46a06`.
- Framework worktree inspected at commit `e6c14f0bfb63d7e221447e20d136a8cfb8ba31a0`; current text is `../saf-k8s-framework/markdown/controls/SAF-K8S-0103-018.md`.
- [Kubernetes v1.36 kubeadm high availability](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/) describes stacked versus external etcd, recommends three or more control-plane machines, and says odd etcd membership is required for optimal voting quorum.
- [Kubernetes v1.36 HA topology options](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/ha-topology/) describes co-located stacked etcd versus separate external etcd and their topology tradeoffs.
- [Kubernetes v1.36 setting up HA etcd with kubeadm](https://v1-36.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/setup-ha-etcd-with-kubeadm/) documents kubeadm's local etcd on each control-plane node in the stacked topology.
- [etcd v3.6 failure modes](https://etcd.io/docs/v3.6/op-guide/failures/) covers majority quorum and member availability during failures.
- [etcd v3.6 FAQ](https://etcd.io/docs/v3.6/faq/) explains majority calculation and why an added even member can leave failure tolerance unchanged. The fixture uses quorum `floor(n/2)+1`: 3 members require 2 and tolerate 1 loss; 4 require 3 and tolerate 1; 5 require 3 and tolerate 2.
- [kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/) permits multiple control-plane nodes and cautions that kind nodes have limited isolation and do not add real compute capacity.
- Pinned node image in the lab runner: `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`; pinned stacked-etcd image expected from kubeadm: `registry.k8s.io/etcd:3.6.8-0`.

## Scope and prerequisites

The case provisions the three-control-plane topology in `kind.yaml`. It checks the Kubernetes server version and exact Ready node set. It checks one Ready static mirror Pod per kubeadm control-plane component on each node, one Ready etcd static Pod per node, matching three-member etcd views, three distinct member IDs and peer URLs, and each member’s readiness and health. It then stops only the generated `<case-cluster>-control-plane` Docker container for a bounded maintenance window, checks API `/readyz`, and writes and reads one synthetic ConfigMap in `saf-test`. The container is restarted in `finally`. The case waits for the full set of Ready static replicas by node, inspects each etcd member through its case-owned node’s local runtime, and runs an independent API write/read before cluster deletion.

Prerequisites: Python 3.9+, compatible kind and kubectl versions, a local Docker Unix-socket context, and the pinned node image. Image pulls and cluster creation are performed only when the supervisor executes the case. No external endpoint is contacted by the probe. No workload flood, partition, or exploit is used.

The failure-domain fixture is explicitly synthetic: one case concentrates all three replicas in `zone-a`; its modeled loss leaves zero of three and misses a two-member quorum. The green model assigns one replica to each of three synthetic domains; losing one leaves two of three. These are reproducible model results, not measurements of Docker placement. Three local containers on one Docker host do not demonstrate distinct physical hosts, racks, zones, power, storage, or network failure domains.

## Expected outcomes

The framework retains the passing receipt at `verified/SAF-K8S-0103-018.json`. The local runner also writes `evidence/SAF-K8S-0103-018/<run-id>/result.json` and `commands.log` for each rerun.

| Phase | Reproducible input | Expected result |
| --- | --- | --- |
| Red | `red-concentrated-control-plane`, lose synthetic `zone-a` | 0 survivors, quorum 2, unavailable; assertion records `red OK` when this counterexample is reproduced. |
| Green | `green-one-member-per-synthetic-domain`, lose synthetic `zone-a` | 2 survivors, quorum 2, available; assertion records `green OK`. |
| Positive | Compare 3, 4, and 5 etcd members | 3 tolerates 1 loss, 4 tolerates 1, and 5 tolerates 2; the odd count is efficient for tolerance and is not sufficient by itself to guarantee failure-domain placement. |
| Live green | Pinned three-control-plane kind fixture and a planned stop of its first control-plane container | Exact three-member topology and readiness; API readiness and synthetic ConfigMap read/write expected to continue with one node stopped; restarted node expected Ready.  |

## Findings and verification boundary

This fixture can verify local stacked-etcd mechanics and one-member maintenance under kind v1.36.1. It cannot verify physical-domain separation, production capacity, sustained client traffic, real zone-loss behavior, external-etcd topology, managed-provider SLA/implementation, or application-level availability. The catalog's literal “distinct failure domains” and production guarantee therefore require inventory and provider/architecture evidence outside this lab. The case reports a tested local demonstration only; it does not validate the full production claim.

## Cleanup

The runner creates a unique kind cluster and deletes it in its cleanup path. During maintenance, the case restarts the exact stopped node in a `finally` block before checking recovery. Case-owned API data consists of the three probe ConfigMaps in `saf-test` and is removed with the cluster. If a supervisor interruption prevents the runner's cleanup block from completing, inspect only the reported generated cluster/container and remove that case-owned cluster; do not target unrelated containers or clusters.
