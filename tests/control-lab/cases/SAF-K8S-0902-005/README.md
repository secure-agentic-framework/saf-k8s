# SAF-K8S-0902-005 — Authenticated two-cluster inference failover

Run `python3 lab.py test SAF-K8S-0902-005 --docker-context desktop-linux`.
The case needs two local Kind cluster slots and OpenSSL. A fixture router in
the primary cluster can reach a second owned Kind cluster through a NodePort
assigned by its API. No host port is published. The test verifies the peer
address corresponds to the owned node on the local Kind bridge.

Mutual TLS authenticates normal callers and the router. The router checks both
the declared model revision and a SHA-256 digest computed by each backend from
the exact mounted immutable fixture bytes before requesting inference. A
separate immutable peer ConfigMap contains intentionally different, harmless
bytes under the same declared revision. The router must reject that peer after
its status response and before requesting inference. The fixture then restores
the approved bytes and verifies that the authorized peer route succeeds with
the expected digest. The backend also requires the expected digest on the
inference request and compares it with the bytes it has mounted immediately
before returning the fixture inference result. Separate backend logs record
status and successful inference calls. The wrong-content comparison is saved
to its own raw receipt before the peer Deployment rolls out the approved
ConfigMap; that receipt must show an empty inference log other than its single
status request. The later, restored peer Pod must have exactly its own
status-plus-inference log for the approved route. The previous primary
operation, authorization, stale
revision, and recovery checks remain. Ephemeral certificates and keys are
excluded from receipts. Both clusters are removed.

The digest is anchored to fixed, benign fixture files in this case. This proves
the local router refuses a same-label byte mismatch; it does not establish a
signed model manifest, external model provenance, production registry state,
production ingress or mesh behavior, tenant policy, operational failover,
monitoring, or certificate lifecycle. Those require separate evidence.

This isolated candidate retains the published nine assertions and adds one
same-label/different-bytes refusal assertion, for ten expected assertions. The
wrong-content status/log evidence is persisted before the Deployment rollout
so that Kubernetes' per-Pod logs cannot erase it. It has not been run; the
parent task owns runtime verification.

- [Kind multiple clusters](https://kind.sigs.k8s.io/docs/user/quick-start/#creating-a-cluster)
- [Kubernetes NodePort](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/#type-nodeport)
