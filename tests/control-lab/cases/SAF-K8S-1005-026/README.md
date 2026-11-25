# SAF-K8S-1005-026 — Forensic chain of custody and evidence handling

This case checks a narrow, synthetic custody workflow in one disposable, single-node Kind cluster running Kubernetes v1.36.1. An immutable ConfigMap stores one checked-in inert text fixture whose expected SHA-256 is pinned in `case.py` and `fixtures/case.json`. The case reads the stored bytes back, attempts to change them, then confirms the API rejected the data update and the bytes stayed the same. A tokenless, digest-pinned Python Job reads the fixture and produces raw JSON custody records. No real evidence, identity, credential, feed, target, or external service is used.

## Outcomes

The three transfer scenarios use the same fixture ID and transfer ID, source, destination, purpose, and synthetic timestamp:

- **Red:** The transfer has a `pending` authorization label. With the workflow gate disabled, the mock completes it anyway. Its receipt makes the missing approval visible.
- **Green:** With the gate enabled, that same pending transfer is blocked. The fixture remains at the immutable-storage label, and a hash-linked blocked-attempt record is retained.
- **Positive:** With the gate enabled and an `approved` label whose synthetic approver role and scope match the transfer, the mock records a completed transfer to the fictional review destination.

Each event includes a sequence number, synthetic timestamp, fixture ID, expected artifact SHA-256, action, current and requested destination labels, authorization label/status/scope, previous-event SHA-256, outcome, and its own SHA-256. The Job checks event sequence, link continuity, event hashes, and artifact digest. `evidence/SAF-K8S-1005-026/<run-id>/custody-observations.raw.json` contains the unredacted machine-readable output; it contains only synthetic metadata and the inert fixture digest. The harness also retains the Kubernetes command transcript and structured check results.

The case stores that raw receipt in a second immutable, labeled ConfigMap and verifies its readback and SHA-256 annotation. This provides an independently observable API copy during the disposable run. It remains subject to the same deletion, recreation, cluster-administrator, durability, and independent-retention limits described below.

## Source basis and limits

NIST SP 800-86 recommends documenting significant incident-response actions, preserving integrity, maintaining chain of custody, and storing evidence securely. NIST's glossary describes chain of custody as tracking evidence movement through collection, safeguarding, and analysis, documenting handlers, times, and transfer purpose. This case uses synthetic role labels, fixed fictional timestamps, and explicit transfer purposes to make those fields observable; it does not verify a real person's identity, authority, clock, or handling actions. NIST SP 800-86 is guidance, not a complete forensic procedure or legal advice.

Kubernetes documents that `immutable: true` prevents ConfigMap data changes, while object metadata can still change; the object can also be deleted and recreated. The case tests rejection of an update in this disposable API server. A ConfigMap is not durable, separately administered, encrypted, WORM, or tamper-proof evidence storage. This test does not prevent deletion/recreation by a sufficiently privileged cluster identity, prove API audit-log retention, or anchor the final hash outside the same cluster. ConfigMaps are for non-confidential data, which is appropriate only because the fixture is public synthetic text.

The hash chain and SHA-256 demonstrate byte equality and internal receipt linkage for this fixed run. Without a trusted external signature, protected clock, independently controlled storage, verified identities, complete source acquisition, validated forensic process, and independently retained chain head, they do not authenticate a custodian, prove completeness, establish that records were not rewritten as a whole, or establish legal admissibility. Authorization labels are test data, not an authorization system. The case evaluates a local workflow function; it does not install Kubernetes admission enforcement, RBAC controls, or an organization-wide incident-response procedure.

| Claim area | Case evidence | Unresolved or out of scope |
| --- | --- | --- |
| Fixture integrity | Expected SHA-256 matches the fixture file and bytes read from the immutable ConfigMap | Authenticity or completeness of any real acquisition |
| Storage integrity | API reports immutable; attempted data update fails; readback remains byte-identical | Durable/WORM retention, deletion/recreation, cluster-admin actions, backup, encryption, audit retention |
| Traceability | Synthetic collection, storage, transfer/blocked-attempt events with hash-linked sequence and purpose labels | Real handler identity, actual date/time, independent trusted timestamp or external hash anchoring |
| Authorization | Pending transfer is blocked by the enabled workflow gate; matching approved role/scope succeeds | Actual organizational authority, approver authentication, separation of duties, legal authorization |
| Transfer behavior | Same fictional transfer compared with gate off/on plus approved positive action | Any actual transfer, evidence seizure, production integration, legal admissibility |

The Kind node image is pinned in `case.py` to the digest published by Kind v0.32.0 for Kubernetes v1.36.1. The Python worker uses the digest-pinned Docker Official Image `python:3.13-slim`. The supervisor's harness provides the node image to Kind; this case does not create a cluster itself.

## Official primary sources

- [NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final) — scope and status of the NIST guidance.
- [NIST SP 800-86 publication PDF](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf) — recommendations on documenting actions, integrity, chain of custody, and secure storage.
- [NIST CSRC Glossary: Chain of custody](https://csrc.nist.gov/glossary/term/chain_of_custody) — movement, handling, time, and purpose record elements.
- [Kubernetes v1.36 ConfigMap API](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/core/config-map-v1/) — immutable field behavior.
- [Kubernetes ConfigMaps](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/) — ConfigMaps store non-confidential data; immutable objects can be deleted and recreated.
- [Kind v0.32.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0) — Kubernetes v1.36.1 node image and its digest.
- [Docker Official Image: Python 3.13 slim](https://hub.docker.com/layers/library/python/3.13-slim) — worker image digest.

No cluster or workload has been run as part of this draft. The supervisor should execute and review the case in the lab's disposable-cluster workflow.

The supervisor independently recomputes the hashes and sequence links for all
three event chains and tests rejection of an edited event. The Kubernetes API
separately rejects updates to the immutable source ConfigMap.

## Verify an adopting implementation

Bind every evidence transfer to an authenticated investigator,
approved case/scope, source/destination, purpose, and trusted timestamp.
Require independent authorization, protect signed/hash-linked custody records
in durable access-controlled retention, and verify them independently after
each transfer. Exercise pending/denied and approved inert transfers; retain
policy/legal approval and access/audit evidence without storing sensitive
payloads in receipts.
