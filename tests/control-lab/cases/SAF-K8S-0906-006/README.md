# SAF-K8S-0906-006 — Authenticate producers and query stored training lineage

Run `python3 tests/control-lab/lab.py test SAF-K8S-0906-006 --docker-context desktop-linux` from the framework checkout. This case uses the OpenSSL CLI for disposable TLS setup.

The five checks run isolated Kubernetes Jobs over synthetic source, transform and model records on case-owned PersistentVolumeClaims. An owned HTTPS signer verifies projected producer tokens and audience through native TokenReview and signs canonical stage receipts. The release and separate read-only query verify all three signatures against the pinned public key and confirm the exact source, transform and artifact digests. The alternate producer is denied a signature. The retained records support forward and backward queries across separate Jobs, and ungoverned and unknown inputs yield no release matches.

## Verify adopted producer authority and durable lineage

1. Inventory actual source, transform, training and release authorities and their authentication. Verify the signer, expected issuer and audience, private-key custody and rotation, receipt version and required identities. Use independently controlled trust to reject an unrelated or altered receipt.
2. Follow an approved artifact through its actual parent versions and transformation records. Verify backward artifact lookup and forward affected-release lookup at the actual storage and release boundaries, including missing and superseded references.
3. Test governed retention, authorized access, protected archive and recovery on the chosen lineage and artifact store. Retrieve the prior records after a later release and after an approved recovery. Verify restored identifiers, signatures and digests before using them to release or recall artifacts.
4. Record actual path coverage, time and policy revisions, artifact and receipt identifiers, accountable owners and governed exceptions.

- [Kubernetes ServiceAccounts](https://v1-36.docs.kubernetes.io/docs/concepts/security/service-accounts/)
- [Kubernetes TokenReview](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/)
- [Kubernetes Persistent Volumes](https://v1-36.docs.kubernetes.io/docs/concepts/storage/persistent-volumes/)
