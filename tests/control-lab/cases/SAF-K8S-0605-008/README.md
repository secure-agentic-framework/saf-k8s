# SAF-K8S-0605-008 — Admission webhook TLS rotation and high-availability resilience

This case is prepared for local replay with:

```sh
python3 lab.py test SAF-K8S-0605-008 --docker-context desktop-linux
```

The case uses the repository runner's pinned Kubernetes v1.36.1 Kind node image and a digest-pinned Python backend image. It installs two separately addressable HTTPS AdmissionReview backends behind one shared ClusterIP Service. All requests are ordinary server-dry-run creates for named synthetic ConfigMaps in the case namespace.

## Live evidence

1. It creates independent short-lived old, new, and unrelated synthetic CAs. After verifying the original CA and leaf, it submits a matching dry-run through backend A with only the unrelated CA trusted. The expected result is an API error identifying X.509 trust failure; a namespace read remains available. A second negative probe presents a trusted backend B certificate through backend A's Service and expects X.509 hostname rejection.
2. For renewal, it adds old and new CA certificates to `caBundle`, replaces backend A and backend B certificates one at a time, and directly calls each backend through its own Service. OpenSSL checks the issuing chain and server-auth purpose before distribution. The running API server checks the Service DNS identity. Rotation waits for the exact old Pod to terminate and verifies the replacement mounts the staged Secret. Each successful direct call must also appear as a fixed backend event with the SHA-256 fingerprint of the certificate actually loaded by that backend. The case checks both the old backend B fingerprint and new backend A fingerprint during overlap, then verifies each new fingerprint. It then removes old CA trust and checks the shared Service.
3. It confirms the shared Service has two ready endpoints, scales only case-owned backend B to zero, waits for exactly one endpoint, and requires a new matching dry-run to reach backend A successfully. The PodDisruptionBudget rejects a server-side dry-run eviction of that last backend, and the API server publishes a latency histogram with actual samples for the webhook.

The server logs only fixed event, backend, and public certificate fingerprint fields. It suppresses HTTP request logging. TLS keys are generated in a temporary directory and never printed. The `caBundle` and certificate contents are used as fixture data; they are not credentials for any external system.

All 13 assertions passed on Kubernetes v1.36.1 in `evidence/SAF-K8S-0605-008/20261122T090937Z-db2df575/result.json`.

## Boundaries

Replay can establish that this synthetic API server rejects an untrusted webhook certificate, keeps unrelated API reads available, validates each newly signed backend certificate during an overlap window, and still reaches the remaining endpoint through the Service. It does not establish automated production certificate issuance or renewal, atomic/secure trust distribution, secret access governance, endpoint rollout safety under production traffic, cross-zone or multi-control-plane topology, managed Kubernetes configuration, policy ownership, centralized monitoring and alerts, or recovery objectives. Those require production configuration and operational evidence.

## References

- [Kubernetes v1.36 dynamic admission documentation](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes v1.36 admission webhook good practices](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/)
- [Kubernetes v1.36.1 admissionregistration API types](https://github.com/kubernetes/kubernetes/blob/v1.36.1/staging/src/k8s.io/api/admissionregistration/v1/types.go)
- [Kubernetes v1.36.1 webhook TLS client and Service DNS identity](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.1/staging/src/k8s.io/apiserver/pkg/util/webhook/client.go)
- [Kubernetes v1.36.1 validating webhook failure and dry-run handling](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.1/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/validating/dispatcher.go)

The fixture structure reuses the certificate generation, TLS AdmissionReview server, and bounded ConfigMap dry-run patterns from SAF-K8S-0605-007 and SAF-K8S-0101-015. It does not import from or read those case directories at runtime.

## Adopter verification

1. Record the actual issuer, certificate automation, SANs, trust distribution,
   replica topology, endpoint health, and alert route for every admission
   webhook.
2. In a controlled rollout, retain old/new overlap evidence, prove both
   renewed endpoints serve under the new trust, then retire old trust and
   verify admission still succeeds. Include rollback and expiry alert evidence.
3. Confirm disruption budgets and availability objectives for the deployed
   topology; do not treat the fixture's sampled latency as a universal SLO.

Open child: `saf-lab-0605-008.1`. Native receipt: 13 checks.
