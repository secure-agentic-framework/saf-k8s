# SAF-K8S-0404-002 API extension TLS

Run by ID on fresh Kind. The actual API server validates two outgoing
extension connections independently, one admission webhook and one
aggregation APIService. Both reject a mismatched CA and server name.
With approved trust they reach the owned workload. A deliberate
AdmissionReview denial is distinct from either TLS failure.

The case uses short-lived fixture certificates and an isolated
extension. Production CA policy and rotation, extension-side
request authentication, and application-to-application channels
need separate evidence.

- [Admission webhook TLS](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes API aggregation](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/)

The owned extension listener requires TLS 1.3. It records the negotiated
version on the scoped admission request and the aggregation marker read.

## Trusted mutating webhook

The same owned TLS receiver handles one labeled ConfigMap CREATE dry-run
through a scoped MutatingWebhookConfiguration. An unrelated CA produces
an X.509 refusal from that exact route. Ordinary API reads still succeed.
With the approved CA bundle, the response contains the fixture's exact
annotation change, retains the input annotation, and matches an observed
TLS 1.3 receiver event.

Adopters verify the expected CA and route identity for each extension,
test the rejected and permitted states in an approved rehearsal, and
retain the actual API decision and continuity evidence.

## Unavailable backend and recovery

Each actual extension path is tested separately. The API server is pointed
at a case-owned Service with no endpoints while retaining the approved CA.
The matching dry-run webhook or read-only aggregation request reports the
route-specific unavailable condition. An ordinary namespace read continues.
After the healthy Service is restored, the exact route succeeds and emits
its expected receiver evidence. The healthy workload remains running.

Use the same approach when rehearsing unavailable target behavior for each
governed extension. Record the actual API policy, approved trust material,
failure and positive result, and any provider-specific visibility limits.

## Negotiated profiles on the exact extension paths

The owned TLS 1.3 receivers record the protocol and cipher for the exact
successful admission request, API aggregation marker, restored mutation
request, and restored validation request. These four operations each
negotiated TLS 1.3 with TLS_AES_256_GCM_SHA384 on the reviewed v1.36.1
fixture. The scoped wrong-trust and unavailable endpoints are still
refused and the authorized comparisons remain functional.

Review the actual Kubernetes release, Go TLS behavior and receiver
configuration for each path. This fixture records negotiation at the
receiver. Verify the deployed list of possible negotiated suites and
endpoints against the adopter's approval policy. If the provider does
not disclose a path, retain its disposition and evidence request.

- [Kubernetes v1.36 validating webhooks](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [Kubernetes v1.36 aggregation layer](https://v1-36.docs.kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/)
- [Go 1.26.2 TLS implementation](https://github.com/golang/go/blob/go1.26.2/src/crypto/tls/cipher_suites.go)
