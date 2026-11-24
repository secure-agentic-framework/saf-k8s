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
