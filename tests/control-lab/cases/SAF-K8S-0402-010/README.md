# SAF-K8S-0402-010 workload identity federation

Run from the framework checkout:

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0402-010 --docker-context desktop-linux
```

The reference uses the pinned Kubernetes v1.37.0 Kind node image and the
stable ClusterTrustBundle and PodCertificateRequest APIs. A running Pod
receives only the bundle selected by signer and label. It observes the
approved replacement bundle without restarting. A workload identity request
stays unissued without the allowed signer and yields the exact local key
and certificate path after the signer becomes available.

Two disposable clusters exchange only the selected public roots. Each
workload's key remains in its own Pod. The receiving cluster exposes one
NodePort on the inspected shared Kind network, with no host port mapping.
The approved source Pod completes mutual TLS, verifies the destination DNS
and URI identities, and receives the allow decision. A trusted certificate
for a different URI completes TLS and receives a separate authorization
denial. A structurally valid certificate with the expected URI from an
unexchanged authority receives a TLS unknown-CA alert, corroborated by the
receiving server's certificate-validation result.

The same source Pod later observes a new valid key and certificate from a
distinct issuance request. The fixture deletes both clusters and its exact
temporary local image tag. The receipt retains decisions and public
comparisons.

## Verify an adopting implementation

1. Inventory all trust and administrative domains, issuer approval,
   federation endpoints, named bundles, and each governed client and server
   identity. Verify how an approved peer's public root is authenticated,
   distributed, refreshed, and revoked.
2. Verify exact relying-party identities and trust sources on each effective
   route. Exercise an allowed peer, a trusted but unauthorized identity, and
   an untrusted issuer in an approved staging environment. Preserve separate
   authentication and authorization decisions.
3. Verify workload certificate renewal, key isolation and behavior during
   issuer, bundle or route failures. Record effective trust, versions,
   rotation evidence, failure outcomes, and the appropriate owner.
4. Review any SPIFFE/SPIRE or provider identity and trust-plane controls on
   their actual implementation. The Kind fixture covers two native
   Kubernetes clusters and case-owned issuers.

[Kubernetes v1.37.0 release notes](https://github.com/kubernetes/kubernetes/blob/v1.37.0/CHANGELOG/CHANGELOG-1.37.md).
