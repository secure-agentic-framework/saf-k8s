# SAF-K8S-0404-001 — Issuance, scheduled renewal and active TLS reload

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0404-001 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
A disposable Kubernetes cluster installs the digest-pinned cert-manager
release. The case first demonstrates issuance refusal without the named
Issuer. With the approved namespaced CA-backed Issuer, it verifies the
leaf chain, identity, key algorithm, usage and recorded schedule. A
Certificate spec change replaces the key and leaf. The prior certificate
still validates under the original trust.

The scheduled comparison uses a separate short-lived Certificate and a
later scheduled comparator with the same fixture issuer. The controller
renews the due certificate under the existing spec while the later
comparator retains its original leaf and key. An independent client with
the fixed approved root verifies the initial TLS leaf, then observes the
replacement leaf from the continuing workload on a real HTTPS connection.
The server reopens the mounted leaf and key for new connections.

## Verify the adopted certificate lifecycle

1. Inventory the exact issuer types, scopes, consumers and supported client
   combinations. Record approved identities, chain and validity limits,
   key custody, Secret or hardware storage, authorized changes and planned
   renewal windows.
2. In an approved representative environment, compare refusal or absence
   with the issuer unavailable and successful issuance under the named
   authority. Verify actual chain, hostname, use and certificate identity.
   Validate the applicable controller and issuer versions and retain only
   public certificates or scoped observations in the review.
3. Observe a due renewal and a later healthy comparator. Record the
   controller decision and whether the spec and issuer stayed unchanged.
   Verify the replacement certificate and key, the interval before
   expiry, and the exact independently observed leaf at each live
   consumer and gateway after reload.
4. Establish the actual authority's revocation mechanism and client
   enforcement, including status source and trust. For an approved
   representative certificate, compare the same old leaf before and after
   revocation, and verify an approved replacement and unaffected peer.
   Record propagation and identify any unsupported relying parties. The
   cert-manager CA issuer can carry CRL/OCSP location metadata. The
   issuing authority and relying parties supply and enforce revocation.
   [SAF-K8S-0404-009 demonstrates an actual CA revocation and CRL-aware consumer](https://github.com/secure-agentic-framework/saf-k8s/blob/99e02e2dc5177f204cd2f7961311344ba825c27f/tests/control-lab/cases/SAF-K8S-0404-009/README.md).
5. Retain certificate metadata, policy and issuer revisions, observed
   reload and validation results, revocation enforcement and residual
   limits. Track supported renewal and revocation by actual provider and
   relying party.

[Cert-manager Certificate resources](https://cert-manager.io/docs/usage/certificate/)
and [cert-manager CA issuer behavior](https://cert-manager.io/docs/configuration/ca/).
