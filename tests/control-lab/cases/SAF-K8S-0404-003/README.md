# SAF-K8S-0404-003 — Verify service peer identities and authorization over mTLS

Run `python3 tests/control-lab/lab.py test SAF-K8S-0404-003 --docker-context desktop-linux` from the framework checkout.

The four checks use case-owned TLS 1.3 client and service Pods, a fixture trust root and fixed service names. The baseline permits the operation over server-only TLS. The mutual-authentication phase refuses missing and untrusted client credentials and an incorrect server name. An authorized training identity completes the operation and an authenticated neighboring identity is refused by separate service policy. A replacement client leaf under the same CA and URI SAN reaches the live server and completes the approved operation. The case reports stable observations and uses only disposable keys and identities.

## Verify an adopted service path

1. Inventory the actual peers, source and destination names, trust domains, expected SANs, CA roots, issuer and enrollment, protocols, and independent operation policy. Include separate control, health and data paths and approved exceptions.
2. Observe actual bidirectional verification and effective allowed and denied operations. Use controlled pairs for missing, foreign, wrong-name and elapsed certificates, and for an authenticated but unauthorized peer. Attribute outcomes to the actual TLS or authorization decision.
3. Rotate an approved leaf, confirm issuance and reload, and verify the new certificate's identifier, validity, issuer and identity on the actual relying service. Verify the required old-leaf retirement or trust changes using the adopted authority. Include CA overlap, rollout scope, approved rollback and monitoring where applicable.
4. Repeat across governed controllers, namespaces, network paths and replicas. Capture sanitized peer and policy identifiers, facts used to validate the path and ownership of any gaps.

Related runnable controls exercise automatic certificate renewal and a relying client's observation of the new leaf (SAF-K8S-0404-001), and rejection by a relying verifier after a fixture CA revocation (SAF-K8S-0404-009).
