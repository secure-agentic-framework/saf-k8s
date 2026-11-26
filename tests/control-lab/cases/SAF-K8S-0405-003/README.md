# SAF-K8S-0405-003 — Kubeconfig trust and credential lifecycle

Run from the lab checkout.

```sh
python3 lab.py test SAF-K8S-0405-003 --docker-context desktop-linux
```

From the framework checkout, invoke `python3 tests/control-lab/lab.py`.
The disposable Kind fixture verifies an owner-only profile, the selected
context and API endpoint, and scope of the server-issued credential.
A static profile review identifies the unapproved plugin command without
executing it. The exact reviewed plugin supplies an ExecCredential
directly to the Kubernetes client. With the approved trust anchor it can
read the intended object. The API refuses its other read. An independent
valid trust anchor fails the TLS handshake against the owned endpoint.

The bound credential is accepted before its case-owned reference is
removed. After removal both the original and approved plugin profiles
lose access, and an independent administrator can still read the
fixture. The reports retain the mode, approval, TLS and API outcomes
without the ephemeral credentials.

## Verify an adopted client

1. Inventory the actual kubeconfig contexts, endpoints, trusted CA
   identities, users, exec paths and credential sources. Verify file
   permissions and encryption under the applicable workstation or
   runner storage policy. Audit authorized copies and access.
2. Require signed or otherwise approved plugin binaries and arguments.
   Passively inspect the exact config and verify provenance before any
   untrusted profile could invoke a plugin. Record approved binary
   digest, custody, the resolved executable and supported protocol.
3. Exercise the approved context with legitimate authorized and denied
   API requests. Verify the exact accepted identity, TLS endpoint
   verification and operation scope. Repeat an owned wrong trust
   comparison in a disposable representative environment.
4. Verify authoritative issuance, expected lifetime, offboarding and
   revocation. Compare the same previously valid profile with an
   independent authorized control after the real issuer changes.
   Retain outcomes, owner, timestamps and post-change retrieved access
   evidence without raw credentials.

[Kubernetes kubeconfig](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/)
and [Kubernetes service account administration](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).
