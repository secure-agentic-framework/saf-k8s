# SAF-K8S-0402-007 Human OIDC authentication

Run `python3 lab.py test SAF-K8S-0402-007` against the catalog revision in the
verified result. The disposable Kind node serves a loopback HTTPS OIDC
discovery endpoint. Locally generated short-lived test credentials and a
structured API-server authentication configuration exercise issuer, signature,
audience, expiry, required claims and mapped groups. A separate RBAC
binding controls access to an owned ConfigMap.

The case observes authorization removal on an unexpired JWT that still
authenticates. It restores the binding and original API-server configuration.
Enterprise IdP MFA, a provider's refresh and session lifecycle, and managed
control-plane integration require separate evidence. Key and token values
are ephemeral and are omitted from all output.

- [Kubernetes authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes RBAC](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
