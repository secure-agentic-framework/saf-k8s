# SAF-K8S-0405-012 A real second factor at the OIDC provider

Run by ID on fresh Kind. The fixture starts a disposable Keycloak
provider and uses its actual browser login forms and OIDC code exchange
with PKCE over verified loopback TLS. A synthetic user enrolls a temporary TOTP authenticator.
A new session with just the password stops at the provider challenge.
A valid response in a fresh time window completes the code exchange.
The case retains only boolean observations.

The case imports the provider fixture and reuses the pinned Docker image
from SAF-K8S-0405-017, including its local image-loading path.
Deployment verification must cover the actual privileged Kubernetes
and cloud paths, factor assurance, credential inventory, and documented
exceptions and emergency recovery.

- [Keycloak authentication flows and OTP](https://www.keycloak.org/docs/latest/server_admin/#_authentication-flows)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Kubernetes authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/)
