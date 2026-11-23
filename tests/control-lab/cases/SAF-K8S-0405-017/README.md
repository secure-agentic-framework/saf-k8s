# SAF-K8S-0405-017 Password policy at an identity provider

Run the test by ID on fresh Kind. The API server hosts a pinned,
disposable Keycloak instance. Its native password policy is exercised
before and after requiring a minimum length and a fixture blocklist.
The case verifies a successful login and userinfo response for an
accepted lowercase-only password. The provider is reachable through
a temporary loopback port-forward and all credential values stay out
of the retained evidence. The case imports the pinned image from Docker
into every fresh cluster so only the first run needs the registry.

The local client uses a password grant solely to confirm the verifier
accepts the chosen password. Real federation, broader blocklist coverage,
rate limiting, storage and non-password authenticator policies require
their own verification.

- [NIST SP 800-63B-4 password verifier requirements](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)
- [Keycloak password policies](https://www.keycloak.org/docs/latest/server_admin/#_password-policies)
- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
