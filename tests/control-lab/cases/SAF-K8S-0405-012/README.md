# SAF-K8S-0405-012: Keycloak LoA to owned Kubernetes API

This case checks the provider enrollment and step-up flow and makes one grouped comparison against the fresh Kind cluster's actual kube-apiserver JWT authenticator and RBAC.

## Candidate behavior

At Keycloak 26.8.2 startup, the case imports `realm-fixture.json` from a Secret volume. The import contains only the fixture realm, public PKCE client definition, default `basic` access-token subject scope, an explicit access-token audience mapper, `acr loa level` mapper, realm ACR-to-LoA map, and one generated-password test user. It then creates the documented browser LoA flow through the versioned Admin REST endpoints: level 1 is password (`loa-max-age=36000`); level 2 is OTP (`loa-max-age=0`). The level-2 login requests essential ACR 2, and the case checks the actual access-token issuer, audience, `sub`, `acr`, and signing-key identifier before using it.

The Keycloak Pod is pinned to the single run-owned Kind control-plane node with `hostNetwork` and HTTPS bound to node loopback only at `127.0.0.1:17443`. The runner's port-forward also binds only `127.0.0.1:17443`. No Service, NodePort, host publication, external issuer or user token is used. The API node and runner each fetch the exact discovery and JWKS documents over the locally issued CA-verified TLS chain. The test then enables `AuthenticationConfiguration` only on the run's owned static API manifest. The rule requires exact issuer, the dedicated audience, and `claims.acr == '2'`.

Two inert ConfigMaps are created in `saf-test`. A namespaced Role grants `get` only on the approved marker to the Keycloak `sub` mapped under the `keycloak-fixture:` username prefix. The single supplemental result requires all of these outcomes:

- the actual audience-correct level-1 token receives HTTP 401;
- the actual audience-correct level-2 token reads the approved marker with HTTP 200;
- the same level-2 token receives HTTP 403 for the other ConfigMap.

The first three checks retain their existing identities and roles: password-only baseline, required OTP enrollment, and valid TOTP completion. Total expected checks: **4**.

## Secret and cleanup boundaries

The fixture password and Keycloak bootstrap password are generated in memory. The JSON realm import is built in memory with the user password inserted, then the Realm import, TLS key, and bootstrap password are sent to the Kubernetes API using a captured direct subprocess; `Lab.command` is deliberately not used for this Secret operation because it logs stdin. Tokens, codes, TOTP material, passwords, and private keys are not printed, placed in arguments, or included in evidence. The OIDC bearer is sent in-process only to the loopback kube-apiserver endpoint using kubeconfig CA verification; raw response bodies are discarded except the approved fixed marker.

The API manifest is backed up byte-for-byte inside the owned node before the authentication argument is added. `finally` restores the original manifest, removes the temporary API auth config and node-side public CA copy, and waits for the API to be ready after a replacement. The port-forward process is stopped in its context manager. The enclosing lab deletes the whole Kind cluster and its Secret. Temporary CA and issuer private keys live under the runner's temporary directory, outside retained evidence.

Port 17443 is intentionally fixed because the API server and Keycloak issuer must use the same loopback URL. Run this case serially with other local fixtures using that port. The case fails closed before starting a forward if the port is already occupied and verifies the exact loopback forward line. It does not change host networking, firewall state, or host files.

## Source scope and adopter evidence

This proves one real synthetic Keycloak TOTP flow, one configured Keycloak ACR claim, one API-server trust/claim-validation path, and one exact namespaced RBAC decision on the pinned local Kind profile. It does not establish phishing resistance, organization-selected AAL, production IdP assurance, other authenticators or login paths, cluster-admin role coverage, recovery accounts, audit correlation, or deployed network/firewall topology. Adopters must verify those actual issuer/client/claim bindings and least-privilege role decisions on each production authentication path.

## Versioned references

- [Keycloak 26.8.2 step-up flow guide](https://www.keycloak.org/docs/26.8.2/server_admin/) and the [26.8.2 flow source](https://raw.githubusercontent.com/keycloak/keycloak/26.8.2/docs/documentation/server_admin/topics/authentication/flows.adoc): ordered LoA subflows, numeric levels, max-age, essential ACR request, ACR mapper and token claim validation.
- [Keycloak 26.8.2 Admin REST API](https://www.keycloak.org/docs-api/26.8.2/rest-api/): create flow, create subflow/execution, update execution requirements and configure the conditional LoA execution.
- [Kubernetes v1.36 authentication](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/authentication/): JWT issuer, audience, CA, CEL claim validation and username mapping.

Run from the framework checkout with `python3 tests/control-lab/lab.py test SAF-K8S-0405-012 --docker-context desktop-linux`. The image pin and loopback Kubernetes command use the shared SAF-K8S-0405-017 provider helper.
