"""Join real Keycloak LoA tokens to the one disposable kube-apiserver JWT authenticator."""
import base64
import json
import ssl
import time
from http.client import HTTPSConnection
from urllib.parse import urlsplit

import yaml

REALM = "fixture-mfa"
ISSUER = "https://127.0.0.1:17443/realms/fixture-mfa"
API_AUDIENCE = "saf-k8s-mfa-api"
API_USERNAME_PREFIX = "keycloak-fixture:"
CLIENT = "fixture-mfa-relying-party"
API_CONFIG = "/etc/kubernetes/pki/saf-0405-012-authentication.json"
API_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"
API_BACKUP = "/etc/kubernetes/saf-0405-012-apiserver.yaml"

NS = "saf-test"
NODE_CA = "/etc/kubernetes/pki/saf-0405-012-keycloak-ca.crt"
ALLOW_NAME = "mfa-approved-marker"
DENY_NAME = "mfa-outside-marker"
ROLE = "mfa-approved-marker-reader"
SUBJECT_MARKER = "fixture-owned-approved-value"


def _decode_claims(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None, None
    def decode(value):
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return json.loads(raw)
    try:
        return decode(parts[0]), decode(parts[1])
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None, None


def _jwt_observation(token, jwks, subject_id):
    header, claims = _decode_claims(token)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return {"well_formed": False, "issuer_matches": False,
                "audience_matches": False, "acr_is_expected": False,
                "subject_matches_fixture": False, "signing_key_listed": False,
                "acr_level_1": False, "acr_level_2": False}
    aud = claims.get("aud", [])
    aud = aud if isinstance(aud, list) else [aud]
    kid = header.get("kid")
    listed = isinstance(jwks, dict) and any(key.get("kid") == kid for key in jwks.get("keys", []))
    return {
        "well_formed": header.get("alg") == "RS256" and header.get("typ") == "JWT",
        "issuer_matches": claims.get("iss") == ISSUER,
        "audience_matches": API_AUDIENCE in aud,
        "acr_is_expected": claims.get("acr") in {"1", "2"},
        "subject_matches_fixture": claims.get("sub") == subject_id,
        "signing_key_listed": bool(listed),
        "acr_level_2": claims.get("acr") == "2",
        "acr_level_1": claims.get("acr") == "1",
    }


def _id_token_observation(token, subject_id, expected_acr):
    _header, claims = _decode_claims(token)
    audience = claims.get("aud", []) if isinstance(claims, dict) else []
    audience = audience if isinstance(audience, list) else [audience]
    return {
        "issuer_matches": isinstance(claims, dict) and claims.get("iss") == ISSUER,
        "client_audience_matches": CLIENT in audience,
        "subject_matches_fixture": isinstance(claims, dict) and claims.get("sub") == subject_id,
        "acr_matches_requested_level": isinstance(claims, dict)
            and claims.get("acr") == expected_acr,
    }


def _admin(lab, node, *args, payload=None, timeout=25, allow_failure=False):
    # Admin manifest/config contain public trust material only; never pass tokens or passwords here.
    return lab.command("docker", "exec", *([] if payload is None else ["-i"]), node,
                      *args, payload=payload, timeout=timeout, allow_failure=allow_failure)


def _node_discovery(lab, node, ca_cert):
    _admin(lab, node, "install", "-d", "-m", "0755", "/etc/kubernetes/pki")
    lab.command("docker", "cp", str(ca_cert), node + ":" + NODE_CA, timeout=15)
    discovery = _admin(lab, node, "curl", "--noproxy", "*", "--silent", "--show-error",
                       "--fail", "--max-time", "8", "--cacert", NODE_CA,
                       ISSUER + "/.well-known/openid-configuration", timeout=12)
    if discovery.returncode:
        lab.block("The disposable API node could not verify the actual Keycloak discovery endpoint")
    try:
        metadata = json.loads(discovery.stdout)
    except (ValueError, json.JSONDecodeError):
        lab.block("The actual Keycloak discovery document was not JSON")
    if metadata.get("issuer") != ISSUER or \
            metadata.get("jwks_uri") != ISSUER + "/protocol/openid-connect/certs":
        lab.block("Keycloak discovery issuer or JWKS URL did not match the exact trusted realm")
    jwks_result = _admin(lab, node, "curl", "--noproxy", "*", "--silent", "--show-error",
                         "--fail", "--max-time", "8", "--cacert", NODE_CA,
                         metadata["jwks_uri"], timeout=12)
    if jwks_result.returncode:
        lab.block("The disposable API node could not fetch the trusted Keycloak JWKS")
    try:
        jwks = json.loads(jwks_result.stdout)
    except (ValueError, json.JSONDecodeError):
        lab.block("The actual Keycloak JWKS was not JSON")
    if not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
        lab.block("The trusted Keycloak JWKS did not contain a signing key")
    return jwks


def _configure_api(lab, node, ca_cert):
    config = {
        "apiVersion": "apiserver.config.k8s.io/v1",
        "kind": "AuthenticationConfiguration",
        "jwt": [{
            "issuer": {"url": ISSUER, "audiences": [API_AUDIENCE],
                       "certificateAuthority": ca_cert.read_text()},
            "claimValidationRules": [{
                "expression": "claims.acr == '2'",
                "message": "fixture Kubernetes API access requires Keycloak LoA 2",
            }],
            "claimMappings": {"username": {"claim": "sub", "prefix": API_USERNAME_PREFIX}},
        }],
    }
    _admin(lab, node, "cp", "-p", API_MANIFEST, API_BACKUP)
    _admin(lab, node, "sh", "-ceu", 'cat >"$1"', "write-authentication-config", API_CONFIG,
           payload=json.dumps(config))
    raw = _admin(lab, node, "cat", API_MANIFEST).stdout
    manifest = yaml.safe_load(raw)
    containers = [container for container in manifest.get("spec", {}).get("containers", [])
                  if container.get("name") == "kube-apiserver"]
    if len(containers) != 1:
        lab.block("The owned Kind node did not have exactly one kube-apiserver static Pod")
    command = containers[0].get("command", [])
    if any(arg.startswith(("--oidc-", "--authentication-config")) for arg in command):
        lab.block("The owned API already has unexpected external authentication flags")
    command.append("--authentication-config=" + API_CONFIG)
    _admin(lab, node, "sh", "-ceu",
           'temporary="$(dirname "$1")/.saf-auth-manifest.tmp"; cat >"$temporary"; '
           'chmod --reference="$1" "$temporary"; mv "$temporary" "$1"',
           "activate-authentication-config", API_MANIFEST,
           payload=yaml.safe_dump(manifest, sort_keys=False))


def _api_container(lab, node):
    result = lab.command("docker", "exec", node, "crictl", "ps", "--name", "^kube-apiserver$", "-q",
                         timeout=10, allow_failure=True)
    values = result.stdout.splitlines()
    return values[0] if result.returncode == 0 and len(values) == 1 else None


def _wait_replaced_api(lab, node, previous):
    deadline = time.monotonic() + 110
    while time.monotonic() < deadline:
        current = _api_container(lab, node)
        if current and current != previous:
            ready = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=12)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return
        time.sleep(1)
    lab.block("The owned kube-apiserver did not become ready after the auth configuration change")


def _restore_api(lab, node):
    current_manifest = _admin(lab, node, "cat", API_MANIFEST, timeout=15, allow_failure=True)
    auth_was_configured = current_manifest.returncode == 0 and \
        ("--authentication-config=" + API_CONFIG) in current_manifest.stdout
    restore = _admin(lab, node, "sh", "-ceu",
                     'temporary="$(dirname "$2")/.saf-auth-manifest.tmp"; '
                     'if test -f "$1"; then cp -p "$1" "$temporary"; '
                     'mv "$temporary" "$2"; rm -f "$1"; fi; rm -f "$temporary"; '
                     'rm -f "$3" "$4"', "restore-owned-api", API_BACKUP, API_MANIFEST,
                     API_CONFIG, NODE_CA, timeout=25, allow_failure=True)
    if restore.returncode:
        lab.block("Could not restore the exact original disposable API manifest")
    return auth_was_configured


def _kubeconfig_api(lab):
    kubeconfig = yaml.safe_load(lab.kubeconfig.read_text())
    expected_context = "kind-" + lab.cluster
    if kubeconfig.get("current-context") != expected_context:
        lab.block("The OIDC probe kubeconfig is not the run-owned Kind context")
    context = next((row for row in kubeconfig.get("contexts", [])
                    if row.get("name") == expected_context), None)
    if not context:
        lab.block("The run-owned Kind context is missing from its kubeconfig")
    cluster_name = context.get("context", {}).get("cluster")
    cluster = next((row.get("cluster") for row in kubeconfig.get("clusters", [])
                    if row.get("name") == cluster_name), None)
    server = cluster.get("server", "") if cluster else ""
    parts = urlsplit(server)
    if parts.scheme != "https" or parts.hostname not in {"127.0.0.1", "localhost"} or \
            not cluster or not cluster.get("certificate-authority-data"):
        lab.block("The OIDC request target is not a loopback TLS API from the owned kubeconfig")
    ca = base64.b64decode(cluster["certificate-authority-data"]).decode()
    return server.rstrip("/"), ssl.create_default_context(cadata=ca)


def _api_get(server, trust, token, resource_name):
    parsed = urlsplit(server)
    conn = HTTPSConnection(parsed.hostname, parsed.port, context=trust, timeout=8)
    path = f"/api/v1/namespaces/{NS}/configmaps/{resource_name}"
    try:
        conn.request("GET", path, headers={"Authorization": "Bearer " + token,
                                           "Accept": "application/json"})
        response = conn.getresponse()
        status = response.status
        marker_matches = False
        if status == 200:
            raw = response.read(65536)
            try:
                body = json.loads(raw)
                marker_matches = body.get("metadata", {}).get("name") == resource_name and \
                    body.get("data", {}).get("marker") == SUBJECT_MARKER
            except (ValueError, json.JSONDecodeError):
                marker_matches = False
        else:
            response.close()
        return status, marker_matches
    finally:
        conn.close()


def _create_role(lab, subject_id):
    for name in (ALLOW_NAME, DENY_NAME):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": name, "labels": {"saf.example/fixture": "mfa-oidc"}},
                    "data": {"marker": SUBJECT_MARKER}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": ROLE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [ALLOW_NAME], "verbs": ["get"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": ROLE},
                "subjects": [{"kind": "User", "apiGroup": "rbac.authorization.k8s.io",
                              "name": API_USERNAME_PREFIX + subject_id}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": ROLE}})


def _identity_facts(credentials, subject_id, jwks):
    low = _jwt_observation(credentials["level1"], jwks, subject_id)
    high = _jwt_observation(credentials["level2"], jwks, subject_id)
    low_id = _id_token_observation(credentials["id_level1"], subject_id, "1")
    high_id = _id_token_observation(credentials["id_level2"], subject_id, "2")
    return low, high, low_id, high_id


def run_bridge(lab, idp, credentials, subject_id, ca_cert):
    node = lab.cluster + "-control-plane"
    metadata_status, metadata = idp.request(f"/realms/{REALM}/.well-known/openid-configuration")
    if metadata_status != 200 or metadata.get("issuer") != ISSUER or \
            metadata.get("jwks_uri") != ISSUER + "/protocol/openid-connect/certs":
        lab.block("The runner could not verify exact Keycloak realm discovery over the fixture CA")
    jwks_status, jwks = idp.request(f"/realms/{REALM}/protocol/openid-connect/certs")
    if jwks_status != 200 or not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
        lab.block("The runner could not verify the Keycloak signing-key set")
    node_jwks = _node_discovery(lab, node, ca_cert)
    low_claims, high_claims, low_id, high_id = _identity_facts(credentials, subject_id, jwks)
    predicates = {"low_access": low_claims, "high_access": high_claims,
                  "low_id": low_id, "high_id": high_id}
    (lab.evidence / "mfa-claim-predicates.json").write_text(json.dumps(predicates, indent=2) + "\n")
    if not (low_claims["well_formed"] and low_claims["issuer_matches"] and low_claims["audience_matches"] and
            low_claims["acr_level_1"] and low_claims["subject_matches_fixture"] and
            high_claims["well_formed"] and high_claims["issuer_matches"] and high_claims["audience_matches"] and
            high_claims["acr_level_2"] and high_claims["subject_matches_fixture"] and
            low_claims["signing_key_listed"] and high_claims["signing_key_listed"] and
            all(low_id.values()) and all(high_id.values())):
        lab.block("Keycloak access tokens did not carry the exact issuer/audience/subject/LoA claims")
    # Verify API-node discovery has a signing key compatible with both actual token headers.
    low_header, _ = _decode_claims(credentials["level1"])
    high_header, _ = _decode_claims(credentials["level2"])
    node_kids = {key.get("kid") for key in node_jwks.get("keys", [])}
    if low_header.get("kid") not in node_kids or high_header.get("kid") not in node_kids:
        lab.block("The API node's trusted JWKS does not contain the actual token signing keys")

    _create_role(lab, subject_id)
    previous = _api_container(lab, node)
    if not previous:
        lab.block("Could not identify the exact run-owned kube-apiserver container")
    restore_needed = True
    try:
        _configure_api(lab, node, ca_cert)
        _wait_replaced_api(lab, node, previous)
        server, api_trust = _kubeconfig_api(lab)
        low_status, low_marker = _api_get(server, api_trust, credentials["level1"], ALLOW_NAME)
        high_status, high_marker = _api_get(server, api_trust, credentials["level2"], ALLOW_NAME)
        outside_status, outside_marker = _api_get(server, api_trust, credentials["level2"], DENY_NAME)
        observed = {
            "discovery_issuer_matches": metadata.get("issuer") == ISSUER,
            "node_can_verify_discovery_and_jwks": bool(node_jwks.get("keys")),
            "low_token_is_audience_bound_level_1": low_claims["audience_matches"]
                and low_claims["acr_level_1"] and all(low_id.values()),
            "low_level_refused_by_native_api": low_status == 401,
            "high_token_is_audience_bound_level_2": high_claims["audience_matches"]
                and high_claims["acr_level_2"] and all(high_id.values()),
            "high_level_reads_only_approved_marker": high_status == 200 and high_marker,
            "high_level_outside_resource_denied": outside_status == 403 and not outside_marker,
        }
        lab.check("positive", "The owned Kubernetes API enforces Keycloak LoA and exact RBAC scope",
                  all(observed.values()), observed)
        (lab.evidence / "mfa-kubernetes-bridge.json").write_text(json.dumps({
            "issuer": ISSUER, "audience": API_AUDIENCE, "observed": observed,
            "token_claim_predicates": {
                "level1": {key: value for key, value in low_claims.items()
                           if key not in {"acr_level_1", "acr_level_2"}},
                "level2": {key: value for key, value in high_claims.items()
                           if key not in {"acr_level_1", "acr_level_2"}},
            },
            "checks": lab.checks,
        }, indent=2) + "\n")
    finally:
        if restore_needed:
            current = _api_container(lab, node)
            was_configured = _restore_api(lab, node)
            if was_configured:
                _wait_replaced_api(lab, node, current)
            else:
                ready = lab.kubectl("get", "--raw=/readyz", allow_failure=True, timeout=12)
                if ready.returncode or ready.stdout.strip() != "ok":
                    lab.block("The original API did not remain ready during fixture cleanup")
