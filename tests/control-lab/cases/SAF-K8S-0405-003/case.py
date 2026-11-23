"""Exercise safe configuration, credential lifetime, and actual authorized kubeconfig use."""
import base64
import json
import stat
import subprocess
import time

ACCOUNT = "fixture-kubeconfig-client"
REFERENCE = "fixture-kubeconfig-bound-identity"
ITEM = "fixture-controlled-item"
CONTEXT = "case-read"
NS = "saf-test"
SCOPE = (
    "Assess a synthetic kubeconfig under an explicit fixture policy. Exercise the actual "
    "configured client and restricted API authorization on the owned cluster, using a "
    "short-lived server-issued credential bound to a fixture object. Storage encryption, "
    "real credentials and plugins, and the organization's offboarding remain separate."
)


def owner_file(path, value):
    path.touch(mode=0o600, exist_ok=False)
    path.write_text(value)


def native_value(lab, field):
    return lab.kubectl("config", "view", "--minify", "--raw", "-o",
                       "jsonpath={.clusters[0].cluster." + field + "}").stdout.strip()


def issue_owned_token(lab):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--namespace", NS, "create", "token", ACCOUNT, "--duration=10m",
               "--bound-object-kind=Secret", "--bound-object-name", REFERENCE]
    result = subprocess.run(command, text=True, capture_output=True, timeout=20, env=lab.env)
    if result.returncode != 0 or len(result.stdout.strip().split(".")) != 3:
        lab.block("The scoped token binding fixture could not be issued")
    return result.stdout.strip()


def token_ttl(token):
    encoded = token.split(".")[1]
    data = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    return data["exp"] - data["iat"]


def config(server, trust, credentials):
    return {
        "apiVersion": "v1", "kind": "Config",
        "current-context": CONTEXT,
        "clusters": [{"name": "case-owned", "cluster": {
            "server": server, "certificate-authority-data": trust}}],
        "contexts": [{"name": CONTEXT, "context": {
            "cluster": "case-owned", "user": ACCOUNT, "namespace": NS}}],
        "users": [{"name": ACCOUNT, "user": credentials}],
    }


def assess(path, endpoint, trusted_ca, tokenpath):
    config = json.loads(path.read_text())
    profile = config["clusters"][0]["cluster"]
    context = config["contexts"][0]["context"]
    identity = config["users"][0]["user"]
    findings = []
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        findings.append("owner-mode")
    if profile.get("server") != endpoint or profile.get("certificate-authority-data") != trusted_ca:
        findings.append("approved-endpoint-and-trust")
    if profile.get("insecure-skip-tls-verify"):
        findings.append("verified-tls")
    if config["current-context"] != CONTEXT or context["namespace"] != NS:
        findings.append("explicit-governed-context")
    if set(identity) != {"tokenFile"} or identity.get("tokenFile") != str(tokenpath):
        findings.append("approved-credential-source")
    elif stat.S_IMODE(tokenpath.stat().st_mode) != 0o600:
        findings.append("owner-only-token-file")
    return sorted(findings)


def user_request(lab, path, name):
    return lab.command("kubectl", "--kubeconfig", str(path), "--context", CONTEXT,
                       "--request-timeout=6s", "get", "configmap", name,
                       "-o", "jsonpath={.data.marker}", allow_failure=True, timeout=10)


def run(lab):
    root = lab.kubeconfig.parent
    endpoint = native_value(lab, "server")
    trust = native_value(lab, "certificate-authority-data")
    seed = root/"unapproved.kubeconfig"
    tokenfile = root/"fixture.token"
    rejected_config = config("https://unused-synthetic.invalid", "", {"token": "PUBLIC_TEST_ONLY"})
    rejected_config["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
    rejected_config["contexts"][0]["context"]["namespace"] = "fixture-unapproved"
    owner_file(seed, json.dumps(rejected_config))
    seed.chmod(0o644)
    concerns = assess(seed, endpoint, trust, tokenfile)
    expected = sorted(["owner-mode", "approved-endpoint-and-trust", "verified-tls",
                       "explicit-governed-context", "approved-credential-source"])
    lab.check("red", "The fixture linter detects each insecure or unapproved kubeconfig field",
              concerns == expected, {"finding_ids": concerns})

    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": ITEM},
                "data": {"marker": "owned-approved-config"}},
    )
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-independent"},
                "data": {"marker": "owned-independent-config"}})
    lab.create({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": REFERENCE}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    api = "rbac.authorization.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "Role", "metadata": {"name": ACCOUNT}, "rules": [
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [ITEM], "verbs": ["get"]}]})
    lab.create({"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": ACCOUNT},
                "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NS}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT}})
    token = issue_owned_token(lab)
    elapsed = token_ttl(token)
    owner_file(tokenfile, token)
    ready = root/"approved.kubeconfig"
    owner_file(ready, json.dumps(config(endpoint, trust, {"tokenFile": str(tokenfile)})))
    clean = assess(ready, endpoint, trust, tokenfile)
    allowed = user_request(lab, ready, ITEM)
    forbidden = user_request(lab, ready, "fixture-independent")
    secure = {"assessed_profile_accepted": clean == [],
              "issuer_lifetime_bounded": 0 < elapsed <= 600,
              "correct_profile_and_request_succeeded": allowed.returncode == 0 and allowed.stdout == "owned-approved-config",
              "other_request_denied_by_actual_authorization": forbidden.returncode != 0 and "(Forbidden)" in forbidden.stderr}
    lab.check("green", "The owner-only approved profile reaches only the intended API operation",
              all(secure.values()), secure)

    lab.kubectl("delete", "secret", REFERENCE, "--wait=true")
    denied = False
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        using_old_config = user_request(lab, ready, ITEM)
        if using_old_config.returncode != 0 and (
                "Unauthorized" in using_old_config.stderr or "logged in" in using_old_config.stderr):
            denied = True
            break
        time.sleep(1)
    authorized_admin = lab.kubectl("get", "configmap", ITEM, "-o", "jsonpath={.data.marker}").stdout
    observed = {"unchanged_config_loses_issued_access": denied,
                "separate_administrator_still_reads_fixture": authorized_admin == "owned-approved-config"}
    lab.check("positive", "Removing the bound identity invalidates the credential without changing the kubeconfig",
              all(observed.values()), observed)
    (lab.evidence/"kubeconfig-hygiene-observations.json").write_text(json.dumps({
        "rejected_configuration_findings": concerns, "effective_profile": secure, "lifecycle": observed,
    }, indent=2)+"\n")
