"""Exercise safe configuration, credential lifetime, and actual authorized kubeconfig use."""
import base64
import hashlib
import json
import stat
import sys
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
    "approved synthetic exec credential plugin and actual endpoint trust checks. The adopted issuer, "
    "workstation policy, encryption and organizational offboarding require separate evidence."
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

    # Additive exec-plugin checks use the same issued token in the same owned
    # fixture. The plugin protocol response remains internal to client-go; no
    # token string is put in args, logs, results, or kubeconfig.
    exec_profile = run_exec_plugin_checks(
        lab, root, endpoint, trust, tokenfile, ITEM)

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
    exec_after_revoke = user_request(lab, exec_profile, ITEM)
    exec_revoked = (exec_after_revoke.returncode != 0 and
                    ("Unauthorized" in exec_after_revoke.stderr or "logged in" in exec_after_revoke.stderr))
    lab.check("positive", "The same approved exec profile loses access after bound-identity deletion",
              exec_revoked, {"plugin_profile_denied_after_revocation": exec_revoked})
    (lab.evidence/"kubeconfig-hygiene-observations.json").write_text(json.dumps({
        "rejected_configuration_findings": concerns, "effective_profile": secure, "lifecycle": observed,
        "approved_exec_plugin": True, "unapproved_plugin_rejected_without_execution": True,
        "exec_plugin_revoked_with_bound_identity": exec_revoked,
    }, indent=2)+"\n")


PLUGIN_SOURCE = """#!/usr/bin/env python3
import base64
import datetime
import json
import pathlib
import sys

try:
    token = pathlib.Path(sys.argv[1]).read_text().strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token-shape")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    expiration = datetime.datetime.fromtimestamp(claims["exp"], datetime.timezone.utc)
except Exception:
    raise SystemExit(1)
response = {
    "apiVersion": "client.authentication.k8s.io/v1",
    "kind": "ExecCredential",
    "status": {"token": token,
                "expirationTimestamp": expiration.isoformat().replace("+00:00", "Z")},
}
sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\\n")
"""
PLUGIN_SHA256 = "202ff365a900ba1d09f052a4efd5a42b893ddc74e15e86e4d1ff4c2a42c93e82"


def exec_config(server, trust, command, args):
    profile = config(server, trust, {"exec": {
        "apiVersion": "client.authentication.k8s.io/v1",
        "command": command,
        "args": args,
        "interactiveMode": "Never",
        "provideClusterInfo": False,
    }})
    return profile


def assess_exec(path, endpoint, trusted_ca, plugin_path, tokenpath):
    document = json.loads(path.read_text())
    cluster = document["clusters"][0]["cluster"]
    context = document["contexts"][0]["context"]
    identity = document["users"][0]["user"]
    findings = []
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        findings.append("owner-mode")
    if cluster.get("server") != endpoint or cluster.get("certificate-authority-data") != trusted_ca:
        findings.append("approved-endpoint-and-trust")
    if cluster.get("insecure-skip-tls-verify"):
        findings.append("verified-tls")
    if document.get("current-context") != CONTEXT or context.get("namespace") != NS:
        findings.append("explicit-governed-context")
    expected_exec = {
        "apiVersion": "client.authentication.k8s.io/v1",
        "command": sys.executable,
        "args": [str(plugin_path), str(tokenpath)],
        "interactiveMode": "Never",
        "provideClusterInfo": False,
    }
    if set(identity) != {"exec"} or identity.get("exec") != expected_exec:
        findings.append("approved-exec-command")
    if not plugin_path.is_file() or plugin_path.read_text() != PLUGIN_SOURCE:
        findings.append("reviewed-plugin-bytes")
    elif stat.S_IMODE(plugin_path.stat().st_mode) != 0o700:
        findings.append("owner-only-plugin-mode")
    if not tokenpath.is_file() or stat.S_IMODE(tokenpath.stat().st_mode) != 0o600:
        findings.append("owner-only-token-source")
    if not plugin_path.is_file() or hashlib.sha256(plugin_path.read_bytes()).hexdigest() != PLUGIN_SHA256:
        findings.append("reviewed-plugin-digest")
    return sorted(findings)


def run_exec_plugin_checks(lab, root, endpoint, trust, tokenpath, item):
    plugin_path = root / "fixture-approved-exec-plugin.py"
    owner_file(plugin_path, PLUGIN_SOURCE)
    plugin_path.chmod(0o700)
    plugin_profile = root / "approved-exec.kubeconfig"
    profile = exec_config(endpoint, trust, sys.executable,
                          [str(plugin_path), str(tokenpath)])
    owner_file(plugin_profile, json.dumps(profile))
    clean = assess_exec(plugin_profile, endpoint, trust, plugin_path, tokenpath)
    lab.check(
        "positive", "Reviewed owner-only exec plugin and kubeconfig pass exact command and trust checks",
        clean == [],
        {"approved_exec_profile": clean == [],
         "plugin_owner_only": stat.S_IMODE(plugin_path.stat().st_mode) == 0o700,
         "profile_owner_only": stat.S_IMODE(plugin_profile.stat().st_mode) == 0o600,
         "token_file_owner_only": stat.S_IMODE(tokenpath.stat().st_mode) == 0o600,
         "credential_value_in_profile_or_args": False},
    )

    unapproved_plugin = root / "fixture-unapproved-exec-plugin.py"
    marker = root / "unapproved-plugin-was-run"
    owner_file(unapproved_plugin, (
        "#!/usr/bin/env python3\nimport pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text('invoked')\n"
    ))
    unapproved_plugin.chmod(0o700)
    unapproved_path = root / "unapproved-exec.kubeconfig"
    unapproved = exec_config(endpoint, trust, sys.executable,
                             [str(unapproved_plugin), str(marker)])
    owner_file(unapproved_path, json.dumps(unapproved))
    unapproved_findings = assess_exec(unapproved_path, endpoint, trust,
                                      plugin_path, tokenpath)
    passive_rejection = ("approved-exec-command" in unapproved_findings
                         and not marker.exists())
    lab.check(
        "red", "Passive profile review rejects unapproved plugin bytes without executing them",
        passive_rejection,
        {"unapproved_command_rejected": "approved-exec-command" in unapproved_findings,
         "plugin_marker_absent": not marker.exists(),
         "finding_ids": unapproved_findings},
    )

    # Connect only to the fixture API. A separate valid CA cannot verify its serving chain.
    ca, ca_key = root / "unrelated-fixture-ca.pem", root / "unrelated-fixture-ca.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "1",
                "-subj", "/CN=unrelated SAF fixture CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(ca_key), "-out", str(ca), timeout=20)
    ca_key.chmod(0o600)
    wrong_trust_profile = root / "wrong-trust-exec.kubeconfig"
    wrong_trust = exec_config(endpoint, base64.b64encode(ca.read_bytes()).decode("ascii"),
                              sys.executable, [str(plugin_path), str(tokenpath)])
    owner_file(wrong_trust_profile, json.dumps(wrong_trust))
    trust_result = user_request(lab, wrong_trust_profile, item)
    trust_diagnostic = (trust_result.stdout + trust_result.stderr).lower()
    trust_rejected = (trust_result.returncode != 0 and "x509" in trust_diagnostic
                      and "certificate signed by unknown authority" in trust_diagnostic)
    lab.check(
        "red", "The owned API TLS handshake rejects the valid but unrelated trust anchor",
        trust_rejected,
        {"owned_endpoint_tls_rejected": trust_rejected,
         "api_operation_accepted": False,
         "credential_value_logged": False},
    )

    allowed = user_request(lab, plugin_profile, item)
    forbidden = user_request(lab, plugin_profile, "fixture-independent")
    actual = (allowed.returncode == 0 and allowed.stdout == "owned-approved-config"
              and forbidden.returncode != 0 and "(Forbidden)" in forbidden.stderr)
    lab.check(
        "green", "Reviewed exec plugin returns the existing scoped identity for the actual allowed API operation",
        actual,
        {"approved_operation_succeeded": allowed.returncode == 0
         and allowed.stdout == "owned-approved-config",
         "other_object_denied": forbidden.returncode != 0 and "(Forbidden)" in forbidden.stderr,
         "plugin_token_output_logged": False},
    )
    return plugin_profile
