"""Bind one synthetic reviewer approval to an immutable model digest in API audit."""
import hashlib
import importlib.util
import base64
import json
import ipaddress
from pathlib import Path
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

from lab import NODE_IMAGE
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("saf_0905_051_native_human", HERE / "native_human.py")
human = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(human)
NAMESPACE = "saf-test"
CLUSTER_SUFFIX = "-0905-051-oidc-audit"
AUDIT_FILE = "/var/log/kubernetes/audit/audit.log"
APPROVER = "saf-0905-051-approver"
REVIEWER = f"system:serviceaccount:{NAMESPACE}:{APPROVER}"
OIDC_REVIEWER = "oidc-fixture:human-probe"
REVIEWER_GROUP = "oidc-fixture:reviewers"
ARTIFACT = "synthetic-model-v1"
MODEL_BYTES = b"SAF inert synthetic model fixture v1\n"
MODEL_SHA256 = hashlib.sha256(MODEL_BYTES).hexdigest()
APPROVAL = "approved-" + base64.b32encode(bytes.fromhex(MODEL_SHA256)).decode("ascii").rstrip("=").lower()
DECISION = "approved"

SCOPE = (
    "Two disposable Kubernetes v1.36.1 clusters compare API auditing off and on for the same scoped "
    "approval patch. The existing directly authenticated ServiceAccount path is preserved. In the "
    "audit-enabled cluster, a case-owned synthetic OIDC reviewer is authenticated by the native API "
    "server and writes the same fixed approval record. A metadata-only native API audit event binds "
    "the mapped reviewer username, server time, and approval object name encoding the immutable model "
    "digest; a separate readback verifies the fixed decision and exact digest. No credential, key, "
    "token, or request/response body is included in logs or retained evidence."
)

POD_SCRIPT = r'''import json, os, pathlib, ssl, urllib.request
import hashlib
base = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"],
                          os.environ["KUBERNETES_SERVICE_PORT_HTTPS"])
root = pathlib.Path("/var/run/secrets/kubernetes.io/serviceaccount")
token = (root / "token").read_text().strip()
body = json.dumps({"data": {"reviewer": os.environ["REVIEWER"],
                            "decision": os.environ["DECISION"],
                            "model_sha256": os.environ["MODEL_SHA256"]}},
                  separators=(",", ":")).encode()
request = urllib.request.Request(
    base + "/api/v1/namespaces/saf-test/configmaps/" + os.environ["APPROVAL_NAME"],
    data=body, method="PATCH",
    headers={"Authorization": "Bearer " + token,
             "Content-Type": "application/merge-patch+json"})
context = ssl.create_default_context(cafile=str(root / "ca.crt"))
with urllib.request.urlopen(request, context=context, timeout=15) as response:
    if response.status != 200:
        raise SystemExit("unexpected API status")
    response.read()
verify = urllib.request.Request(
    base + "/api/v1/namespaces/saf-test/configmaps/" + os.environ["APPROVAL_NAME"],
    headers={"Authorization": "Bearer " + token})
with urllib.request.urlopen(verify, context=context, timeout=15) as response:
    stored = json.load(response).get("data", {})
if stored != json.loads(body)["data"]:
    raise SystemExit("approval persistence check failed")
artifact_request = urllib.request.Request(
    base + "/api/v1/namespaces/saf-test/configmaps/synthetic-model-v1",
    headers={"Authorization": "Bearer " + token})
with urllib.request.urlopen(artifact_request, context=context, timeout=15) as response:
    artifact = json.load(response)
fixture = artifact.get("data", {}).get("fixture", "").encode()
artifact_ok = (artifact.get("immutable") is True and
               artifact.get("data", {}).get("sha256") == os.environ["MODEL_SHA256"] and
               hashlib.sha256(fixture).hexdigest() == os.environ["MODEL_SHA256"])
if not artifact_ok:
    raise SystemExit("immutable artifact verification failed")
print(json.dumps({"approval_persisted": True, "immutable_artifact_verified": True}))
'''


def api(lab, cluster, kubeconfig, *args, **kwargs):
    return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context",
                       f"kind-{cluster}", "--namespace", NAMESPACE,
                       "--request-timeout=15s", *args, **kwargs)


def fixed_resources():
    return [
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": ARTIFACT, "namespace": NAMESPACE},
         "immutable": True, "data": {"sha256": MODEL_SHA256,
                                      "fixture": MODEL_BYTES.decode()}},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": APPROVAL, "namespace": NAMESPACE},
         "data": {"reviewer": "pending", "decision": "pending",
                  "model_sha256": "pending"}},
        {"apiVersion": "v1", "kind": "ServiceAccount",
         "metadata": {"name": APPROVER, "namespace": NAMESPACE},
         "automountServiceAccountToken": True},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": {"name": "saf-0905-051-review-record", "namespace": NAMESPACE},
         "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [APPROVAL], "verbs": ["patch", "get"]},
                   {"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [ARTIFACT], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": {"name": "saf-0905-051-review-record", "namespace": NAMESPACE},
         "subjects": [{"kind": "ServiceAccount", "name": APPROVER, "namespace": NAMESPACE}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                     "name": "saf-0905-051-review-record"}},
        {"apiVersion": "v1", "kind": "Pod",
         "metadata": {"name": "saf-0905-051-approval", "namespace": NAMESPACE},
         "spec": {"restartPolicy": "Never", "serviceAccountName": APPROVER,
                  "automountServiceAccountToken": True,
                  "containers": [{"name": "request", "image": (
                      "docker.io/library/python:3.13.2-alpine@sha256:"
                      "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"),
                      "imagePullPolicy": "IfNotPresent",
                      "command": ["python", "-B", "-c", POD_SCRIPT],
                      "env": [{"name": "REVIEWER", "value": REVIEWER},
                {"name": "APPROVAL_NAME", "value": APPROVAL},
                              {"name": "DECISION", "value": DECISION},
                              {"name": "MODEL_SHA256", "value": MODEL_SHA256}],
                      "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                    "limits": {"cpu": "100m", "memory": "64Mi"}}}]}}]


def apply_resources(lab, cluster, kubeconfig, objects, directory):
    """Apply inert objects from a private file so the command log has no bodies."""
    manifest = directory / "objects.json"
    manifest.write_text(json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}))
    api(lab, cluster, kubeconfig, "apply", "-f", str(manifest))


def prepare_fixture(lab, cluster, kubeconfig):
    with tempfile.TemporaryDirectory(prefix="saf-0905-051-objects-") as dirname:
        apply_resources(lab, cluster, kubeconfig, fixed_resources(), Path(dirname))
    api(lab, cluster, kubeconfig, "wait", "--for=jsonpath={.status.phase}=Succeeded",
        "pod/saf-0905-051-approval", "--timeout=90s", timeout=100)
    logs = api(lab, cluster, kubeconfig, "logs", "pod/saf-0905-051-approval").stdout.strip()
    try:
        observed = json.loads(logs)
    except json.JSONDecodeError:
        observed = {}
    return {"approval_persisted": observed.get("approval_persisted") is True,
            "immutable_artifact_verified": observed.get("immutable_artifact_verified") is True}


def baseline_state(lab):
    script = (
        "set -eu; m=/etc/kubernetes/manifests/kube-apiserver.yaml; test -r $m; "
        "if grep -q -- '--audit-' $m; then flags=present; else flags=absent; fi; "
        f"if test -e {AUDIT_FILE}; then file=present; else file=absent; fi; "
        "printf 'audit_flags=%s audit_file=%s\\n' $flags $file"
    )
    return lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c", script,
                       timeout=20).stdout.strip()


def make_kind_config(root):
    audit_dir = root / "audit"
    audit_dir.mkdir()
    policy_path = root / "audit-policy.yaml"
    policy_path.write_text((HERE / "audit-policy.yaml").read_text().replace("@APPROVAL_NAME@", APPROVAL))
    template = (HERE / "kind.yaml.in").read_text()
    path = root / "kind.yaml"
    path.write_text(template.replace("@POLICY_PATH@", json.dumps(str(policy_path)))
                    .replace("@AUDIT_DIR@", json.dumps(str(audit_dir))))
    return path, audit_dir



def expected_data(reviewer=REVIEWER):
    return {"reviewer": reviewer, "decision": DECISION, "model_sha256": MODEL_SHA256}


def selected_record(path, username=REVIEWER):
    if not path.is_file():
        return None
    with path.open() as log:
        rows = []
        for line in log:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ref = event.get("objectRef") or {}
            user = (event.get("user") or {}).get("username")
            if (ref.get("namespace"), ref.get("resource"), ref.get("name"), event.get("verb"),
                event.get("stage"), user) != (NAMESPACE, "configmaps", APPROVAL, "patch",
                                              "ResponseComplete", username):
                continue
            rows.append({**{key: event.get(key) for key in (
                         "auditID", "level", "stage", "verb", "requestReceivedTimestamp", "stageTimestamp")},
                         "objectName": ref.get("name"), "user": user,
                         "responseCode": (event.get("responseStatus") or {}).get("code")})
    return rows[0] if len(rows) == 1 else None


def valid_event(event, reviewer=REVIEWER):
    from datetime import datetime

    if not event:
        return False
    try:
        received = datetime.fromisoformat(event["requestReceivedTimestamp"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(event["stageTimestamp"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError):
        return False
    return (bool(event["auditID"]) and event["level"] == "Metadata" and event["responseCode"] == 200
            and event["objectName"] == APPROVAL and _approval_name_digest(APPROVAL) == MODEL_SHA256
            and reviewer in (REVIEWER, OIDC_REVIEWER)
            and received.tzinfo is not None and completed.tzinfo is not None and completed >= received)


def safe_event_summary(event, reviewer):
    """Return metadata predicates only; never retain identity tokens or object bodies."""
    return {
        "selected_event_found": bool(event),
        "api_audit_id_present": bool(event and event.get("auditID")),
        "response_complete_stage": bool(event and event.get("stage") == "ResponseComplete"),
        "patch_verb": bool(event and event.get("verb") == "patch"),
        "authenticated_actor_matches_expected": bool(event and event.get("user") == reviewer),
        "approval_object_matches_expected": bool(event and event.get("objectName") == APPROVAL),
        "approval_object_name_encodes_immutable_model_digest": bool(
            event and _approval_name_digest(event.get("objectName", "")) == MODEL_SHA256),
        "response_code_is_200": bool(event and event.get("responseCode") == 200),
        "server_timestamps_ordered": bool(event and _timestamps_ordered(event)),
    }


def _approval_name_digest(name):
    prefix = "approved-"
    if not isinstance(name, str) or not name.startswith(prefix):
        return None
    encoded = name[len(prefix):].upper()
    try:
        raw = base64.b32decode(encoded + "=" * ((8 - len(encoded) % 8) % 8))
    except (ValueError, TypeError):
        return None
    return raw.hex() if len(raw) == 32 else None


def _timestamps_ordered(event):
    from datetime import datetime
    try:
        received = datetime.fromisoformat(event["requestReceivedTimestamp"].replace("Z", "+00:00"))
        completed = datetime.fromisoformat(event["stageTimestamp"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError):
        return False
    return received.tzinfo is not None and completed.tzinfo is not None and completed >= received


def wait_api_replacement(lab, cluster, kubeconfig, node, previous, timeout=110):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = human.api_container(lab, node)
        if current and current != previous:
            ready = api(lab, cluster, kubeconfig, "get", "--raw=/readyz",
                        timeout=12, allow_failure=True)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return True
        time.sleep(1)
    return False


def wait_api_ready(lab, cluster, kubeconfig, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = api(lab, cluster, kubeconfig, "get", "--raw=/readyz",
                    timeout=12, allow_failure=True)
        if ready.returncode == 0 and ready.stdout.strip() == "ok":
            return True
        time.sleep(1)
    return False


def _local_api_transport(cluster, kubeconfig):
    config = yaml.safe_load(Path(kubeconfig).read_text())
    context_name = f"kind-{cluster}"
    context = next(row["context"] for row in config["contexts"] if row["name"] == context_name)
    cluster_config = next(row["cluster"] for row in config["clusters"]
                          if row["name"] == context["cluster"])
    server = cluster_config["server"]
    parsed = urllib.parse.urlparse(server)
    host = parsed.hostname
    try:
        is_loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except (TypeError, ValueError):
        is_loopback = False
    if parsed.scheme != "https" or not is_loopback or not parsed.port:
        raise ValueError("owned API endpoint is not HTTPS loopback")
    ca_data = cluster_config.get("certificate-authority-data")
    if ca_data:
        ca_pem = base64.b64decode(ca_data).decode("ascii")
    else:
        ca_pem = Path(cluster_config["certificate-authority"]).read_text()
    return server.rstrip("/"), ssl.create_default_context(cadata=ca_pem)


def write_oidc_approval(cluster, kubeconfig, token):
    """Make one TLS-verified, proxy-disabled API patch and readback without logging bodies."""
    try:
        base, tls = _local_api_transport(cluster, kubeconfig)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=tls))
        url = base + f"/api/v1/namespaces/{NAMESPACE}/configmaps/{APPROVAL}"
        body = json.dumps({"data": expected_data(OIDC_REVIEWER)}, separators=(",", ":")).encode()
        headers = {"Authorization": "Bearer " + token,
                   "Content-Type": "application/merge-patch+json"}
        patch = urllib.request.Request(url, data=body, headers=headers, method="PATCH")
        with opener.open(patch, timeout=12) as response:
            patch_ok = response.status == 200
            response.read()
        if not patch_ok:
            return False
        get = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with opener.open(get, timeout=12) as response:
            stored = json.load(response)
        return stored.get("data") == expected_data(OIDC_REVIEWER)
    except (OSError, ValueError, KeyError, StopIteration, yaml.YAMLError,
            urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        # Deliberately discard network exception text, which can include request details.
        return False


def oidc_role_binding():
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "saf-0905-051-oidc-review-record", "namespace": NAMESPACE},
            "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group",
                          "name": REVIEWER_GROUP}],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                        "name": "saf-0905-051-review-record"}}


def mint_oidc_reviewer(lab, directory):
    now = int(time.time())
    claims = {"iss": human.ISSUER, "aud": human.AUDIENCE, "sub": "human-probe",
              "iat": now - 10, "exp": now + 300, "groups": ["reviewers"],
              "fixture_class": "human-review", "session": "session-fixture-01",
              "approval_path": {"artifact_digest": "sha256:" + MODEL_SHA256,
                                "decision": DECISION}}
    return human.mint_jwt(lab, directory / "approved.key", claims)


def run(lab):
    # The normal lab runner creates saf-test and uses its ordinary, audit-disabled
    # v1.36.1 API server. Exercise the exact fixed request shape as the red probe.
    red_observation = prepare_fixture(lab, lab.cluster, lab.kubeconfig)
    red_accepts = red_observation["approval_persisted"]
    red_state = baseline_state(lab)
    red_inactive = "audit_flags=absent" in red_state and "audit_file=absent" in red_state
    lab.check("red", "The identical synthetic approval succeeds while the API server audit backend is disabled",
              red_accepts and red_inactive,
              {"approval_request_accepted": red_accepts,
               "audit_backend": "disabled" if red_inactive else "unexpected state"})

    cluster = lab.cluster + CLUSTER_SUFFIX
    with tempfile.TemporaryDirectory(prefix="saf-0905-051-") as temp:
        root = Path(temp).resolve()
        config, audit_dir = make_kind_config(root)
        kubeconfig = root / "kubeconfig"
        existing = lab.command("kind", "get", "clusters").stdout.splitlines()
        if cluster in existing:
            lab.block("Case-owned audit cluster name is already in use")
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(config), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            api(lab, cluster, kubeconfig, "create", "namespace", NAMESPACE)
            accepted = prepare_fixture(lab, cluster, kubeconfig)
            event = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                event = selected_record(audit_dir / "audit.log")
                if event:
                    (lab.evidence / "approval-audit-observation.json").write_text(
                        json.dumps(safe_event_summary(event, REVIEWER), indent=2, sort_keys=True) + "\n")
                    break
                time.sleep(0.25)

            artifact_ok = accepted["immutable_artifact_verified"]
            event_ok = valid_event(event)
            lab.check("green", "The node audit record binds the authenticated fixture actor, reviewer, decision, server time and model digest",
                      accepted["approval_persisted"] and event_ok,
                      {"approval_request_accepted": accepted["approval_persisted"],
                       "node_audit_record_matches_fixed_scope": event_ok})
            lab.check("positive", "The approved digest resolves to the immutable synthetic model ConfigMap",
                      artifact_ok,
                      {"immutable_artifact_matches_approval_digest": artifact_ok})

            oidc_temp = Path(tempfile.mkdtemp(prefix="saf-0905-051-oidc-"))
            node = f"{cluster}-control-plane"
            configured = False
            try:
                human.start_issuer(lab, node, oidc_temp, HERE / "issuer.py")
                previous = human.api_container(lab, node)
                if not previous:
                    lab.block("The owned API container is unavailable before OIDC setup")
                configured = True
                human.configure_api(lab, node, oidc_temp)
                if not wait_api_replacement(lab, cluster, kubeconfig, node, previous):
                    lab.block("The owned API did not become ready with the synthetic reviewer authenticator")

                apply_resources(lab, cluster, kubeconfig, [oidc_role_binding()], oidc_temp)
                token = mint_oidc_reviewer(lab, oidc_temp)
                request_ok = write_oidc_approval(cluster, kubeconfig, token)
                token = None
                oidc_event = None
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    oidc_event = selected_record(audit_dir / "audit.log", OIDC_REVIEWER)
                    if oidc_event:
                        break
                    time.sleep(0.25)
                oidc_ok = valid_event(oidc_event, OIDC_REVIEWER)
                summary = safe_event_summary(oidc_event, OIDC_REVIEWER)
                (lab.evidence / "oidc-reviewer-audit-observation.json").write_text(
                    json.dumps(summary, indent=2, sort_keys=True) + "\n")
                lab.check("positive", "Native OIDC reviewer identity is bound to the fixed approval and model digest in the API audit event",
                          request_ok and oidc_ok,
                          {"scoped_approval_write_and_readback_succeeded": request_ok,
                           **summary})
            finally:
                token = None
                import shutil
                try:
                    if configured:
                        active = human.api_container(lab, node)
                        human.restore_api(lab, node)
                        restored = (wait_api_replacement(lab, cluster, kubeconfig, node, active, timeout=70)
                                    if active else wait_api_ready(lab, cluster, kubeconfig))
                        if not restored:
                            lab.block("The owned API did not become ready after removing the synthetic reviewer authenticator")
                    else:
                        human.restore_api(lab, node)
                finally:
                    shutil.rmtree(oidc_temp, ignore_errors=True)

        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)
