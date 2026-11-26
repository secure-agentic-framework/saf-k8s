"""Disposable Kubernetes projected-identity and authenticated alert proof."""
import json
from pathlib import Path
import time

NS = "saf-test"
CODE = "fixture-authenticated-telemetry-code"
CERT = "fixture-authenticated-telemetry-tls"
TRUST = "fixture-authenticated-telemetry-trust"
API_ROLE = "fixture-authenticated-tokenreviewer"
MODEL_SA = "fixture-model-identity"
ALERT_SA = "fixture-alert-identity"
APPROVED_SA = "fixture-caller-approved"
UNAPPROVED_SA = "fixture-caller-unapproved"
MODEL = "fixture-auth-model"
SINK = "fixture-auth-alert"
NOAUTH = "fixture-auth-noauth"
APPROVED = "fixture-auth-approved"
UNAPPROVED = "fixture-auth-unapproved"
CALLER_AUDIENCE = "saf-fixture-model-call"
ALERT_AUDIENCE = "saf-fixture-alerts"
EXPECTED_PRINCIPAL = f"system:serviceaccount:{NS}:{APPROVED_SA}"
EXPECTED_EVENT = {
    "event": "model-marker-detected", "alert_id": "alert-auth-req-marker-001",
    "rule_id": "fixture.marker.review.auth.v1", "request_id": "auth-req-marker-001",
    "principal": EXPECTED_PRINCIPAL, "model_id": "fixture-model-auth-v1", "marker": "review",
}


def create(lab, kind, name, api="v1", **fields):
    metadata = {"name": name}
    if kind not in {"ClusterRole", "ClusterRoleBinding"}:
        metadata["namespace"] = NS
    return lab.create({"apiVersion": api, "kind": kind, "metadata": metadata, **fields})


def api_token_volume(name="api-identity"):
    return {"name": name, "projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
        {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
    ]}}


def caller_token_volume(name="caller-identity"):
    return {"name": name, "projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "audience": CALLER_AUDIENCE,
                                  "expirationSeconds": 600}},
    ]}}


def alert_token_volume():
    return {"name": "alert-identity", "projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "audience": ALERT_AUDIENCE,
                                  "expirationSeconds": 600}},
    ]}}


def pod_spec(name, image, role, service_account, *, mounts, volumes, command):
    container = {
        "name": "fixture", "image": image, "imagePullPolicy": "Never",
        "command": command,
        "volumeMounts": mounts,
        "securityContext": {"allowPrivilegeEscalation": False,
                             "capabilities": {"drop": ["ALL"]},
                             "runAsNonRoot": True, "runAsUser": 65534,
                             "seccompProfile": {"type": "RuntimeDefault"}},
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "150m", "memory": "96Mi"}},
    }
    if role in {"model", "sink"}:
        container["ports"] = [{"name": "https", "containerPort": 8443}]
        container["readinessProbe"] = {"httpGet": {"scheme": "HTTPS", "path": "/health",
                                                    "port": 8443}, "periodSeconds": 1,
                                  "failureThreshold": 60}
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NS, "labels": {"app": name}},
            "spec": {"restartPolicy": "Always" if role in {"model", "sink"} else "Never",
                     "serviceAccountName": service_account,
                     "automountServiceAccountToken": False,
                     "containers": [container], "volumes": volumes}}


def service(lab, name):
    create(lab, "Service", name, spec={"selector": {"app": name},
           "ports": [{"name": "https", "port": 8443, "targetPort": 8443}]})


def make_server(lab, image, name, role, account, code_mount, tls_mount,
                api_mount, trust_mount, extra_volumes=(), extra_mounts=()):
    mounts = [code_mount, tls_mount, api_mount, trust_mount, *extra_mounts]
    volumes = [{"name": "fixture-code", "configMap": {"name": CODE}},
               {"name": "tls", "secret": {"secretName": CERT}}, api_token_volume(),
               {"name": "trust", "configMap": {"name": TRUST}}, *extra_volumes]
    manifest = pod_spec(name, image, role, account, mounts=mounts, volumes=volumes,
                        command=["python", "/fixture/identity_fixture.py", "serve", role])
    lab.create(manifest)
    service(lab, name)


def make_caller(lab, image, name, account=None, *, receiver_comparators=False):
    mounts = [{"name": "fixture-code", "mountPath": "/fixture", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "fixture-code", "configMap": {"name": CODE}},
               {"name": "trust", "configMap": {"name": TRUST}}]
    if account:
        mounts.append({"name": "caller-identity", "mountPath": "/caller", "readOnly": True})
        volumes.append(caller_token_volume())
    if receiver_comparators:
        mounts.append({"name": "alert-identity", "mountPath": "/alert-token", "readOnly": True})
        volumes.append(alert_token_volume())
    lab.create(pod_spec(name, image, "client", account or "default", mounts=mounts,
                        volumes=volumes, command=["sleep", "3600"]))


def tokenreview_rbac(lab):
    create(lab, "ClusterRole", API_ROLE, "rbac.authorization.k8s.io/v1", rules=[{
        "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]
    }])
    for suffix, account in (("model", MODEL_SA), ("sink", ALERT_SA)):
        create(lab, "ClusterRoleBinding", f"{API_ROLE}-{suffix}",
               "rbac.authorization.k8s.io/v1",
               roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                        "name": API_ROLE},
               subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def start(lab, image, fixture_path):
    for account in (MODEL_SA, ALERT_SA, APPROVED_SA, UNAPPROVED_SA):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    tokenreview_rbac(lab)

    cert = lab.kubeconfig.parent / "fixture-auth-telemetry.crt"
    key = lab.kubeconfig.parent / "fixture-auth-telemetry.key"
    try:
        lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                    "-subj", "/CN=fixture-auth-model.saf-test.svc",
                    "-addext", "subjectAltName=DNS:fixture-auth-model.saf-test.svc,DNS:fixture-auth-alert.saf-test.svc",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
                    "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                    "-keyout", str(key), "-out", str(cert), timeout=20)
        lab.kubectl("create", "secret", "tls", CERT, "--key=" + str(key), "--cert=" + str(cert),
                    "-n", NS, "-o", "name")
        create(lab, "ConfigMap", TRUST, immutable=True, data={"ca.crt": cert.read_text()})
    finally:
        cert.unlink(missing_ok=True)
        key.unlink(missing_ok=True)
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"identity_fixture.py": fixture_path.read_text(encoding="utf-8")})
    code_mount = {"name": "fixture-code", "mountPath": "/fixture", "readOnly": True}
    tls_mount = {"name": "tls", "mountPath": "/certificate", "readOnly": True}
    api_mount = {"name": "api-identity", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                 "readOnly": True}
    trust_mount = {"name": "trust", "mountPath": "/trust", "readOnly": True}
    make_server(lab, image, MODEL, "model", MODEL_SA, code_mount, tls_mount, api_mount,
                trust_mount, extra_volumes=(alert_token_volume(),), extra_mounts=(
                    {"name": "alert-identity", "mountPath": "/alert-token", "readOnly": True},))
    make_server(lab, image, SINK, "sink", ALERT_SA, code_mount, tls_mount, api_mount, trust_mount)
    make_caller(lab, image, NOAUTH)
    make_caller(lab, image, APPROVED, APPROVED_SA, receiver_comparators=True)
    make_caller(lab, image, UNAPPROVED, UNAPPROVED_SA)
    for name in (MODEL, SINK, NOAUTH, APPROVED, UNAPPROVED):
        lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "-n", NS,
                    "--timeout=90s", timeout=100)
    for _ in range(12):
        probe = lab.kubectl("exec", "pod/" + APPROVED, "--", "python",
                            "/fixture/identity_fixture.py", "ready", timeout=12)
        if probe.stdout.strip() == "ready":
            break
        time.sleep(1)
    else:
        lab.block("The authenticated model and receiver Service routes are not reachable")


def call_model(lab, pod_name, mode):
    result = lab.kubectl("exec", "pod/" + pod_name, "-n", NS, "--", "python",
                         "/fixture/identity_fixture.py", "probe-model", mode, timeout=15)
    return json.loads(result.stdout.strip().splitlines()[-1])


def call_sink_direct(lab, mode):
    result = lab.kubectl("exec", "pod/" + APPROVED, "-n", NS, "--", "python",
                         "/fixture/identity_fixture.py", "probe-sink", mode, timeout=15)
    return json.loads(result.stdout.strip().splitlines()[-1])


def alert_records(lab):
    raw = lab.kubectl("logs", "pod/" + SINK, "-n", NS).stdout
    return [json.loads(line) for line in raw.splitlines() if line.strip().startswith("{")]


def run(lab, image):
    fixture_path = Path(__file__).with_name("identity_fixture.py")
    start(lab, image, fixture_path)
    noauth = call_model(lab, NOAUTH, "selected")
    unapproved = call_model(lab, UNAPPROVED, "selected")
    before = alert_records(lab)
    approved = call_model(lab, APPROVED, "selected")
    emitted = alert_records(lab)
    source_auth = call_sink_direct(lab, "wrong-audience")
    wrong_source = call_sink_direct(lab, "wrong-source")
    routine = call_model(lab, APPROVED, "normal")
    after = alert_records(lab)

    caller_identity_ok = (noauth.get("status") == 401 and unapproved.get("status") == 403
                          and before == [] and approved == {"status": 200,
                          "body": {"status": "ok", "model_id": "fixture-model-auth-v1"}}
                          and emitted == [EXPECTED_EVENT]
                          and emitted[0].get("principal") == EXPECTED_PRINCIPAL
                          and emitted[0].get("principal") != "fixture:claimed:forged")
    lab.check("green", "Projected caller identity, not its request claim, governs the alert principal",
              caller_identity_ok, {"missing_identity_denied": noauth.get("status") == 401,
                                   "valid_but_unapproved_identity_denied": unapproved.get("status") == 403,
                                   "denials_emit_no_alert": before == [],
                                   "approved_identity_alerts": emitted == [EXPECTED_EVENT],
                                   "alert_principal_is_verified_service_account": bool(emitted)
                                       and emitted[0].get("principal") == EXPECTED_PRINCIPAL,
                                   "forged_request_principal_not_used": bool(emitted)
                                       and emitted[0].get("principal") != "fixture:claimed:forged"})

    receiver_ok = (source_auth.get("status") == 401 and wrong_source.get("status") == 403 and
                   routine == {"status": 200, "body": {"status": "ok", "model_id": "fixture-model-auth-v1"}}
                   and after == [EXPECTED_EVENT])
    lab.check("positive", "Receiver accepts only the authorized source identity and keeps ordinary traffic quiet",
              receiver_ok, {"wrong_audience_source_denied": source_auth.get("status") == 401,
                            "valid_unapproved_source_denied": wrong_source.get("status") == 403,
                            "routine_request_succeeds": routine.get("status") == 200,
                            "exactly_one_authenticated_alert_after_comparators": after == [EXPECTED_EVENT],
                            "alert_has_no_feature_or_claimed_principal_fields": bool(after)
                                and "features" not in after[0]
                                and "claimed_principal" not in after[0],
                            "projected_tokens_excluded_from_observations": True})

    (lab.evidence / "authenticated-telemetry-observation.json").write_text(json.dumps({
        "scope": "case-owned projected SA identity and TokenReview; synthetic requests and receiver only",
        "checks": {"caller_identity": caller_identity_ok, "receiver_identity": receiver_ok},
        "event": EXPECTED_EVENT,
        "limits": ["not a deployed IdP trust validation", "not external disclosure monitoring",
                   "not alert durability, loss/latency objectives, or human review acknowledgment"],
    }, indent=2, sort_keys=True) + "\n")
