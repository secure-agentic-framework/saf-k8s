"""Local defensive validation of bounded inference queue behavior."""
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0903-006"
NAMESPACE = "saf-0903-006"
WORKLOAD = "queue-serving-fixture"
CONFIG = "queue-serving-fixture"
NORMAL_CLIENT = "queue-client-standard"
PRIORITY_CLIENT = "queue-client-priority"
TLS_SECRET = "queue-serving-tls"
CLIENT_NORMAL_SECRET = "queue-client-standard-tls"
CLIENT_PRIORITY_SECRET = "queue-client-priority-tls"
TRUST_CONFIG = "queue-serving-trust"
SERVICE_PORT = 8443
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
SCOPE = (
    "One disposable Kind cluster and one local-only Python serving fixture (one replica). "
    "The fixture accepts a fixed set of benign job IDs, caps waiting depth at two, maps "
    "synthetic principals to service classes, orders held work by class, and uses a manually "
    "advanced fixture clock to expire one waiting item. All queue receipts and execution "
    "records come from the running server process. Dedicated client Pods use locally issued "
    "mTLS certificates with URI SAN identities at the actual ClusterIP app route; the server "
    "derives class grants from the verified certificate and ignores caller identity labels. "
    "No external endpoint, model, or real target is involved. This does not validate production "
    "identity issuance, gateway integration, real inference, "
    "multi-replica queue coordination, durable receipts, or production timeout semantics."
)

FIXTURE = json.loads((HERE / "fixtures" / "queue.json").read_text(encoding="utf-8"))


def _blocked(lab, message):
    lab.block(message)


def _labels():
    return {"saf-k8s.example/control": CONTROL_ID,
            "saf-k8s.example/fixture": "synthetic"}


def _call(lab, action, workload=WORKLOAD, identity="standard", *, present_certificate=True):
    client = PRIORITY_CLIENT if identity == "priority" else NORMAL_CLIENT
    url = f"https://{workload}.{NAMESPACE}.svc:{SERVICE_PORT}"
    certificate = ("/identity/tls.crt", "/identity/tls.key") if present_certificate else ("-", "-")
    result = lab.kubectl(
        "-n", NAMESPACE, "exec", f"pod/{client}", "--", "python", "-B", "/case/queue.py",
        "request", url, "/trust/ca.crt", *certificate,
        json.dumps(action, sort_keys=True, separators=(",", ":")),
        timeout=20,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        _blocked(lab, f"Serving fixture returned invalid JSON: {error}")


def _state(lab, workload=WORKLOAD, identity="standard"):
    return _call(lab, {"op": "state"}, workload, identity)


def _check_fixture(lab):
    expected = {
        "control_id": CONTROL_ID,
        "max_pending": 2,
        "class_priority": {"standard": 10, "priority": 20},
        "principal_classes": {
            "synthetic-standard-principal": ["standard"],
            "synthetic-priority-principal": ["priority"],
        },
        "principal_uris": {
            "synthetic-standard-principal": "spiffe://saf.example/0903-006/standard",
            "synthetic-priority-principal": "spiffe://saf.example/0903-006/priority",
        },
        "jobs": [
            {"id": "happy-001", "class": "standard", "principal": "synthetic-standard-principal", "ttl": 5},
            {"id": "wait-standard-001", "class": "standard", "principal": "synthetic-standard-principal", "ttl": 20},
            {"id": "wait-priority-001", "class": "priority", "principal": "synthetic-priority-principal", "ttl": 20},
            {"id": "denied-priority-001", "class": "priority", "principal": "synthetic-priority-principal", "ttl": 20},
            {"id": "overflow-001", "class": "standard", "principal": "synthetic-standard-principal", "ttl": 20},
            {"id": "expire-001", "class": "standard", "principal": "synthetic-standard-principal", "ttl": 2},
        ],
    }
    if FIXTURE != expected:
        _blocked(lab, "Queue fixture differs from its fixed benign contract")


def _deployment(workload=WORKLOAD, mode="enforced"):
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": workload, "namespace": NAMESPACE, "labels": _labels()},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": workload}},
                 "template": {
                     "metadata": {"labels": {"app": workload, **_labels()}},
                     "spec": {
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "runAsGroup": 65534, "fsGroup": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{
                             "name": "serving", "image": PYTHON_IMAGE,
                             "imagePullPolicy": "IfNotPresent",
                             "command": ["python", "-B", "/case/queue.py", "serve", mode],
                             "ports": [{"name": "https", "containerPort": SERVICE_PORT}],
                             "readinessProbe": {"httpGet": {"path": "/ready", "port": "https",
                                                               "scheme": "HTTPS"},
                                                "periodSeconds": 2, "timeoutSeconds": 1},
                             "securityContext": {"allowPrivilegeEscalation": False,
                                                  "readOnlyRootFilesystem": True,
                                                  "capabilities": {"drop": ["ALL"]}},
                             "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                           "limits": {"cpu": "100m", "memory": "96Mi"}},
                             "volumeMounts": [
                                 {"name": "fixture", "mountPath": "/case", "readOnly": True},
                                 {"name": "tls", "mountPath": "/identity", "readOnly": True},
                                 {"name": "trust", "mountPath": "/trust", "readOnly": True}],
                         }],
                         "volumes": [
                             {"name": "fixture", "configMap": {"name": CONFIG}},
                             {"name": "tls", "secret": {"secretName": TLS_SECRET,
                                "defaultMode": 0o440}},
                             {"name": "trust", "configMap": {"name": TRUST_CONFIG}}],
                     },
                 }},
    }


def _service(workload):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": workload, "namespace": NAMESPACE, "labels": _labels()},
            "spec": {"type": "ClusterIP", "selector": {"app": workload},
                     "ports": [{"name": "https", "port": SERVICE_PORT,
                                "targetPort": SERVICE_PORT}]}}


def _client_pod(name, secret):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE, "labels": _labels()},
            "spec": {"restartPolicy": "Always", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "fsGroup": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "client", "image": PYTHON_IMAGE,
                         "imagePullPolicy": "IfNotPresent", "command": ["sleep", "3600"],
                         "volumeMounts": [
                             {"name": "fixture", "mountPath": "/case", "readOnly": True},
                             {"name": "identity", "mountPath": "/identity", "readOnly": True},
                             {"name": "trust", "mountPath": "/trust", "readOnly": True}],
                         "securityContext": {"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                         "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                       "limits": {"cpu": "100m", "memory": "96Mi"}}}],
                     "volumes": [{"name": "fixture", "configMap": {"name": CONFIG}},
                         {"name": "identity", "secret": {"secretName": secret,
                            "defaultMode": 0o440}},
                         {"name": "trust", "configMap": {"name": TRUST_CONFIG}}]}}


def _openssl(lab, *args):
    try:
        result = subprocess.run(["openssl", *map(str, args)], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        _blocked(lab, "The case-local mTLS identity fixture could not run OpenSSL")
    if result.returncode:
        _blocked(lab, "The case-local mTLS identity fixture could not prepare its certificates")


def _certificates(lab):
    with TemporaryDirectory(prefix="saf-0903-006-mtls-", dir=lab.kubeconfig.parent) as raw:
        temp = Path(raw)
        ca, ca_key = temp / "ca.crt", temp / "ca.key"
        _openssl(lab, "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=SAF disposable queue identity CA",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash",
                 "-keyout", ca_key, "-out", ca)
        ca_key.chmod(0o600)

        server_dns = (f"{WORKLOAD}.{NAMESPACE}.svc,"
                      f"{WORKLOAD}-baseline.{NAMESPACE}.svc")
        server_ext = temp / "server.ext"
        server_ext.write_text(
            f"subjectAltName=DNS:{server_dns.replace(',', ',DNS:')}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n", encoding="utf-8")
        server_key, server_csr = temp / "server.key", temp / "server.csr"
        server_cert = temp / "server.crt"
        _openssl(lab, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                 "-subj", "/CN=SAF bounded queue fixture",
                 "-keyout", server_key, "-out", server_csr)
        _openssl(lab, "x509", "-req", "-in", server_csr, "-CA", ca, "-CAkey", ca_key,
                 "-CAcreateserial", "-days", "1", "-extfile", server_ext, "-out", server_cert)
        server_key.chmod(0o600)
        lab.kubectl("-n", NAMESPACE, "create", "secret", "tls", TLS_SECRET,
                    "--key=" + str(server_key), "--cert=" + str(server_cert), "-o", "name")

        identities = ((CLIENT_NORMAL_SECRET, "normal", "synthetic-standard-principal"),
                      (CLIENT_PRIORITY_SECRET, "priority", "synthetic-priority-principal"))
        for secret, label, principal in identities:
            uri = FIXTURE["principal_uris"][principal]
            ext = temp / f"{label}.ext"
            ext.write_text(f"subjectAltName=URI:{uri}\n"
                           "basicConstraints=critical,CA:FALSE\n"
                           "keyUsage=critical,digitalSignature,keyEncipherment\n"
                           "extendedKeyUsage=clientAuth\n"
                           "subjectKeyIdentifier=hash\n"
                           "authorityKeyIdentifier=keyid,issuer\n", encoding="utf-8")
            key, csr, cert = (temp / f"{label}.{suffix}" for suffix in ("key", "csr", "crt"))
            _openssl(lab, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                     "-subj", f"/CN=SAF {label} queue client",
                     "-keyout", key, "-out", csr)
            _openssl(lab, "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                     "-CAcreateserial", "-days", "1", "-extfile", ext, "-out", cert)
            key.chmod(0o600)
            lab.kubectl("-n", NAMESPACE, "create", "secret", "tls", secret,
                        "--key=" + str(key), "--cert=" + str(cert), "-o", "name")

        lab.kubectl("-n", NAMESPACE, "create", "configmap", TRUST_CONFIG,
                    "--from-file=ca.crt=" + str(ca), "-o", "name")


def _wait_ready(lab, workload=WORKLOAD):
    lab.kubectl("-n", NAMESPACE, "wait", f"deployment/{workload}",
                "--for=condition=Available", "--timeout=90s", timeout=100)
    pod = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-l", f"app={workload}", "-o", "json").stdout)
    items = pod.get("items", [])
    if len(items) != 1 or items[0].get("status", {}).get("phase") != "Running":
        _blocked(lab, "Expected exactly one running queue serving Pod")


def _receipt(state, job_id):
    matches = [item for item in state.get("receipts", []) if item.get("job_id") == job_id]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one receipt for {job_id}, got {len(matches)}")
    return matches[0]


def run(lab):
    _check_fixture(lab)
    source = (HERE / "fixtures" / "queue.py").read_text(encoding="utf-8")
    lab.kubectl("create", "namespace", NAMESPACE)
    config = {"apiVersion": "v1", "kind": "ConfigMap",
              "metadata": {"name": CONFIG, "namespace": NAMESPACE, "labels": _labels()},
              "immutable": True,
              "data": {"queue.json": json.dumps(FIXTURE, sort_keys=True), "queue.py": source}}
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(config))
    readback = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", CONFIG, "-o", "json").stdout)
    data = readback.get("data", {})
    if (readback.get("immutable") is not True or data.get("queue.py") != source
            or data.get("queue.json") != json.dumps(FIXTURE, sort_keys=True)):
        _blocked(lab, "Queue fixture ConfigMap readback did not match the reviewed source")
    _certificates(lab)
    baseline = WORKLOAD + "-baseline"
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(_deployment(baseline, "baseline")))
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(_service(baseline)))
    for name, secret in ((NORMAL_CLIENT, CLIENT_NORMAL_SECRET),
                         (PRIORITY_CLIENT, CLIENT_PRIORITY_SECRET)):
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                    payload=json.dumps(_client_pod(name, secret)))
    _wait_ready(lab, baseline)
    for name in (NORMAL_CLIENT, PRIORITY_CLIENT):
        lab.kubectl("-n", NAMESPACE, "wait", f"pod/{name}",
                    "--for=condition=Ready", "--timeout=90s", timeout=100)
    _call(lab, {"op": "hold_dispatch", "held": True}, baseline, "priority")
    jobs = {job["id"]: job for job in FIXTURE["jobs"]}
    names = ["wait-standard-001", "wait-priority-001", "overflow-001", "expire-001"]
    admissions = []
    for name in names:
        job = jobs[name]
        admissions.append(_call(lab, {"op": "submit", "job_id": name,
                                      "service_class": job["class"], "ttl": job["ttl"]}, baseline,
                             "priority" if job["principal"] == "synthetic-priority-principal" else "standard"))
    _call(lab, {"op": "advance_clock", "ticks": 2}, baseline, "priority")
    baseline_pending = _state(lab, baseline)
    _call(lab, {"op": "hold_dispatch", "held": False}, baseline, "priority")
    baseline_final = _state(lab, baseline)
    lab.check("red", "Unenforced queue exceeds configured depth, drains in arrival order, and dispatches the expired job",
              [item.get("status") for item in admissions] == [202] * 4
              and baseline_pending.get("pending") == names and baseline_pending.get("clock") == 2
              and baseline_final.get("executed") == names
              and _receipt(baseline_final, "expire-001").get("execution_count") == 1,
              {"pending_at_expiry": baseline_pending.get("pending"),
               "executed": baseline_final.get("executed"), "admitted": len(admissions)})
    lab.kubectl("-n", NAMESPACE, "delete", "deployment", baseline,
                "--cascade=foreground", "--wait=true", timeout=35)
    lab.kubectl("-n", NAMESPACE, "delete", "service", baseline, "--wait=true", timeout=20)

    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(_deployment()))
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(_service(WORKLOAD)))
    _wait_ready(lab)
    pod_spec = json.loads(lab.kubectl("-n", NAMESPACE, "get", "deployment", WORKLOAD, "-o", "json").stdout)
    containers = pod_spec["spec"]["template"]["spec"]["containers"]
    if len(containers) != 1 or containers[0]["image"] != PYTHON_IMAGE:
        _blocked(lab, "Serving backend image or replica contract changed")
    no_cert_state = _call(lab, {"op": "state"}, present_certificate=False)
    no_cert_submit = _call(lab, {"op": "submit", "job_id": "happy-001", "service_class": "standard",
                                 "ttl": 5}, present_certificate=False)
    no_identity_evidence = {"status": 403, "reason": "fixture_identity_not_authorized"}
    no_certificate_denied = no_cert_state == no_cert_submit == no_identity_evidence
    initial = _state(lab)
    if initial != {"event": "queue_state", "clock": 0, "executed": [], "pending": [], "receipts": [], "dispatch_held": False}:
        _blocked(lab, "Queue backend did not start in its empty deterministic state")

    # Happy path remains live: a normal authorized benign item executes once.
    happy = _call(lab, {"op": "submit", "job_id": "happy-001", "service_class": "standard",
                        "ttl": 5})
    happy_state = _state(lab)
    happy_receipt = _receipt(happy_state, "happy-001")
    happy_ok = (happy.get("status") == 200 and happy_receipt.get("status") == "executed"
                and happy_receipt.get("execution_count") == 1
                and happy_state.get("pending") == []
                and happy_state.get("executed") == ["happy-001"])
    lab.check("positive", "An authorized standard job follows the unchanged happy path and executes exactly once",
              happy_ok, {"submit": happy, "receipt": happy_receipt,
                         "executed": happy_state.get("executed"), "pending_depth": len(happy_state.get("pending", []))})

    # Red paths exercise both authorization and the configured pending-depth ceiling.
    denied = _call(lab, {"op": "submit", "job_id": "denied-priority-001", "service_class": "priority",
                         "principal": "synthetic-priority-principal", "ttl": 20})
    denied_state = _state(lab)
    denied_receipt = _receipt(denied_state, "denied-priority-001")
    lab.check("green", "A standard principal cannot select the independently authorized priority class",
              denied.get("status") == 403 and denied_receipt.get("status") == "rejected"
              and denied_receipt.get("reason") == "service_class_not_authorized"
              and denied_state.get("pending") == []
              and "denied-priority-001" not in denied_state.get("executed", []),
              {"response": denied, "receipt": denied_receipt, "pending_depth": len(denied_state.get("pending", []))})

    held = _call(lab, {"op": "hold_dispatch", "held": True}, identity="priority")
    low = _call(lab, {"op": "submit", "job_id": "wait-standard-001", "service_class": "standard",
                      "ttl": 20})
    high = _call(lab, {"op": "submit", "job_id": "wait-priority-001", "service_class": "priority",
                       "ttl": 20}, identity="priority")
    overflow = _call(lab, {"op": "submit", "job_id": "overflow-001", "service_class": "standard",
                          "ttl": 20})
    capped = _state(lab)
    try:
        low_receipt = _receipt(capped, "wait-standard-001")
        high_receipt = _receipt(capped, "wait-priority-001")
        overflow_receipt = _receipt(capped, "overflow-001")
    except ValueError as error:
        _blocked(lab, str(error))
    cap_ok = (held.get("dispatch_held") is True and low.get("status") == high.get("status") == 202
              and low_receipt.get("status") == "queued"
              and high_receipt.get("status") == "queued" and overflow.get("status") == 429
              and overflow_receipt.get("status") == "rejected"
              and overflow_receipt.get("reason") == "queue_depth_limit"
              and len(capped.get("pending", [])) == FIXTURE["max_pending"]
              and capped.get("pending") == ["wait-priority-001", "wait-standard-001"]
              and capped.get("executed") == ["happy-001"])
    lab.check("green", "At most two authorized jobs wait; the next fixed job gets a depth-limit receipt",
              cap_ok, {"hold": held, "pending": capped.get("pending"), "pending_depth": len(capped.get("pending", [])),
                       "limit": FIXTURE["max_pending"], "overflow_response": overflow,
                       "admission_statuses": [low.get("status"), high.get("status")],
                       "overflow_receipt": overflow_receipt, "executed": capped.get("executed")})

    released = _call(lab, {"op": "hold_dispatch", "held": False}, identity="priority")
    ordered = _state(lab)
    order_ok = (released.get("dispatch_held") is False
                and ordered.get("executed") == ["happy-001", "wait-priority-001", "wait-standard-001"]
                and len(ordered.get("pending", [])) == 0
                and _receipt(ordered, "wait-priority-001").get("execution_count") == 1
                and _receipt(ordered, "wait-standard-001").get("execution_count") == 1)
    lab.check("green", "Two independently authorized waiting classes drain by service-class priority",
              order_ok, {"release": released, "execution_order": ordered.get("executed"),
                         "priority_receipt": _receipt(ordered, "wait-priority-001"),
                         "standard_receipt": _receipt(ordered, "wait-standard-001"),
                         "pending_depth": len(ordered.get("pending", []))})

    _call(lab, {"op": "hold_dispatch", "held": True}, identity="priority")
    expiring = _call(lab, {"op": "submit", "job_id": "expire-001", "service_class": "standard",
                           "ttl": 2})
    before = _state(lab)
    advanced = _call(lab, {"op": "advance_clock", "ticks": 2}, identity="priority")
    expired = _state(lab)
    try:
        expiry_receipt = _receipt(expired, "expire-001")
    except ValueError as error:
        _blocked(lab, str(error))
    expiry_ok = (expiring.get("status") == 202 and len(before.get("pending", [])) == 1
                 and advanced.get("clock") == before.get("clock", 0) + 2
                 and expiry_receipt.get("status") == "expired"
                 and expiry_receipt.get("execution_count") == 0
                 and expiry_receipt.get("expired_at") == advanced.get("clock")
                 and "expire-001" not in expired.get("pending", [])
                 and "expire-001" not in expired.get("executed", []))
    lab.check("green", "Expiry removes a waiting job and records zero executions",
              expiry_ok, {"submit": expiring, "pending_before_expiry": before.get("pending"),
                          "clock_advance": advanced, "receipt": expiry_receipt,
                          "pending_after_expiry": expired.get("pending"),
                          "executed": expired.get("executed")})

    final = _state(lab)
    expected_executed = ["happy-001", "wait-priority-001", "wait-standard-001"]
    expected_statuses = {
        "happy-001": ("executed", None, 1),
        "denied-priority-001": ("rejected", "service_class_not_authorized", 0),
        "wait-standard-001": ("executed", None, 1),
        "wait-priority-001": ("executed", None, 1),
        "overflow-001": ("rejected", "queue_depth_limit", 0),
        "expire-001": ("expired", None, 0),
    }
    observed_statuses = {
        item.get("job_id"): (item.get("status"), item.get("reason"), item.get("execution_count"))
        for item in final.get("receipts", [])
    }
    expected = {"pending": [], "executed": expected_executed, "clock": 2,
                "dispatch_held": True}
    state_matches = all(final.get(key) == value for key, value in expected.items())
    receipts_match = (len(final.get("receipts", [])) == len(expected_statuses)
                      and observed_statuses == expected_statuses)
    if not state_matches or not receipts_match:
        _blocked(lab, f"Final backend state disagrees with exact fixture receipts: {final}")

    identity_authz_ok = (
        no_certificate_denied
        and happy_receipt.get("principal") == "synthetic-standard-principal"
        and denied_receipt.get("principal") == "synthetic-standard-principal"
        and low_receipt.get("principal") == "synthetic-standard-principal"
        and high_receipt.get("principal") == "synthetic-priority-principal"
        and expiry_receipt.get("principal") == "synthetic-standard-principal"
        and denied.get("status") == 403
        and denied_receipt.get("reason") == "service_class_not_authorized"
    )
    lab.check("green", "The actual TLS app route derives ordinary and priority class identity from verified URI SAN certificates, ignoring the forged request label",
              bool(identity_authz_ok), {
                  "requests_without_certificate_denied": no_certificate_denied,
                  "ordinary_certificate_receipts_match": all(
                      receipt.get("principal") == "synthetic-standard-principal"
                      for receipt in (happy_receipt, denied_receipt, low_receipt, expiry_receipt)),
                  "priority_certificate_receipt_matches": (
                      high_receipt.get("principal") == "synthetic-priority-principal"),
                  "forged_priority_label_remains_denied": (
                      denied.get("status") == 403
                      and denied_receipt.get("principal") == "synthetic-standard-principal"),
              })

    (lab.evidence / "queue-receipts.raw.json").write_text(
        json.dumps({"unenforced": baseline_final, "enforced": final}, indent=2) + "\n")
