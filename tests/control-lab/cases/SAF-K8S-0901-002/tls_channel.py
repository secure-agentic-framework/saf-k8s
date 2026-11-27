"""Bounded TLS-only worker channel comparison for 0901-002."""
import json
import re
import hashlib
from pathlib import Path
import tempfile
import time


NAMESPACE = "saf-0901-002"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
CODE = "aggregation-tls-code"
CA_CONFIG = "aggregation-tls-ca"
PRIMARY_SECRET = "aggregation-tls-primary"
ALTERNATE_SECRET = "aggregation-tls-alternate"
PRIMARY_SERVICE = "aggregation-tls"
ALTERNATE_SERVICE = "aggregation-alternate"
SERVER_POD = "aggregation-tls-server"
WORKER_POD = "aggregation-tls-worker"
HOST = f"{PRIMARY_SERVICE}.{NAMESPACE}.svc.cluster.local"
ALTERNATE_HOST = f"{ALTERNATE_SERVICE}.{NAMESPACE}.svc.cluster.local"
PORT = 8443
LABEL = "saf-k8s.example/0901-002-tls-role"


def _kubectl(lab, *args, **kwargs):
    return lab.kubectl(*args, timeout=kwargs.pop("timeout", 35), **kwargs)


def _apply(lab, obj):
    _kubectl(lab, "apply", "-n", NAMESPACE, "-f", "-", payload=json.dumps(obj))


def _make_leaf(lab, work, label, dns_name):
    key = work / f"{label}.key"
    csr = work / f"{label}.csr"
    cert = work / f"{label}.crt"
    ext = work / f"{label}.ext"
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n"
        f"subjectAltName=DNS:{dns_name}\n",
        encoding="ascii",
    )
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={dns_name}", "-keyout", str(key), "-out", str(csr), timeout=30)
    key.chmod(0o600)
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(work / "ca.crt"),
                "-CAkey", str(work / "ca.key"), "-CAcreateserial", "-days", "1", "-sha256",
                "-extfile", str(ext), "-out", str(cert), timeout=30)
    return cert, key


def _tls_material(lab):
    """Create short-lived fixture-only keys; never retain private material in evidence."""
    temporary = tempfile.TemporaryDirectory(prefix="saf-0901-002-tls-")
    work = Path(temporary.name)
    ca_key, ca_cert = work / "ca.key", work / "ca.crt"
    try:
        lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=SAF-0901-002 synthetic channel CA",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-addext", "subjectKeyIdentifier=hash",
                    "-keyout", str(ca_key), "-out", str(ca_cert), timeout=30)
        ca_key.chmod(0o600)
        primary = _make_leaf(lab, work, "primary", HOST)
        alternate = _make_leaf(lab, work, "alternate", ALTERNATE_HOST)

        def validate_leaf(certificate, expected_name):
            trusted = lab.command("openssl", "verify", "-x509_strict", "-CAfile", str(ca_cert),
                                  str(certificate), timeout=15).returncode == 0
            description = lab.command("openssl", "x509", "-in", str(certificate),
                                      "-noout", "-text", timeout=15).stdout
            names = re.findall(r"\bDNS:([A-Za-z0-9.-]+)", description)
            return trusted and names == [expected_name]

        primary_ok = validate_leaf(primary[0], HOST)
        alternate_ok = validate_leaf(alternate[0], ALTERNATE_HOST)
        wrong_name_rejected = alternate_ok and HOST != ALTERNATE_HOST
        if not (primary_ok and alternate_ok and wrong_name_rejected):
            lab.block("The fixture CA or expected primary/alternate certificate name checks failed")
        return temporary, work, primary, alternate, {
            "primary_dns_name": HOST,
            "alternate_dns_name": ALTERNATE_HOST,
            "primary_certificate_sha256": hashlib.sha256(primary[0].read_bytes()).hexdigest(),
            "alternate_certificate_sha256": hashlib.sha256(alternate[0].read_bytes()).hexdigest(),
            "primary_certificate_trusted_for_service_name": primary_ok,
            "alternate_certificate_trusted_for_alternate_name": alternate_ok,
            "trusted_alternate_certificate_omits_primary_dns": wrong_name_rejected,
        }
    except BaseException:
        temporary.cleanup()
        raise


def _create_secret(lab, name, pair):
    _kubectl(lab, "create", "secret", "generic", name,
             f"--from-file=tls.crt={pair[0]}", f"--from-file=tls.key={pair[1]}",
             "-n", NAMESPACE)


def _deploy_code(lab, case_dir):
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": CODE, "namespace": NAMESPACE},
                 "data": {"tls_aggregator.py": (case_dir / "fixtures" / "tls_aggregator.py").read_text(encoding="utf-8"),
                          "tls_client.py": (case_dir / "fixtures" / "tls_client.py").read_text(encoding="utf-8")}})


def _pod(name, role, secret=None):
    if role == "server":
        command = ["python3", "/case/tls_aggregator.py"]
        service_account = "aggregation"
        volumes = [
            {"name": "code", "configMap": {"name": CODE}},
            {"name": "core", "configMap": {"name": "aggregator-code"}},
            {"name": "tls", "secret": {"secretName": secret, "defaultMode": 288}},
        ]
        mounts = [
            {"name": "code", "mountPath": "/case", "readOnly": True},
            {"name": "core", "mountPath": "/core", "readOnly": True},
            {"name": "tls", "mountPath": "/tls", "readOnly": True},
        ]
        env = [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
               {"name": "ENFORCEMENT_MODE", "value": "enforce"},
               {"name": "TLS_CERT_PATH", "value": "/tls/tls.crt"},
               {"name": "TLS_KEY_PATH", "value": "/tls/tls.key"}]
        ports = [{"name": "https", "containerPort": PORT}]
    else:
        command = ["python3", "-c", "import time; time.sleep(3600)"]
        service_account = "worker-a"
        volumes = [
            {"name": "code", "configMap": {"name": CODE}},
            {"name": "identity", "projected": {"sources": [
                {"serviceAccountToken": {"audience": "saf-fixture-0901-002",
                                          "expirationSeconds": 600, "path": "token"}}
            ]}},
            {"name": "ca", "configMap": {"name": CA_CONFIG}},
        ]
        mounts = [
            {"name": "code", "mountPath": "/case", "readOnly": True},
            {"name": "identity", "mountPath": "/run/fixture-identity", "readOnly": True},
            {"name": "ca", "mountPath": "/ca", "readOnly": True},
        ]
        env = [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}]
        ports = []
    pod_security = {"runAsNonRoot": True, "runAsUser": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"}}
    if role == "server":
        pod_security["fsGroup"] = 65532
    container = {
        "name": "fixture", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": command, "env": env, "ports": ports, "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
    }
    if role == "server":
        container["readinessProbe"] = {
            "tcpSocket": {"port": "https"}, "periodSeconds": 1, "timeoutSeconds": 1,
        }
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE,
                         "labels": {LABEL: role}},
            "spec": {"restartPolicy": "Always", "serviceAccountName": service_account,
                     "automountServiceAccountToken": role == "server",
                     "terminationGracePeriodSeconds": 1,
                     "securityContext": pod_security,
                     "containers": [container], "volumes": volumes}}


def _service(name):
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "spec": {"type": "ClusterIP", "selector": {LABEL: "server"},
                     "ports": [{"name": "https", "protocol": "TCP",
                                "port": PORT, "targetPort": PORT}]}}


def _wait_ready(lab, name, timeout=90):
    _kubectl(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{name}",
             f"--timeout={timeout}s", timeout=timeout + 10)
    return json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)


def _wait_endpoints(lab, service, pod_ip, timeout=30):
    deadline = time.monotonic() + timeout
    last = {"items": []}
    while time.monotonic() < deadline:
        last = json.loads(_kubectl(lab, "-n", NAMESPACE, "get", "endpointslices", "-l",
                                   f"kubernetes.io/service-name={service}", "-o", "json").stdout)
        addresses = [address for item in last.get("items", [])
                     for endpoint in item.get("endpoints", [])
                     if endpoint.get("conditions", {}).get("ready")
                     for address in endpoint.get("addresses", [])]
        if addresses == [pod_ip]:
            return last
        time.sleep(0.25)
    return last


def _slice_has_exact_pod(document, pod):
    expected_ip = pod.get("status", {}).get("podIP")
    expected_uid = pod.get("metadata", {}).get("uid")
    endpoints = [endpoint for item in document.get("items", [])
                 for endpoint in item.get("endpoints", [])
                 if endpoint.get("conditions", {}).get("ready")]
    return (len(endpoints) == 1 and endpoints[0].get("addresses") == [expected_ip]
            and endpoints[0].get("targetRef", {}).get("uid") == expected_uid)


def _exec_json(lab, operation):
    result = _kubectl(lab, "-n", NAMESPACE, "exec", f"pod/{WORKER_POD}", "--",
                      "python3", "/case/tls_client.py", operation,
                      timeout=28 if operation == "ready" else 12, allow_failure=True)
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        lab.block(f"TLS fixture client returned no bounded JSON result for {operation}")


def _start_server(lab, secret, *, replace=False):
    if replace:
        _kubectl(lab, "-n", NAMESPACE, "delete", "pod", SERVER_POD,
                 "--wait=true", timeout=40)
    _apply(lab, _pod(SERVER_POD, "server", secret))
    pod = _wait_ready(lab, SERVER_POD)
    return pod, _wait_endpoints(lab, PRIMARY_SERVICE, pod.get("status", {}).get("podIP"))


def run_tls_channel(lab, case_dir):
    temporary, work, primary, alternate, certificate_checks = _tls_material(lab)
    try:
        _deploy_code(lab, case_dir)
        _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                     "metadata": {"name": CA_CONFIG, "namespace": NAMESPACE},
                     "data": {"ca.crt": (work / "ca.crt").read_text(encoding="ascii")}})
        _create_secret(lab, PRIMARY_SECRET, primary)
        _create_secret(lab, ALTERNATE_SECRET, alternate)

        _apply(lab, _service(PRIMARY_SERVICE))
        _apply(lab, _service(ALTERNATE_SERVICE))
        _apply(lab, _pod(WORKER_POD, "worker"))
        _wait_ready(lab, WORKER_POD)
        primary_pod, primary_slice = _start_server(lab, PRIMARY_SECRET)
        primary_ready = _exec_json(lab, "ready")
        good = _exec_json(lab, "trusted-submit")
        primary_state = primary_pod.get("status", {}).get("phase") == "Running"
        expected_request = {
            "request_id": "synthetic-tls-channel-01", "worker_id": "worker-a",
            "round_id": "round-7", "schema_version": "v1", "vector": [0.01, -0.02, 0.03],
        }
        event_log = _kubectl(lab, "-n", NAMESPACE, "logs", f"pod/{SERVER_POD}").stdout
        events = [json.loads(line) for line in event_log.splitlines() if line.strip()]
        primary_event = (len(events) == 1 and events[0].get("request") == expected_request
                         and events[0].get("authenticated_identity") == "worker-a"
                         and events[0].get("outcome") == {"status": "accepted"})
        primary_observed = {
            "certificate_preflight": certificate_checks,
            "service_name": HOST,
            "pod_uid": primary_pod.get("metadata", {}).get("uid"),
            "endpoint_slice": primary_slice,
            "server_ready_over_verified_tls": primary_ready,
            "cleartext_probe_and_trusted_tls_request": good,
            "expected_fixed_request": expected_request,
            "only_event_is_tokenreviewed_worker_contribution": primary_event,
            "server_log_contains_only_fixed_synthetic_request": events,
        }
        evidence = getattr(lab, "evidence")
        (evidence / "worker-channel-tls-primary.raw.json").write_text(
            json.dumps(primary_observed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        lab.check("positive", "One fixed worker contribution uses verified TLS and the TLS listener rejects cleartext",
                  primary_state and _slice_has_exact_pod(primary_slice, primary_pod)
                  and certificate_checks["primary_certificate_trusted_for_service_name"]
                  and primary_ready.get("tls_ready") is True
                  and good.get("plaintext_listener_rejected") is True
                  and good.get("count_before_tls_submit") == 0
                  and good.get("http_status") == 200
                  and good.get("response") == {"status": "accepted"}
                  and good.get("tls_protocol") in ("TLSv1.2", "TLSv1.3")
                  and bool(good.get("cipher"))
                  and good.get("server_status") == {"received_count": 1, "accepted_count": 1,
                      "rejected_count": 0, "rejected_by_reason": {"schema": 0, "assignment": 0}}
                  and good.get("aggregate") == {"accepted_count": 1, "mean": [0.01, -0.02, 0.03]}
                  and primary_event,
                  {"certificate_name_and_trust_preflight": {
                       key: value for key, value in certificate_checks.items()
                       if not key.endswith("_sha256")},
                   "service_endpoint_is_exact_ready_pod": _slice_has_exact_pod(primary_slice, primary_pod),
                   "server_ready_over_verified_tls": primary_ready.get("tls_ready") is True,
                   "plaintext_listener_rejected": good.get("plaintext_listener_rejected") is True,
                   "tls_protocol": good.get("tls_protocol"), "cipher": good.get("cipher"),
                   "one_fixed_tokenreviewed_contribution": primary_event,
                   "independent_tls_status_and_aggregate": {
                       "status": good.get("server_status"), "aggregate": good.get("aggregate")}})

        alternate_pod, alternate_slice = _start_server(lab, ALTERNATE_SECRET, replace=True)
        alternate_name_slice = _wait_endpoints(
            lab, ALTERNATE_SERVICE, alternate_pod.get("status", {}).get("podIP"))
        wrong_name = _exec_json(lab, "wrong-primary-name")
        alternate_valid = _exec_json(lab, "read-alternate-name")
        alternate_observed = {
            "alternate_service_name": ALTERNATE_HOST,
            "pod_uid": alternate_pod.get("metadata", {}).get("uid"),
            "primary_service_endpoint_slice": alternate_slice,
            "alternate_service_endpoint_slice": alternate_name_slice,
            "wrong_primary_name_result": wrong_name,
            "verified_alternate_name_status": alternate_valid,
            "expected_no_contributions": {"received_count": 0, "accepted_count": 0,
                "rejected_count": 0, "rejected_by_reason": {"schema": 0, "assignment": 0}},
        }
        (evidence / "worker-channel-tls-alternate-name.raw.json").write_text(
            json.dumps(alternate_observed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        expected_empty = {"received_count": 0, "accepted_count": 0,
                          "rejected_count": 0, "rejected_by_reason": {"schema": 0, "assignment": 0}}
        lab.check("red", "A CA-trusted alternate-name certificate fails primary Service DNS verification before contribution",
                  certificate_checks["alternate_certificate_trusted_for_alternate_name"]
                  and certificate_checks["trusted_alternate_certificate_omits_primary_dns"]
                  and _slice_has_exact_pod(alternate_slice, alternate_pod)
                  and _slice_has_exact_pod(alternate_name_slice, alternate_pod)
                  and wrong_name.get("hostname_verification_failed") is True
                  and wrong_name.get("contribution_request_sent") is False
                  and alternate_valid.get("verified_alternate_name") is True
                  and alternate_valid.get("tls_protocol") in ("TLSv1.2", "TLSv1.3")
                  and alternate_valid.get("status") == expected_empty
                  and alternate_valid.get("aggregate") == {"accepted_count": 0, "mean": []},
                  {"certificate_name_and_trust_preflight": {
                       key: value for key, value in certificate_checks.items()
                       if not key.endswith("_sha256")},
                   "both_service_aliases_select_the_exact_ready_pod":
                       _slice_has_exact_pod(alternate_slice, alternate_pod)
                       and _slice_has_exact_pod(alternate_name_slice, alternate_pod),
                   "primary_name_rejected": wrong_name,
                   "trusted_alternate_name_and_no_contribution": alternate_valid})
    finally:
        temporary.cleanup()
