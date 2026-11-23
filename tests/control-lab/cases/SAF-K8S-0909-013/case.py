"""Live Kind exercise for approved repository admission before RAG ingestion."""
import base64
import hashlib
import importlib.util
import json
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"  # runner-managed namespace
PREFIX = "saf-source-allowlist"
REGISTRY = PREFIX + "-registry"
CODE = PREFIX + "-code"
TRUST = PREFIX + "-trust"
TLS = PREFIX + "-tls"
TOKENS = PREFIX + "-credentials"
UNAPPROVED_REPO = PREFIX + "-unregistered"
APPROVED_REPO = PREFIX + "-approved"
CONSUMER_A = PREFIX + "-consumer-a"
CONSUMER_B = PREFIX + "-consumer-b"
INGESTER = PREFIX + "-ingester"
PVC_A = PREFIX + "-consumer-a-data"
PVC_B = PREFIX + "-consumer-b-data"
SOURCE_PATH = "/fixed/field-notes.txt"
UNAPPROVED_ID = "repo:synthetic:meadow-notes:17"
APPROVED_ID = "repo:synthetic:cedar-notes:42"
UNAPPROVED_BYTES = b"The meadow notebook records a quiet afternoon beside the stone bridge.\n"
APPROVED_BYTES = b"The cedar notebook records a calm morning beside the garden gate.\n"

SCOPE = (
    "In runner-managed namespace saf-test, two owned HTTPS repository services expose fixed "
    "benign bytes and two distinct PVC-backed consumers persist received bytes. An immutable "
    "registry binds one exact synthetic repository ID to the approved service endpoint and uses a separately mounted "
    "read credential. The red check shows an ordinary unregistered ID can be fetched and "
    "written to both consumers with the gate disabled. The green check enables admission and "
    "requires rejection before any source fetch or either downstream write. The positive check "
    "requires an approved ID to fetch and persist the expected exact bytes at both consumers. "
    "All names, paths, endpoints, and content are fixed local fixtures; this is not production "
    "repository identity, network isolation, or general RAG security evidence."
)


def load_runtime(lab):
    source = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_source_runtime", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def _identity(lab):
    directory = lab.kubeconfig.parent
    cert, key = directory/"repositories.crt", directory/"repositories.key"
    names = (APPROVED_REPO, UNAPPROVED_REPO, CONSUMER_A, CONSUMER_B)
    alt = ",".join(f"DNS:{name}.{NS}.svc" for name in names)
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={APPROVED_REPO}.{NS}.svc", "-addext", "subjectAltName="+alt,
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
                "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", TLS, "--cert="+str(cert), "--key="+str(key), "-o", "name")
    _create(lab, "ConfigMap", TRUST, immutable=True, data={"ca.crt": cert.read_text()})
    paths = {name: directory/("repo-"+name) for name in ("approved", "unregistered")}
    for path in paths.values():
        path.write_text(secrets.token_urlsafe(24))
        path.chmod(0o600)
    lab.kubectl("create", "secret", "generic", TOKENS,
                *(f"--from-file={name}={path}" for name,path in paths.items()), "-o", "name")
    for path in paths.values():
        path.unlink()


def _create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind,
                        "metadata": {"name": name, "namespace": NS}, **fields})


def _wait_ready(lab, name):
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=100s", timeout=110)


def _service(lab, name, port):
    _create(lab, "Service", name, spec={
        "selector": {"app": name},
        "ports": [{"name": "http", "port": port, "targetPort": port}],
    })


def _pod(lab, image, name, role, command, *, pvc=None, readonly=False, token=False):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}}]
    if role == "ingester":
        mounts.append({"name": "registry", "mountPath": "/registry", "readOnly": True})
        volumes.append({"name": "registry", "configMap": {"name": REGISTRY}})
    if role == "ingester":
        mounts.extend([{"name":"trust","mountPath":"/trust","readOnly":True},
                       {"name":"tokens","mountPath":"/tokens","readOnly":True}])
        volumes.extend([{"name":"trust","configMap":{"name":TRUST}},
                        {"name":"tokens","secret":{"secretName":TOKENS,"defaultMode":0o440}}])
    else:
        mounts.append({"name":"tls","mountPath":"/tls","readOnly":True})
        volumes.append({"name":"tls","secret":{"secretName":TLS,"defaultMode":0o440}})
    if role == "repository":
        credential = "approved" if name == APPROVED_REPO else "unregistered"
        volumes.append({"name":"tokens","secret":{"secretName":TOKENS,"defaultMode":0o440,
                        "items":[{"key":credential,"path":"repository"}]}})
        mounts.append({"name":"tokens","mountPath":"/tokens","readOnly":True})
    if pvc:
        mounts.append({"name": "data", "mountPath": "/data", "readOnly": readonly})
        volumes.append({"name": "data", "persistentVolumeClaim":
                        {"claimName": pvc, "readOnly": readonly}})
    port = 8080
    if role in ("repository", "consumer"):
        command = ["python", "/fixture/source_fixture.py", "serve", role]
    unit = {"name": "fixture", "image": image, "imagePullPolicy": "Never",
            "command": command,
            "securityContext": {"allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": mounts}
    if role == "repository":
        unit["env"] = [{"name": "REPOSITORY_ID", "value": name},
                       {"name": "REPOSITORY_CONTENT_B64", "value": base64.b64encode(
                           APPROVED_BYTES if name == APPROVED_REPO else UNAPPROVED_BYTES
                       ).decode("ascii")}]
    elif role == "consumer":
        unit["env"] = [{"name": "DATA_FILE", "value": "/data/records.jsonl"}]
    if role in ("repository", "consumer"):
        unit["ports"] = [{"containerPort": port}]
        unit["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 2}
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": NS, "labels": {"app": name}},
           "spec": {"restartPolicy": "Never", "automountServiceAccountToken": token,
                    "serviceAccountName": name, "securityContext":
                    {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                     "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": volumes}}
    lab.create(pod)
    if role in ("repository", "consumer"):
        _service(lab, name, port)


def _http(lab, caller, target, method, path, body=None, headers=None):
    result = lab.kubectl("-n", NS, "exec", f"pod/{caller}", "--",
                         "python", "/fixture/source_fixture.py", "request", method,
                         f"https://{target}.{NS}.svc:8080{path}",
                         base64.b64encode(body).decode("ascii") if body is not None else "-",
                         json.dumps(headers or {}, sort_keys=True), timeout=20)
    response = json.loads(result.stdout)
    if path in ("/stats", "/state") and response["status"] == 200:
        return json.loads(base64.b64decode(response["body_b64"], validate=True))
    return response


def _ingest(lab, mode, source_id):
    result = lab.kubectl("-n", NS, "exec", f"pod/{INGESTER}", "--",
                         "python", "/fixture/source_fixture.py", "ingest", mode, source_id,
                         timeout=25)
    return json.loads(result.stdout.strip())


def _publish(lab, image):
    _identity(lab)
    _create(lab, "ConfigMap", CODE, immutable=True,
            data={"source_fixture.py": (HERE / "source_fixture.py").read_text()})
    registry = {
        "schema": 1,
        "repositories": {
            APPROVED_ID: {"endpoint": f"https://{APPROVED_REPO}.{NS}.svc:8080{SOURCE_PATH}",
                          "path": SOURCE_PATH,
                          "sha256": hashlib.sha256(APPROVED_BYTES).hexdigest()},
        },
    }
    _create(lab, "ConfigMap", REGISTRY, immutable=True,
            data={"registry.json": json.dumps(registry, sort_keys=True, separators=(",", ":"))})
    for name in (UNAPPROVED_REPO, APPROVED_REPO, CONSUMER_A, CONSUMER_B, INGESTER):
        _create(lab, "ServiceAccount", name, automountServiceAccountToken=False)

    # Create PVCs and their consuming Pods before any wait, so delayed-binding storage can
    # schedule each consumer and select its volume zone.
    for claim, consumer in ((PVC_A, CONSUMER_A), (PVC_B, CONSUMER_B)):
        _create(lab, "PersistentVolumeClaim", claim, spec={
            "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "16Mi"}},
        })
        _pod(lab, image, consumer, "consumer", [], pvc=claim)
    _pod(lab, image, UNAPPROVED_REPO, "repository", [])
    _pod(lab, image, APPROVED_REPO, "repository", [])
    _pod(lab, image, INGESTER, "ingester",
         ["python", "/fixture/source_fixture.py", "idle"])
    for name in (CONSUMER_A, CONSUMER_B, UNAPPROVED_REPO, APPROVED_REPO, INGESTER):
        _wait_ready(lab, name)
    for claim in (PVC_A, PVC_B):
        lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Bound",
                    f"pvc/{claim}", "--timeout=100s", timeout=110)


def run(lab):
    image = load_runtime(lab)
    _publish(lab, image)

    red = _ingest(lab, "open", UNAPPROVED_ID)
    red_unregistered = _http(lab, INGESTER, UNAPPROVED_REPO, "GET", "/stats")
    red_a = _http(lab, INGESTER, CONSUMER_A, "GET", "/state")
    red_b = _http(lab, INGESTER, CONSUMER_B, "GET", "/state")
    red_expected = {"source_id": UNAPPROVED_ID,
                    "sha256": hashlib.sha256(UNAPPROVED_BYTES).hexdigest(),
                    "bytes_b64": base64.b64encode(UNAPPROVED_BYTES).decode("ascii")}
    red_ok = (red.get("decision") == "accepted" and red.get("source_id") == UNAPPROVED_ID
              and red.get("fetched_sha256") == red_expected["sha256"]
              and red_unregistered.get("fetches") == 1
              and red_a.get("records") == [red_expected]
              and red_b.get("records") == [red_expected])
    lab.check("red", "With admission disabled, a fixed unregistered source reaches both consumers",
              red_ok, {"decision": red.get("decision"), "unregistered_source_fetches":
                       red_unregistered.get("fetches"),
                       "consumer_a_has_expected_bytes": red_a.get("records") == [red_expected],
                       "consumer_b_has_expected_bytes": red_b.get("records") == [red_expected],
                       "expected_sha256": red_expected["sha256"]})

    before_unregistered = _http(lab, INGESTER, UNAPPROVED_REPO, "GET", "/stats")
    before_a = _http(lab, INGESTER, CONSUMER_A, "GET", "/state")
    before_b = _http(lab, INGESTER, CONSUMER_B, "GET", "/state")
    green = _ingest(lab, "locked", UNAPPROVED_ID)
    after_unregistered = _http(lab, INGESTER, UNAPPROVED_REPO, "GET", "/stats")
    after_a = _http(lab, INGESTER, CONSUMER_A, "GET", "/state")
    after_b = _http(lab, INGESTER, CONSUMER_B, "GET", "/state")
    green_ok = (green == {"decision": "rejected", "reason": "repository_id_not_registered",
                         "source_id": UNAPPROVED_ID, "fetches": 0, "downstream_writes": 0}
                and before_unregistered == after_unregistered
                and before_a == after_a and before_b == after_b)
    lab.check("green", "The enabled registry gate rejects before fetch or either consumer write",
              green_ok, {"decision": green.get("decision"), "reason": green.get("reason"),
                         "source_fetch_count_unchanged": before_unregistered == after_unregistered,
                         "consumer_a_unchanged": before_a == after_a,
                         "consumer_b_unchanged": before_b == after_b})

    denied = _http(lab, INGESTER, APPROVED_REPO, "GET", SOURCE_PATH)
    positive = _ingest(lab, "locked", APPROVED_ID)
    approved_stats = _http(lab, INGESTER, APPROVED_REPO, "GET", "/stats")
    final_a = _http(lab, INGESTER, CONSUMER_A, "GET", "/state")
    final_b = _http(lab, INGESTER, CONSUMER_B, "GET", "/state")
    expected_record = {"source_id": APPROVED_ID,
                       "sha256": hashlib.sha256(APPROVED_BYTES).hexdigest(),
                       "bytes_b64": base64.b64encode(APPROVED_BYTES).decode("ascii")}
    positive_ok = (positive.get("decision") == "accepted" and positive.get("registry_match") is True
                   and positive.get("fetched_sha256") == expected_record["sha256"]
                   and approved_stats.get("fetches") == 2 and denied.get("status") == 401
                   and final_a.get("records", [])[-1:] == [expected_record]
                   and final_b.get("records", [])[-1:] == [expected_record])
    lab.check("positive", "An approved repository is fetched and its exact bytes persist at both consumers",
              positive_ok, {"registry_match": positive.get("registry_match"),
                            "approved_source_fetches": approved_stats.get("fetches"),
                            "unauthenticated_read_denied": denied.get("status") == 401,
                            "expected_digest": expected_record["sha256"],
                            "consumer_a_persisted": final_a.get("records", [])[-1:] == [expected_record],
                            "consumer_b_persisted": final_b.get("records", [])[-1:] == [expected_record]})

    receipt = {"case": "SAF-K8S-0909-013", "namespace": NS,
               "fixtures": "fixed-benign-local-repositories", "red": red_ok,
               "green": green_ok, "positive": positive_ok,
               "unregistered_source_fetches": red_unregistered.get("fetches"),
               "gated_unregistered_fetch_delta": after_unregistered.get("fetches", 0)
               - before_unregistered.get("fetches", 0),
               "consumer_write_deltas_on_rejection": [
                   len(after_a.get("records", [])) - len(before_a.get("records", [])),
                   len(after_b.get("records", [])) - len(before_b.get("records", []))],
               "approved_source_fetches": approved_stats.get("fetches"),
               "approved_sha256": expected_record["sha256"],
               "approved_persisted_by_both": positive_ok}
    (lab.evidence / "source-allowlist-observations.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n")
