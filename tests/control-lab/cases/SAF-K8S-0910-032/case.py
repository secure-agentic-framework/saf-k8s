"""Observe bounded telemetry volume over the published owned-peer mTLS route."""
import importlib.util
import json
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
from fixtures import container, pod, ready

NS = "saf-test"
COLLECTOR = "fixture-telemetry-collector"
SOURCE = "fixture-telemetry-source"
OBSERVER = "fixture-telemetry-observer"
UNAPPROVED_SOURCE = "fixture-telemetry-unapproved"
CODE = "fixture-monitor-code"
TRUST = "fixture-monitor-trust"
SERVER_NAME = "fixture-monitor.saf.test"
SOURCE_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-telemetry-source"
OBSERVER_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-telemetry-observer"
UNAPPROVED_SOURCE_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-telemetry-unapproved"
UNAPPROVED_SERVER_NAME = "unapproved-destination.saf.test"
WINDOW_SECONDS = 20
RECORD_THRESHOLD = 3
BYTE_THRESHOLD = 1024

SCOPE = (
    "The supervisor-owned source Kind cluster sends only bounded synthetic telemetry over the "
    "same private NodePort route to a separately owned peer Kind collector. Exact mTLS URI identity "
    "attributes the source; the collector measures observed JSON bytes and unique fixture record IDs. "
    "A separate mTLS observer reads the collector report and correlates each observed digest and size "
    "to the expected records and the generated alert. This is deterministic fixture evidence, not "
    "production network coverage."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def uri_extension(identity, usage):
    return ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={usage}\nsubjectAltName=URI:{identity}\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")


def pki(lab, root):
    ca, ca_key = root / "root.crt", root / "root.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=fixture-monitor-root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext",
                "subjectKeyIdentifier=hash", "-keyout", str(ca_key), "-out", str(ca))
    for name, purpose, identity, dns in (
            (COLLECTOR, "serverAuth", None, SERVER_NAME),
            (SOURCE, "clientAuth", SOURCE_URI, None),
            (OBSERVER, "clientAuth", OBSERVER_URI, None),
            (UNAPPROVED_SOURCE, "clientAuth", UNAPPROVED_SOURCE_URI, None)):
        key, cert, conf = (root / f"{name}.{suffix}" for suffix in ("key", "crt", "ext"))
        if identity:
            conf.write_text(uri_extension(identity, purpose))
        else:
            conf.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                            f"extendedKeyUsage={purpose}\nsubjectAltName=DNS:{dns}\n"
                            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        csr = root / f"{name}.csr"
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                    f"/CN={name}", "-keyout", str(key), "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey",
                    str(ca_key), "-CAcreateserial", "-days", "1", "-sha256", "-extfile",
                    str(conf), "-out", str(cert))
    return root, ca


def create(call, resource):
    result = call("create", "-f", "-", "-o", "json", payload=json.dumps(resource), timeout=25)
    return json.loads(result.stdout) if result.stdout.strip().startswith("{") else {}


def workload(name, image, credential=False, server=False, mode="enabled"):
    mounts = [{"name": "code", "mountPath": "/code", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}},
               {"name": "trust", "configMap": {"name": TRUST}}]
    if credential:
        mounts.append({"name": "credential", "mountPath": "/credential", "readOnly": True})
        volumes.append({"name": "credential", "secret": {"secretName": name, "defaultMode": 288}})
    worker = container("fixture", image=image, imagePullPolicy="Never",
                       command=["python", "/code/monitor_fixture.py", "serve", mode] if server
                       else ["sleep", "360"], volumeMounts=mounts)
    if server:
        worker["ports"] = [{"containerPort": 8443}]
        worker["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    obj = pod(name, [worker], automountServiceAccountToken=False,
              securityContext={"fsGroup": 65534}, volumes=volumes, terminationGracePeriodSeconds=2)
    obj["metadata"]["namespace"] = NS
    obj["metadata"]["labels"] = {"app": name}
    if not server:
        obj["spec"]["serviceAccountName"] = name
    return obj


def report(lab, name, address, port, state, ids):
    result = lab.kubectl("exec", name, "--", "python", "/code/monitor_fixture.py", "observe",
                         address, str(port), SERVER_NAME, state, *ids, timeout=12)
    return json.loads(result.stdout)


def send(lab, address, port, ids):
    return send_from(lab, SOURCE, address, port, ids)


def send_from(lab, client, address, port, ids):
    result = lab.kubectl("exec", client, "--", "python", "/code/monitor_fixture.py", "send",
                         address, str(port), SERVER_NAME, *ids, timeout=15)
    return json.loads(result.stdout)


def run(lab):
    # runtime_case pins the Python image; owned_peer creates a second owned Kind cluster,
    # checks distinct cluster UIDs and a private bridge route, then tears it down.
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_monitor_runtime")
    bridge = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_monitor_owned_peer")
    image = runtime.load_runtime(lab)
    with tempfile.TemporaryDirectory(prefix="saf-monitor-pki-") as temp:
        root, ca = pki(lab, Path(temp))
        with bridge.owned_peer(lab, image) as (peer, address):
            def peer_create(resource):
                return create(peer, resource)

            peer("create", "secret", "tls", COLLECTOR, "--cert=" + str(root / (COLLECTOR + ".crt")),
                 "--key=" + str(root / (COLLECTOR + ".key")), "-n", NS, "-o", "name")
            peer_create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                         "immutable": True, "data": {"monitor_fixture.py":
                         (HERE / "monitor_fixture.py").read_text()}})
            peer_create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST},
                         "immutable": True, "data": {"ca.crt": ca.read_text()}})
            peer_create(workload(COLLECTOR, image, credential=True, server=True, mode="disabled"))
            service = peer_create({"apiVersion": "v1", "kind": "Service",
                                   "metadata": {"name": COLLECTOR, "namespace": NS},
                                   "spec": {"type": "NodePort", "selector": {"app": COLLECTOR},
                                            "ports": [{"name": "mtls", "port": 8443,
                                                       "targetPort": 8443}]}})
            port = int(service["spec"]["ports"][0]["nodePort"])

            lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
                "name": CODE, "namespace": NS}, "immutable": True,
                "data": {"monitor_fixture.py": (HERE / "monitor_fixture.py").read_text()}})
            lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
                "name": TRUST, "namespace": NS}, "immutable": True,
                "data": {"ca.crt": ca.read_text()}})
            for name in (SOURCE, OBSERVER, UNAPPROVED_SOURCE):
                lab.kubectl("create", "secret", "tls", name,
                            "--cert=" + str(root / (name + ".crt")),
                            "--key=" + str(root / (name + ".key")), "-n", NS, "-o", "name")
                lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                            "metadata": {"name": name, "namespace": NS},
                            "automountServiceAccountToken": False})
                lab.create(workload(name, image, credential=True))

            peer("wait", "--for=condition=Ready", "pod/" + COLLECTOR, "-n", NS,
                 "--timeout=80s", timeout=90)
            for name in (SOURCE, OBSERVER, UNAPPROVED_SOURCE):
                ready(lab, name)

            def await_route():
                deadline = time.monotonic() + 18
                while time.monotonic() < deadline:
                    response = lab.kubectl("exec", OBSERVER, "--", "python", "/code/monitor_fixture.py",
                                          "health", address, str(port), SERVER_NAME, timeout=10,
                                          allow_failure=True)
                    if response.returncode == 0 and json.loads(response.stdout) == {"ready": True}:
                        return
                    time.sleep(0.25)
                lab.block("The owned collector route was not ready")

            def rotate_collector():
                peer("delete", "pod", COLLECTOR, "--wait=true", "--timeout=35s", timeout=42)
                peer_create(workload(COLLECTOR, image, credential=True, server=True))
                peer("wait", "--for=condition=Ready", "pod/" + COLLECTOR, "--timeout=80s", timeout=90)
                await_route()

            def witness(ids, expected):
                sent = send(lab, address, port, ids)
                result = report(lab, OBSERVER, address, port, expected, ids)
                if list(item["status"] for item in sent["sent"]) != [202] * len(ids):
                    lab.block("The owned collector did not accept all exact fixture records")
                return result

            await_route()
            burst_ids = [f"synthetic-telemetry-burst-{i:03d}" for i in range(1, 5)]
            baseline = witness(burst_ids, "quiet")
            lab.check("red", "The baseline receives the exact above-threshold records without an alert",
                      all(baseline["checks"].values()), baseline)

            rotate_collector()
            burst = witness(burst_ids, "alert")
            lab.check("green", "The observer correlates a real bounded alert to the exact same measured records",
                      all(burst["checks"].values())
                      and baseline["report"]["records"] == burst["report"]["records"], burst)

            rotate_collector()
            ordinary = witness(["synthetic-telemetry-ordinary-001", "synthetic-telemetry-ordinary-002"], "quiet")
            lab.check("positive", "The monitored route still accepts ordinary traffic without an alert",
                      all(ordinary["checks"].values()), ordinary)

            # Start from a fresh collector state. An unapproved source URI signed by
            # the same disposable CA and an approved source using the wrong expected
            # destination name must both fail closed before any report record exists.
            rotate_collector()
            refused = send_from(lab, UNAPPROVED_SOURCE, address, port,
                                ["synthetic-telemetry-unapproved-001"])
            destination = lab.kubectl(
                "exec", SOURCE, "--", "python", "/code/monitor_fixture.py",
                "destination-probe", address, str(port), SERVER_NAME, UNAPPROVED_SERVER_NAME,
                timeout=12)
            destination = json.loads(destination.stdout)
            empty_after_refusals = report(lab, OBSERVER, address, port, "quiet", [])

            # Two individually bounded inert records exceed only the byte threshold;
            # the record-count threshold is not crossed. IDs remain synthetic and
            # the transmitted metric fields contain no workload or user data.
            byte_ids = ["synthetic-telemetry-byte-" + ("a" * 520) + suffix
                        for suffix in ("-001", "-002")]
            byte_batch = witness(byte_ids, "alert")
            byte_records = byte_batch["report"]["records"]
            byte_only = (byte_batch["report"]["record_count"] == 2
                         and byte_batch["report"]["record_count"] <= RECORD_THRESHOLD
                         and byte_batch["report"]["observed_bytes"] > BYTE_THRESHOLD
                         and all(0 < row["body_bytes"] <= 1024 for row in byte_records)
                         and len(byte_batch["report"]["events"]) == 1
                         and byte_batch["report"]["events"][0].get("record_count") == 2
                         and byte_batch["report"]["events"][0].get("observed_bytes")
                             == byte_batch["report"]["observed_bytes"])
            source_refused = (len(refused.get("sent", [])) == 1
                              and refused["sent"][0].get("status") == 403
                              and refused["sent"][0].get("decision") == "source-refused")
            destination_refused = (destination.get("configured_destination") == SERVER_NAME
                                   and destination.get("destination_identity_rejected") is True
                                   and destination.get("classification") == "certificate_identity_mismatch")
            no_unauthorized_record = (all(empty_after_refusals["checks"].values())
                                      and empty_after_refusals["report"]["records"] == []
                                      and empty_after_refusals["report"]["events"] == [])
            lab.check("positive",
                      "The configured source and destination are authenticated, refusals persist no record, and byte volume alerts independently",
                      source_refused and destination_refused and no_unauthorized_record
                      and all(byte_batch["checks"].values()) and byte_only,
                      {"configured_source_uri": SOURCE_URI,
                       "unapproved_same_ca_source_denied": source_refused,
                       "configured_destination_sni": SERVER_NAME,
                       "unapproved_destination_identity_rejected": destination_refused,
                       "unauthorized_attempts_left_no_observed_records": no_unauthorized_record,
                       "byte_threshold_exercised_without_count_threshold": byte_only,
                       "byte_threshold_report": byte_batch})

    (lab.evidence / "cross-cluster-telemetry-monitoring.json").write_text(json.dumps({
        "case": "SAF-K8S-0910-032",
        "route": {"kind": "owned-private-bridge-nodeport", "server_name": SERVER_NAME,
                  "path": "/telemetry", "mutual_tls": True},
        "limits": {"window_seconds": WINDOW_SECONDS, "record_threshold_gt": RECORD_THRESHOLD,
                   "byte_threshold_gt": BYTE_THRESHOLD, "maximum_record_bytes": 1024,
                   "maximum_retained_records": 16},
        "baseline": baseline,
        "alerting": burst,
        "ordinary": ordinary,
        "source_destination_and_byte_threshold": {"unapproved_source": refused,
            "unapproved_destination": destination, "empty_after_refusals": empty_after_refusals,
            "byte_threshold": byte_batch},
    }, sort_keys=True, indent=2) + "\n")
