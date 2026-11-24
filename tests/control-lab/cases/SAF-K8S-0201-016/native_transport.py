"""Join the actual sanitized audit marker to scoped durable forwarding evidence."""
import json
from pathlib import Path
from runpy import run_path
import tempfile
import time

ROOT = Path(__file__).resolve().parent
TLS_NAME = "native-audit-receiver.saf-test.svc"
RECEIVER = "native-audit-receiver"
SENDER = "native-audit-sender"
SOURCE = "native-audit-source"
APP = "native-audit-app"
SPOOL = "native-audit-spool"
SINK = "native-audit-sink"


def native_event(lab):
    helper = ROOT.parent / "SAF-K8S-0201-015" / "audit_fixtures.py"
    if not helper.is_file():
        lab.block("The reviewed Linux Audit case helper must accompany this example")
    observed = run_path(str(helper))["observe_guest"](lab)
    if not all(observed[key] for key in ("collector_canary_logged", "no_audit_loss", "rules_removed", "guest_deleted")):
        lab.block("The owned producer did not establish native Audit source evidence and cleanup")
    marker, = [item for item in observed["events"] if (item["kind"], item["operation"]) == ("config", "read")]
    event = {key: marker[key] for key in ("serial", "kind", "operation", "success")}
    event["source"] = marker["marker_key"].split("_", 1)[0]
    return observed, marker, event


def install_tls(lab, directory):
    ca_config = directory / "ca.conf"
    ca_config.write_text("[req]\ndistinguished_name=dn\n[dn]\n[ext]\n"
                                                  "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                         "subjectKeyIdentifier=hash\n")
    ca_key, ca = directory / "ca.key", directory / "ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SAF temporary audit CA", "-config", str(ca_config), "-extensions", "ext",
                "-keyout", str(ca_key), "-out", str(ca), timeout=30)
    for role, name, usage in (("server", TLS_NAME, "serverAuth"), ("client", "audit-forwarder", "clientAuth")):
        key, csr, leaf = (directory / f"{role}.{suffix}" for suffix in ("key", "csr", "crt"))
        extension = directory / f"{role}.ext"
        extension.write_text(f"basicConstraints=critical,CA:FALSE\nextendedKeyUsage={usage}\n"
                             "keyUsage=critical,digitalSignature,keyEncipherment\n"
                             "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n"
                             + (f"subjectAltName=DNS:{TLS_NAME}\n" if role == "server" else ""))
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
                    "-keyout", str(key), "-out", str(csr), timeout=30)
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", "2", "-extfile", str(extension), "-out", str(leaf), timeout=30)
        key.chmod(0o600)
        # Passing file paths avoids placing key values in the lab API command log.
        lab.kubectl("create", "secret", "generic", f"native-audit-{role}-tls",
                    *(f"--from-file={file}" for file in (ca, key, leaf)))


def make_pod(base, *, receiver=False, resume=False):
    name = RECEIVER if receiver else SENDER
    mode = "resume" if resume else "send"
    cert_role = "server" if receiver else "client"
    spec = base["_pod_security"]()
    mounts = [{"name": "app", "mountPath": "/app", "readOnly": True},
              {"name": "tls", "mountPath": "/tls", "readOnly": True}]
    volumes = [{"name": "app", "configMap": {"name": APP}},
               {"name": "tls", "secret": {"secretName": f"native-audit-{cert_role}-tls", "defaultMode": 0o440}}]
    data_path, volume = ("/data", SINK) if receiver else ("/spool", SPOOL)
    mounts.append({"name": "state", "mountPath": data_path})
    volumes.append({"name": "state", "persistentVolumeClaim": {"claimName": volume}})
    if not receiver and not resume:
        mounts.append({"name": "input", "mountPath": "/input", "readOnly": True})
        volumes.append({"name": "input", "configMap": {"name": SOURCE}})
    command = ["python", "-u", "/app/tls_receiver.py"] if receiver else ["python", "-u", "/app/native_forwarder.py", mode]
    ports = [{"containerPort": 8443, "name": "https"}] if receiver else None
    fixture = base["_container"](cert_role, command, mounts, ports)
    fixture["readinessProbe"] = ({"tcpSocket": {"port": "https"}, "periodSeconds": 1} if receiver else
                                 {"exec": {"command": ["test", "-s", "/spool/pending.json"]}, "periodSeconds": 1})
    spec.update(containers=[fixture], volumes=volumes, restartPolicy="Never", terminationGracePeriodSeconds=2)
    return {"apiVersion": "v1", "kind": "Pod", "metadata": base["_meta"](name, {"app": name}), "spec": spec}


def snapshot(lab, kind, name):
    return json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)


def ready(lab, *names):
    lab.kubectl("wait", "--for=condition=Ready", *(f"pod/{name}" for name in names), "--timeout=80s", timeout=88)


def sender(lab, *args, payload=None):
    stdin = ("-i",) if payload is not None else ()
    return lab.kubectl("exec", *stdin, f"pod/{SENDER}", "--", "python", "/app/native_forwarder.py", *args,
                       payload=payload, timeout=25).stdout.strip()


def query(lab, serial):
    return json.loads(sender(lab, "query", serial))


def logged(lab, marker, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        log = lab.kubectl("logs", f"pod/{SENDER}", allow_failure=True).stdout
        if marker in log.splitlines():
            return True
        time.sleep(1)
    return False


def binding(pvc):
    return {"uid": pvc["metadata"]["uid"], "volume": pvc["spec"]["volumeName"]}


def run(lab, base):
    observed, native, event = native_event(lab)
    serial = event["serial"]
    with tempfile.TemporaryDirectory(prefix="saf-native-audit-tls-") as directory:
        install_tls(lab, Path(directory))
    # Only the selected synthetic marker is admitted to the sender input.
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": base["_meta"](SOURCE),
                "data": {"event.json": json.dumps(event)}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": base["_meta"](APP),
                "data": {name: (ROOT / name).read_text() for name in ("native_forwarder.py", "tls_receiver.py")}})
    for name in (SINK, SPOOL):
        lab.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": base["_meta"](name),
                    "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "16Mi"}}}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": base["_meta"](RECEIVER),
                "spec": {"selector": {"app": RECEIVER}, "ports": [{"port": 8443, "targetPort": 8443}]}})
    first_srv = lab.create(make_pod(base, receiver=True))
    first_send = lab.create(make_pod(base))
    # The default local provisioner binds after the consumer Pods are scheduled.
    ready(lab, RECEIVER, SENDER)
    original_sink = binding(snapshot(lab, "pvc", SINK))
    original_spool = binding(snapshot(lab, "pvc", SPOOL))
    denied = sender(lab, "without-certificate") == "client-certificate-required"
    lab.check("red", "A client without a certificate is rejected by the real mTLS listener", denied,
              {"uncredentialed_client_rejected_by_tls": denied})
    initial_503 = logged(lab, f"delivery status=503 serial={serial}")
    uncopied = query(lab, serial) == []
    lab.check("red", "The authenticated sender receives 503 and the central query has no acknowledged marker",
              initial_503 and uncopied, {"receiver_503": initial_503, "sink_still_empty": uncopied})
    lab.kubectl("delete", "pod", SENDER, "--wait=true")
    lab.kubectl("delete", "configmap", SOURCE, "--wait=true")
    replacement_send = lab.create(make_pod(base, resume=True))
    ready(lab, SENDER)
    after_spool = binding(snapshot(lab, "pvc", SPOOL))
    changed = replacement_send["metadata"]["uid"] != first_send["metadata"]["uid"]
    no_input = all(vol["name"] != "input" for vol in replacement_send["spec"]["volumes"])
    retry = logged(lab, f"delivery status=503 serial={serial}")
    lab.check("positive", "The replacement sender can read only the preserved spool and retries the same marker",
              changed and no_input and retry and after_spool == original_spool,
              {"new_sender_pod": changed, "original_source_removed": no_input,
               "same_spool_binding": after_spool == original_spool, "buffered_marker_retried": retry})

    lab.kubectl("exec", f"pod/{RECEIVER}", "--", "touch", "/data/accepting")
    accepted = logged(lab, f"delivery status=202 serial={serial}", 45)
    drained = lab.kubectl("exec", f"pod/{SENDER}", "--", "test", "!", "-e", "/spool/pending.json",
                          allow_failure=True).returncode == 0
    authentic = {**event, "authenticated_source": "audit-forwarder"}
    first_query = query(lab, serial)
    lab.check("green", "Recovery commits the expected native event with the authenticated sender identity",
              accepted and drained and first_query == [authentic],
              {"acknowledged": accepted, "sender_spool_drained_after_ack": drained,
               "exact_central_receipt_and_identity": first_query == [authentic]})

    lab.kubectl("delete", "pod", RECEIVER, "--wait=true")
    replacement_srv = lab.create(make_pod(base, receiver=True))
    ready(lab, RECEIVER)
    after_sink = binding(snapshot(lab, "pvc", SINK))
    recovered = query(lab, serial)
    server_changed = replacement_srv["metadata"]["uid"] != first_srv["metadata"]["uid"]
    lab.check("positive", "A replacement receiver can retrieve the original marker from the original bound storage",
              server_changed and recovered == [authentic] and after_sink == original_sink,
              {"new_receiver_pod": server_changed, "same_sink_binding": after_sink == original_sink,
               "event_retrieved_after_replacement": recovered == [authentic]})
    duplicate = sender(lab, "replay", payload=json.dumps(event)) == "delivery status=202"
    final = query(lab, serial)
    lab.check("positive", "Authenticated replay of the same event remains exactly one central record",
              duplicate and final == [authentic], {"duplicate_acknowledged": duplicate,
                                                  "central_records_after_replay": len(final)})
    (lab.evidence / "native-audit-forwarding.json").write_text(json.dumps({
        "source_platform": observed["platform"], "source_probe_sha256": observed["probe_sha256"],
        "native_event": native, "imported_marker": event, "central_records": final,
        "sender_before": first_send["metadata"]["uid"], "sender_after": replacement_send["metadata"]["uid"],
        "receiver_before": first_srv["metadata"]["uid"], "receiver_after": replacement_srv["metadata"]["uid"],
        "initial_spool": original_spool, "replacement_spool": after_spool,
        "initial_sink": original_sink, "replacement_sink": after_sink,
        "no_input_on_resume": no_input, "client_certificate_required": denied, "receiver_503_before_and_after": initial_503 and retry,
        "accepted": accepted, "drained_after_acceptance": drained, "duplicate_acknowledged": duplicate,
    }, indent=2) + "\n")
