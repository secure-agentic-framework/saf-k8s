"""Check independently retained Zot audit and HTTP events using Fluent Bit."""
from collections import Counter
import json
from pathlib import Path
import secrets
import subprocess
import time

HERE = Path(__file__).resolve().parent
ZOT = "ghcr.io/project-zot/zot:v2.1.23@sha256:9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7"
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
FLUENT_BIT = "cr.fluentbit.io/fluent/fluent-bit:5.1.2@sha256:d792375ca8e53be72fc25716c28f291f32c6fc6f4f31d12d0d14bc78cefe9226"
BUSYBOX = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
ACTOR = "fixture-publisher"
REPO = "saf-test/audit-model"
AUDIT = "/events/audit.jsonl"
ACCESS = "/events/access.jsonl"
SCOPE = (
    "One fresh Kind cluster runs two authenticated Zot v2.1.23 registries. The same "
    "inert OCI operations occur with forwarding off and on. Fluent Bit 5.1.2 ships "
    "native audit and HTTP access events to an independent HTTP receiver backed by a "
    "PVC. The receiver is replaced, retained events are compared, and a fresh event "
    "sequence is delivered. Covers model manifest publish, pull, retag and digest "
    "deletion. Permission and administrative event sources, loss recovery during "
    "a receiver outage, production access controls, SIEM delivery and retention are open."
)


def _submit(lab, obj):
    lab.kubectl("create", "-f", "-", payload=json.dumps(obj))


def _configmap(lab, name, data):
    _submit(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": name}, "data": data})


def _volume(name, **reference):
    return {"name": name, **reference}


def _mount(name, path, *, read_only=False):
    return {"name": name, "mountPath": path, "readOnly": read_only}


def _container(name, image, mounts, *, command=None, args=None, ready_port=None):
    container = {
        "name": name, "image": image, "imagePullPolicy": "IfNotPresent", "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "15m", "memory": "24Mi"},
                      "limits": {"cpu": "250m", "memory": "128Mi"}},
    }
    if command:
        container["command"] = command
    if args:
        container["args"] = args
    if ready_port:
        container["readinessProbe"] = {"tcpSocket": {"port": ready_port}, "periodSeconds": 1}
    return container


def _deployment(lab, name, containers, volumes, port=None):
    _submit(lab, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                  "spec": {"replicas": 1, "strategy": {"type": "Recreate"},
                           "selector": {"matchLabels": {"app": name}},
                           "template": {"metadata": {"labels": {"app": name}},
                                        "spec": {"automountServiceAccountToken": False,
                                                 "containers": containers, "volumes": volumes}}}})
    if port:
        _submit(lab, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
                      "spec": {"selector": {"app": name},
                               "ports": [{"port": port, "targetPort": port}]}})


def _wait(lab, name):
    lab.kubectl("rollout", "status", f"deployment/{name}", "--timeout=90s", timeout=100)


def _fixture_identity(lab):
    auth = lab.kubeconfig.parent / "registry-auth"
    auth.mkdir(mode=0o700)
    password = secrets.token_urlsafe(24)
    result = subprocess.run(("htpasswd", "-Bni", ACTOR), input=password + "\n",
                            text=True, capture_output=True, timeout=15, env=lab.env)
    if result.returncode or not result.stdout.startswith(ACTOR + ":"):
        lab.block("Could not prepare the disposable registry identity")
    for name, value in (("htpasswd", result.stdout), ("password", password)):
        path = auth / name
        path.touch(mode=0o600, exist_ok=False)
        path.write_text(value)
    lab.kubectl("create", "secret", "generic", "registry-auth",
                f"--from-file=htpasswd={auth/'htpasswd'}", f"--from-file=password={auth/'password'}")


def _setup(lab):
    _fixture_identity(lab)
    config = {"distSpecVersion": "1.1.0", "storage": {"rootDirectory": "/var/lib/registry"},
              "log": {"level": "info", "output": ACCESS, "audit": AUDIT},
              "http": {"address": "0.0.0.0", "port": "5000",
                       "auth": {"htpasswd": {"path": "/auth/htpasswd"}},
                       "accessControl": {"repositories": {REPO: {"policies": [
                           {"users": [ACTOR], "actions": ["read", "create", "update", "delete"]}
                       ]}}}}}
    _configmap(lab, "registry-config", {"config.json": json.dumps(config)})
    _configmap(lab, "scripts", {name: (HERE / name).read_text() for name in ("sink.py", "probe.py")})
    _configmap(lab, "forwarding-config", {"fluent-bit.yaml": (HERE / "fluent-bit.yaml").read_text()})
    _submit(lab, {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                  "metadata": {"name": "sink-data"},
                  "spec": {"accessModes": ["ReadWriteOnce"],
                           "resources": {"requests": {"storage": "64Mi"}}}})
    scripts = _volume("scripts", configMap={"name": "scripts"})
    script_mount = _mount("scripts", "/app", read_only=True)
    _deployment(lab, "sink", [_container("sink", PYTHON, [script_mount, _mount("data", "/sink")],
                                        command=["python", "/app/sink.py"], ready_port=8080)],
                [scripts, _volume("data", persistentVolumeClaim={"claimName": "sink-data"})], 8080)
    _deployment(lab, "probe", [_container("probe", PYTHON, [script_mount, _mount("auth", "/auth", read_only=True)],
                                          command=["python", "-c", "import time; time.sleep(3600)"])],
                [scripts, _volume("auth", secret={"secretName": "registry-auth",
                                                  "items": [{"key": "password", "path": "password"}]})])
    for registry in ("without-forwarding", "with-forwarding"):
        read_events = _mount("events", "/events", read_only=True)
        volumes = [_volume("config", configMap={"name": "registry-config"}),
                   _volume("auth", secret={"secretName": "registry-auth",
                                           "items": [{"key": "htpasswd", "path": "htpasswd"}]}),
                   _volume("registry", emptyDir={}), _volume("events", emptyDir={})]
        containers = [
            _container("zot", ZOT, [_mount("config", "/etc/zot", read_only=True),
                                   _mount("auth", "/auth", read_only=True),
                                   _mount("registry", "/var/lib/registry"), _mount("events", "/events")],
                       args=["serve", "/etc/zot/config.json"], ready_port=5000),
            _container("observer", BUSYBOX, [read_events], command=["sleep", "3600"]),
        ]
        if registry == "with-forwarding":
            volumes.append(_volume("forwarding", configMap={"name": "forwarding-config"}))
            containers.append(_container("fluent-bit", FLUENT_BIT,
                                         [read_events, _mount("forwarding", "/config", read_only=True)],
                                         args=["-c", "/config/fluent-bit.yaml"]))
        _deployment(lab, registry, containers, volumes, 5000)
    for name in ("sink", "probe", "without-forwarding", "with-forwarding"):
        _wait(lab, name)


def _exercise(lab, registry, tag):
    response = lab.kubectl("exec", "deployment/probe", "--", "python", "/app/probe.py",
                           f"http://{registry}:5000", tag)
    row = json.loads(response.stdout)
    expected = {"publish_status": 201, "pull_status": 200, "retag_status": 201, "delete_status": 202}
    if not all(row.get(key) == value for key, value in expected.items()) or row["pull_digest"] != row["digest"]:
        lab.block(f"OCI probe did not perform all expected operations: {row}")
    return row


def _rows(raw):
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _selected(events, stream, targets):
    fields = ("action", "object", "status", "subject", "HTTP API Audit") if stream == "audit" else (
        "method", "path", "statusCode", "username", "HTTP API")
    method, path, status, actor, message = fields
    return [{"stream": stream, "method": row[method], "path": row[path], "status": row[status],
             "actor": row.get(actor), "time": row.get("time")} for row in events
            if row.get("message") == message and (row.get(method), row.get(path)) in targets]


def _local(lab, registry, targets):
    observed = []
    for stream, path in (("audit", AUDIT), ("access", ACCESS)):
        result = lab.kubectl("exec", f"deployment/{registry}", "-c", "observer", "--", "cat", path)
        observed.extend(_selected(_rows(result.stdout), stream, targets))
    return observed


def _read_sink(lab, targets):
    raw = lab.kubectl("exec", "deployment/sink", "--", "python", "-c",
                      "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/events', timeout=3).read().decode())")
    rows = _rows(raw.stdout)
    return [entry for stream in ("audit", "access")
            for entry in _selected([row["event"] for row in rows if row["stream"] == stream], stream, targets)]


def _expected(tag, digest):
    prefix = f"/v2/{REPO}/manifests"
    operations = [("PUT", f"{prefix}/{tag}-v1", 201), ("GET", f"{prefix}/{tag}-v1", 200),
                  ("PUT", f"{prefix}/{tag}-v2", 201), ("DELETE", f"{prefix}/{digest}", 202)]
    expected = [(stream, method, path, status, ACTOR) for stream in ("audit", "access")
                for method, path, status in operations if stream == "access" or method != "GET"]
    return Counter(expected), {(method, path) for method, path, _ in operations}


def _count(events, *, timestamp=False):
    keys = ("stream", "method", "path", "status", "actor")
    if timestamp:
        keys += ("time",)
    return Counter(tuple(row[key] for key in keys) for row in events)


def _await_corpus(lab, targets, expected):
    start = time.monotonic()
    while time.monotonic() - start < 35:
        delivered = _read_sink(lab, targets)
        if _count(delivered, timestamp=True) == _count(expected, timestamp=True):
            return delivered
        time.sleep(0.6)
    return delivered


def _sink_uid(lab):
    raw = lab.kubectl("get", "pods", "-l", "app=sink", "-o", "json")
    pod, = json.loads(raw.stdout)["items"]
    return pod["metadata"]["uid"]


def run(lab):
    _setup(lab)
    red = _exercise(lab, "without-forwarding", "first")
    expected, targets = _expected("first", red["digest"])
    local_red = _local(lab, "without-forwarding", targets)
    sink_red = _read_sink(lab, targets)
    lab.check("red", "Without forwarding the exact registry actions appear locally and the separate sink stays empty",
              _count(local_red) == expected and not sink_red,
              {"local_expected_records": len(local_red), "sink_records": len(sink_red)})

    green = _exercise(lab, "with-forwarding", "first")
    local_green = _local(lab, "with-forwarding", targets)
    received = _await_corpus(lab, targets, local_green)
    lab.check("green", "Fluent Bit delivers the exact local audit and HTTP access records for each action",
              green == red and _count(local_green) == expected and all(row["time"] for row in local_green)
              and _count(received, timestamp=True) == _count(local_green, timestamp=True),
              {"expected_audit_records": 3, "expected_access_records": 4,
               "exact_corpus_matches": _count(received, timestamp=True) == _count(local_green, timestamp=True)})

    old_uid = _sink_uid(lab)
    lab.kubectl("delete", "pod", "-l", "app=sink", "--wait=true", timeout=70)
    _wait(lab, "sink")
    new_uid = _sink_uid(lab)
    retained = _read_sink(lab, targets)
    after = _exercise(lab, "with-forwarding", "second")
    after_expected, after_targets = _expected("second", after["digest"])
    after_local = _local(lab, "with-forwarding", after_targets)
    after_received = _await_corpus(lab, after_targets, after_local)
    retained_exact = _count(retained, timestamp=True) == _count(received, timestamp=True)
    continued = _count(after_local) == after_expected and _count(after_received, timestamp=True) == _count(after_local, timestamp=True)
    (lab.evidence / "forwarded-zot-events.json").write_text(json.dumps(
        {"local_before": local_red, "sink_before": sink_red, "local_enabled": local_green,
         "sink_enabled": received, "retained": retained, "local_after_restart": after_local,
         "sink_after_restart": after_received, "receiver_uids": [old_uid, new_uid]}, indent=2) + "\n")
    lab.check("positive", "The replacement receiver retains prior events and accepts the exact next registry sequence",
              old_uid != new_uid and retained_exact and continued,
              {"receiver_replaced": old_uid != new_uid, "prior_records_exact": retained_exact,
               "new_records_exact": continued})
