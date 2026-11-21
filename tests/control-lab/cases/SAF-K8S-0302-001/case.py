"""Require explicit safe security context on app, init, and debug containers."""
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
NAMESPACE = "saf-test"
DENIAL = "every app, init, and ephemeral container must explicitly set"
SCOPE = (
    "Pods in the synthetic saf-k8s.example/enforce-container-context namespace: "
    "explicit per-container runAsNonRoot=true, positive runAsUser, "
    "readOnlyRootFilesystem=true, and allowPrivilegeEscalation=false for app and "
    "init containers on Pod CREATE/UPDATE, plus separately added ephemeral debug "
    "containers on the ephemeralcontainers subresource. No exception is configured."
)



def secure_context():
    return {"runAsNonRoot": True, "runAsUser": 65534,
            "readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False}


def secure_container(name, **fields):
    item = container(name, **fields)
    item["securityContext"] = secure_context()
    return item


def denied(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr and DENIAL in result.stderr


def server_dry_run(lab, obj):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def pod_shape(name, *, app=None, init=None):
    spec = {}
    if app is not None:
        spec["containers"] = [app]
    if init is not None:
        spec["initContainers"] = [init]
    obj = pod(name, spec.pop("containers", []), **spec)
    obj["metadata"]["namespace"] = NAMESPACE
    return obj


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE, "saf-k8s.example/enforce-container-context=true")
    before = server_dry_run(lab, pod_shape(
        "missing-context-before-policy", app=container("app")))
    lab.check("red", "The scoped API accepts a missing container context before policy",
              before.returncode == 0, before.stderr.strip() or "server dry-run accepted")

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        probe = server_dry_run(lab, pod_shape(
            "missing-context-after-policy", app=container("app")))
        if denied(probe) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The policy rejects the missing context with its specific reason",
              denied(probe), probe.stderr.strip())

    # Test each obligation independently in both app and init container lists.
    fields = ("runAsNonRoot", "runAsUser", "readOnlyRootFilesystem",
              "allowPrivilegeEscalation")
    for kind in ("app", "init"):
        for field in fields:
            context = secure_context()
            del context[field]
            malformed = secure_container(kind)
            malformed["securityContext"] = context
            candidate = pod_shape(f"missing-{kind}-{field.lower()}",
                                  app=malformed if kind == "app" else secure_container("app"),
                                  init=malformed if kind == "init" else None)
            result = server_dry_run(lab, candidate)
            lab.check("green", f"The policy rejects omitted {field} on {kind} containers",
                      denied(result), result.stderr.strip())

    # A compliant Pod is persisted so ephemeralcontainers admission can be
    # challenged with server dry-run UPDATEs only.
    good = pod_shape("secure-reference", app=secure_container("app"),
                     init=secure_container("init", command=["sh", "-c", "true"]))
    good["spec"]["volumes"] = [{"name": "writable-temp", "emptyDir": {}}]
    good["spec"]["securityContext"] = {"fsGroup": 65534}
    good["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "writable-temp", "mountPath": "/tmp"},
    ]
    lab.create(good)
    lab.kubectl("wait", "--for=condition=Ready", "pod/secure-reference", "--timeout=95s",
                timeout=105)
    identity = lab.kubectl("exec", "secure-reference", "-c", "app", "--", "sh", "-c",
                           "set -eu; uid=$(id -u); test \"$uid\" = 65534; "
                           "root=$(awk '$2==\"/\" {print $4; exit}' /proc/mounts); "
                           "case ,$root, in *,ro,*) ;; *) exit 20;; esac; "
                           "if touch /saf-root-write-probe 2>/dev/null; then "
                           "rm -f /saf-root-write-probe; exit 21; fi; "
                           "touch /tmp/saf-writable-probe; rm /tmp/saf-writable-probe; "
                           "printf 'uid=%s root_mount=%s root_write=denied tmp_write=ok\\n' \"$uid\" \"$root\"")
    lab.check("positive", "The app runs as UID 65534 with read-only root and writable temp",
              "uid=65534" in identity.stdout and "root_write=denied" in identity.stdout
              and "tmp_write=ok" in identity.stdout, identity.stdout.strip())

    # Build a compliant debug container update, then omit each required field in
    # separate requests. These updates are all server dry-runs.
    debug = secure_container("debug")
    args = ("patch", "pod/secure-reference", "--subresource=ephemeralcontainers",
            "--type=merge", "-p", json.dumps({"spec": {"ephemeralContainers": [debug]}}),
            "--dry-run=server", "-o", "json")
    compliant_debug = lab.kubectl(*args, allow_failure=True)
    lab.check("positive", "A separately added compliant ephemeral container is admitted",
              compliant_debug.returncode == 0, compliant_debug.stderr.strip() or "dry-run accepted")
    for field in fields:
        unsafe_debug = json.loads(json.dumps(debug))
        del unsafe_debug["securityContext"][field]
        result = lab.kubectl(
            "patch", "pod/secure-reference", "--subresource=ephemeralcontainers",
            "--type=merge", "-p", json.dumps({"spec": {"ephemeralContainers": [unsafe_debug]}}),
            "--dry-run=server", "-o", "json", allow_failure=True)
        lab.check("green", f"The policy rejects debug containers missing {field}",
                  denied(result), result.stderr.strip())
