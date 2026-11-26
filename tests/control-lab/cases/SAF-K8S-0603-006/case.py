"""Run the TUF reference implementation against an in-cluster synthetic repository."""
from hashlib import sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
REPO = "saf-0603-006-repo"
CLIENT = "saf-0603-006-client"
SCOPE = (
    "python-tuf 7.0.1 on Kubernetes v1.36.1 with a case-owned Service and two Pods. "
    "A separately pinned fixture root controls a synthetic repository with local Ed25519 signing. "
    "The case exercises digest and version binding, distinct signatures, metadata limits, expiry, "
    "separate bootstrap root identity, persisted rollback protection, exact target acceptance and root rotation. "
    "Live custody, managed services and signing ceremonies require separate evidence."
)
INSTALL = (
    "python -m pip --isolated --disable-pip-version-check install "
    "--index-url https://pypi.org/simple --only-binary=:all: --require-hashes --no-cache-dir "
    "--target /tmp/fixture-lib -r /fixture/requirements.txt >/tmp/install.log 2>&1 "
    "|| { cat /tmp/install.log; exit 1; }; "
    "export PYTHONPATH=/tmp/fixture-lib; exec python /fixture/update_fixture.py "
)


def pod(name, mode, *, server=False):
    volumes = [{"name": "fixture", "configMap": {"name": "saf-0603-006-fixture"}}]
    mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    container = {
        "name": mode, "image": IMAGE, "command": ["sh", "-ec", INSTALL + mode],
        "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "25m", "memory": "48Mi"},
                      "limits": {"cpu": "1", "memory": "256Mi"}},
        "volumeMounts": mounts,
    }
    if server:
        container["ports"] = [{"containerPort": 8080}]
        container["readinessProbe"] = {"httpGet": {"path": "/ready", "port": 8080}, "periodSeconds": 1}
    else:
        volumes.append({"name": "bootstrap", "configMap": {"name": "saf-0603-006-root"}})
        mounts.append({"name": "bootstrap", "mountPath": "/bootstrap", "readOnly": True})
        volumes.append({"name": "trust-policy", "configMap": {"name": "saf-0603-006-root-policy"}})
        mounts.append({"name": "trust-policy", "mountPath": "/trust-policy", "readOnly": True})
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [container], "volumes": volumes},
    }


def wait(lab, name, condition):
    result = lab.kubectl("wait", f"--for={condition}", f"pod/{name}", "--timeout=85s",
                         timeout=95, allow_failure=True)
    if result.returncode:
        lab.kubectl("describe", "pod", name, allow_failure=True)
        lab.kubectl("logs", name, allow_failure=True)
        lab.block(f"TUF fixture Pod {name} did not meet {condition}")


def run(lab):
    lab.kubectl("create", "configmap", "saf-0603-006-fixture",
                f"--from-file={HERE / 'requirements.txt'}", f"--from-file={HERE / 'update_fixture.py'}")
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": REPO},
                "spec": {"selector": {"app": REPO}, "ports": [{"port": 8080, "targetPort": 8080}]}})
    lab.create(pod(REPO, "serve", server=True))
    wait(lab, REPO, "condition=Ready")
    root = lab.kubectl("exec", REPO, "--", "cat", "/tmp/bootstrap.json").stdout
    alternative = lab.kubectl("exec", REPO, "--", "cat", "/tmp/alternative-bootstrap.json").stdout
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-0603-006-root-policy"},
                "immutable": True, "data": {"sha256": sha256(root.encode()).hexdigest()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-0603-006-root"},
                "immutable": True, "data": {"root.json": root, "alternative.json": alternative}})
    lab.create(pod(CLIENT, "verify"))
    wait(lab, CLIENT, "jsonpath={.status.phase}=Succeeded")
    observed = json.loads(lab.kubectl("logs", CLIENT).stdout)
    (lab.evidence / "tuf-client-observations.json").write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n")
    raw = observed["raw_http_returned_alternate"]
    lab.check("red", "Raw HTTP returns alternate fixture bytes without an update verification check", raw,
              {"alternate_target_received_without_integrity_check": raw})
    for label, result in observed["cases"].items():
        lab.check("green", f"The reference client rejects {label} without accepting a target",
                  bool(result["expected_error"]) and result["no_accepted_target"], result)
    blocked_rollback = observed["rollback"]
    lab.check("green", "The seeded client rejects an older signed release and keeps trusted metadata",
              all(blocked_rollback.values()), blocked_rollback)
    rotated = observed["rotation"]
    lab.check("positive", "The reference client accepts root rotation signed by both root delegations",
              rotated["new_root_and_exact_target_verified"], rotated)
    verified = (observed["tuf_version"] == "7.0.1" and observed["accepted"]["target_exact"]
                and observed["accepted"]["target_sha256"] == observed["expected_sha256"])
    lab.check("positive", "The authorized 2-of-3 targets role delivers the exact selected payload",
              verified, {"verified_tuf_version": observed["tuf_version"], **observed["accepted"]})
    bootstrap = observed["bootstrap"]
    lab.check("green", "The separate bootstrap policy accepts the approved version-one root and rejects a different signed version-one root",
              all(bootstrap.values()), bootstrap)
