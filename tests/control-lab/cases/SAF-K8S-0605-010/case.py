"""Verify bounded admission and ordinary replacement of a fixture CRD webhook."""
from base64 import b64encode
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
GROUP = "availability.saf-fixture.example.test"
NS = "saf-test"
NAME = "saf-reliability"
HOOK = f"{NAME}.example.test"
RESOURCES = {"requests": {"cpu": "10m", "memory": "24Mi"},
             "limits": {"cpu": "100m", "memory": "64Mi"}}
SCOPE = (
    "One disposable Kind cluster and a case-owned inert CRD. Single sequential server-side "
    "dry-run requests measure ordinary validation, serving availability during individual "
    "pod replacement, and fail-closed response during controlled endpoint removal. "
    "Production traffic sizing, capacity and vendor configurations require separate evidence."
)


def certificates(lab):
    path = lab.kubeconfig.parent / "webhook-reliability"
    path.mkdir(mode=0o700)
    ca, ca_key = path / "ca.crt", path / "ca.key"
    leaf, leaf_key = path / "tls.crt", path / "tls.key"
    dns = f"{NAME}.{NS}.svc"
    csr, ext = path / "leaf.csr", path / "leaf.ext"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SAF fixture admission root", "-keyout", str(ca_key), "-out", str(ca),
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={dns}",
                "-keyout", str(leaf_key), "-out", str(csr))
    ext.write_text(f"subjectAltName=DNS:{dns}\nbasicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-set_serial", "1", "-extfile", str(ext), "-days", "2", "-out", str(leaf))
    lab.kubectl("create", "secret", "tls", NAME, "--cert", str(leaf), "--key", str(leaf_key))
    return b64encode(ca.read_bytes()).decode()


def install_crd(lab):
    resource = f"checks.{GROUP}"
    lab.create({
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": resource},
        "spec": {"group": GROUP, "scope": "Namespaced", "names": {"plural": "checks", "singular": "check", "kind": "Check"},
                 "versions": [{"name": "v1", "served": True, "storage": True, "schema": {"openAPIV3Schema": {
                     "type": "object", "required": ["spec"], "properties": {
                         "spec": {"type": "object", "required": ["enabled"],
                                  "properties": {"enabled": {"type": "boolean"}}},
                     },
                 }}}]},
    })
    lab.kubectl("wait", "--for=condition=Established", f"crd/{resource}", "--timeout=30s", timeout=40)


def install_service(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "immutable": True,
                "data": {"webhook.py": (HERE / "webhook.py").read_text()}})
    selector = {"app": NAME}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": NAME},
        "spec": {"replicas": 2, "minReadySeconds": 1,
                 "selector": {"matchLabels": selector},
                 "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1}},
                 "template": {"metadata": {"labels": selector}, "spec": {
                     "automountServiceAccountToken": False, "terminationGracePeriodSeconds": 3,
                     "containers": [{
                         "name": "webhook", "image": PYTHON, "command": ["python", "-B", "/fixture/webhook.py"],
                         "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8443, "scheme": "HTTPS"},
                                            "initialDelaySeconds": 13, "periodSeconds": 1},
                         "resources": RESOURCES,
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                             "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                         "env": [{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}],
                         "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True},
                                          {"name": "code", "mountPath": "/fixture", "readOnly": True}],
                     }],
                     "volumes": [{"name": "tls", "secret": {"secretName": NAME}},
                                 {"name": "code", "configMap": {"name": NAME}}],
                 }}},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": NAME}, "spec": {
        "type": "ClusterIP", "selector": selector, "ports": [{"port": 443, "targetPort": 8443}],
    }})
    lab.kubectl("rollout", "status", f"deployment/{NAME}", "--timeout=80s", timeout=90)


def configure_webhook(lab, ca):
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": NAME}, "webhooks": [{
            "name": HOOK, "admissionReviewVersions": ["v1"], "sideEffects": "None",
            "failurePolicy": "Fail", "timeoutSeconds": 3,
            "clientConfig": {"service": {"namespace": NS, "name": NAME, "path": "/validate", "port": 443},
                             "caBundle": ca},
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}},
            "rules": [{"apiGroups": [GROUP], "apiVersions": ["v1"], "resources": ["checks"],
                       "operations": ["CREATE"], "scope": "Namespaced"}],
        }],
    })


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def endpoints(lab):
    slices = get(lab, "endpointslices", "-l", f"kubernetes.io/service-name={NAME}")["items"]
    return {endpoint["targetRef"]["uid"]: endpoint["targetRef"]["name"] for item in slices
            for endpoint in (item.get("endpoints") or []) if endpoint["conditions"].get("ready") and "targetRef" in endpoint}


def wait_endpoints(lab, predicate):
    end = time.monotonic() + 35
    while time.monotonic() < end:
        rows = endpoints(lab)
        if predicate(rows):
            return rows
        time.sleep(0.4)
    lab.block("The owned webhook did not reach the expected Ready endpoint state")


def probe(lab, name, enabled=True):
    return lab.create({"apiVersion": f"{GROUP}/v1", "kind": "Check", "metadata": {"name": name},
                       "spec": {"enabled": enabled}}, dry_run=True, allow_failure=True)


def receipt(lab, name, ready):
    for uid, pod in ready.items():
        data = lab.kubectl("logs", pod, allow_failure=True)
        if data.returncode:
            continue
        events = (json.loads(line) for line in data.stdout.splitlines() if line.startswith("{"))
        if any(event == {"probe": name, "allowed": True, "pod_uid": uid} for event in events):
            return uid
    return None


def replace_one(lab, ready, index, old):
    lab.kubectl("delete", "pod", ready[old], "--wait=false")
    lab.kubectl("wait", "--for=delete", f"pod/{ready[old]}", "--timeout=18s", timeout=24)
    survivors = wait_endpoints(lab, lambda rows: len(rows) == 1 and old not in rows)
    name = f"{NAME}-replacement-{index}"
    called = probe(lab, name)
    served = receipt(lab, name, survivors)
    acceptable = called.returncode == 0 and served in survivors
    lab.kubectl("rollout", "status", f"deployment/{NAME}", "--timeout=65s", timeout=75)
    recovered = wait_endpoints(lab, lambda rows: len(rows) == 2 and old not in rows)
    new, = set(recovered) - set(survivors)
    readback = get(lab, "deployment", NAME)["status"]
    healthy = readback.get("readyReplicas") == readback.get("availableReplicas") == 2
    lab.check("green", "The verified survivor serves admission during ordinary replacement",
              acceptable and healthy, {"replacement": index, "one_ready_endpoint_during": len(survivors) == 1,
                           "survivor_handled_request": acceptable, "two_ready_endpoints_after": healthy and len(recovered) == 2})
    return recovered, {"old": old, "serving": served, "new": new}


def run(lab):
    install_crd(lab)
    base = probe(lab, f"{NAME}-baseline", enabled=False)
    lab.check("red", "The disabled fixture field is admitted before webhook enforcement",
              base.returncode == 0, {"admitted_without_webhook": base.returncode == 0})
    ca = certificates(lab)
    install_service(lab)
    ready = wait_endpoints(lab, lambda rows: len(rows) == 2)
    configure_webhook(lab, ca)
    # Wait on the frozen configuration and endpoint state, then send single serial fixture requests.
    readback = get(lab, "validatingwebhookconfiguration", NAME)["webhooks"][0]
    time.sleep(2)
    rejected = probe(lab, f"{NAME}-disabled", enabled=False)
    denied = rejected.returncode != 0 and HOOK in rejected.stderr and "selected fixture field is disabled" in rejected.stderr
    pods = get(lab, "pods", "-l", f"app={NAME}")["items"]
    limited = len(pods) == 2 and all(pod["spec"]["containers"][0]["resources"] == RESOURCES for pod in pods)
    configured = limited and readback["timeoutSeconds"] == 3 and readback["failurePolicy"] == "Fail"
    if not denied:
        for name in ready.values():
            lab.kubectl("logs", name, allow_failure=True)
    lab.check("green", "The live CRD webhook denies the fixture field with the intended timeout and resource budget",
              denied and configured, {"explicit_policy_denial": denied, "expected_live_settings": configured})
    okay = probe(lab, f"{NAME}-ready")
    first_contact = receipt(lab, f"{NAME}-ready", ready)
    lab.check("positive", "A valid admitted request is confirmed by an active fixture backend",
              okay.returncode == 0 and first_contact in ready, {"serving_fixture_verified": first_contact in ready})

    old_first, old_second = sorted(ready)
    ready, first = replace_one(lab, ready, 1, old_first)
    ready, second = replace_one(lab, ready, 2, old_second)
    lab.kubectl("scale", f"deployment/{NAME}", "--replicas=0")
    lab.kubectl("wait", "--for=delete", *(f"pod/{pod}" for pod in ready.values()), "--timeout=25s", timeout=31)
    wait_endpoints(lab, lambda rows: not rows)
    absent = probe(lab, f"{NAME}-no-endpoint")
    failure = absent.stderr.lower()
    transport = any(reason in failure for reason in ("no endpoints available", "connection refused",
                                                      "context deadline exceeded", "i/o timeout"))
    failed = absent.returncode != 0 and HOOK in absent.stderr and "failed calling webhook" in failure and transport
    lab.kubectl("scale", f"deployment/{NAME}", "--replicas=2")
    lab.kubectl("rollout", "status", f"deployment/{NAME}", "--timeout=65s", timeout=75)
    final = wait_endpoints(lab, lambda rows: len(rows) == 2)
    restored = probe(lab, f"{NAME}-restored")
    verified = restored.returncode == 0 and receipt(lab, f"{NAME}-restored", final) in final
    lab.check("positive", "A single request fails closed without endpoints and admission recovers after restoration",
              failed and verified, {"no_endpoint_request_denied": failed, "restored_admission_confirmed": verified})
    (lab.evidence / "webhook-replacements.json").write_text(json.dumps({
        "resources": RESOURCES, "failure_policy": readback["failurePolicy"], "timeout": readback["timeoutSeconds"],
        "replacement_records": [first, second], "restored_ready_endpoints": len(final),
    }, indent=2, sort_keys=True) + "\n")
