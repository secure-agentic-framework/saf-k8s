"""Check the actual pod-bound identity used by a local authorization boundary."""

import json
from pathlib import Path

SCOPE = "Projected Kubernetes credentials plus a TLS-protected fixture identity mapping; no provider is contacted."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
HOST = "fixture-workload-identity.saf-test.svc.cluster.local"
SERVICE = "fixture-workload-identity"
APPROVED = "fixture-workload-approved"
OTHER = "fixture-workload-other"
SERVER = "fixture-workload-reviewer"
AUDIENCE = "saf-fixture-workload"
RBAC = "rbac.authorization.k8s.io"
PROBE = """
import json, ssl, urllib.error, urllib.request
from pathlib import Path
identity = Path('/identity/token').read_text().strip()
context = ssl.create_default_context(cafile='/trust/server.crt')
query = urllib.request.Request('https://fixture-workload-identity.saf-test.svc.cluster.local:8443/v1/identity',
                               headers={'Authorization': 'Bearer ' + identity})
try:
    with urllib.request.urlopen(query, context=context, timeout=5) as result:
        print(json.dumps({'status': result.status, 'body': json.load(result)}))
except urllib.error.HTTPError as error:
    print(json.dumps({'status': error.code}))
"""


def unit(command, mounts):
    return {"name": "fixture", "image": IMAGE, "command": command, "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "150m", "memory": "72Mi"}}}


def pod(lab, name, account, container, volumes, *, automount=False, labels=None):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": labels or {}}, "spec": {
        "restartPolicy": "Never", "serviceAccountName": account, "automountServiceAccountToken": automount,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container], "volumes": volumes,
    }})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=70s", timeout=80)


def certificates(lab):
    temporary = lab.kubeconfig.parent / "fixture-identity-tls"
    temporary.mkdir(mode=0o700)
    cert, key = temporary / "server.crt", temporary / "server.key"
    lab.command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "generic", SERVICE, f"--from-file={key}", f"--from-file={cert}")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SERVICE},
                "data": {"server.crt": cert.read_text(), "identity.py": Path(__file__).with_name("identity.py").read_text()}})


def start(lab, mode):
    server = unit(["python", "-B", "/source/identity.py", mode], [
        {"name": "source", "mountPath": "/source", "readOnly": True},
        {"name": "server-tls", "mountPath": "/tls", "readOnly": True},
    ])
    server["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    pod(lab, SERVICE, SERVER, server, [{"name": "source", "configMap": {"name": SERVICE}},
                                        {"name": "server-tls", "secret": {"secretName": SERVICE}}],
        labels={"app": SERVICE}, automount=True)


def client(lab, name, account, audience):
    consumer = unit(["python", "-c", "import time; time.sleep(180)"],
                    [{"name": "identity", "mountPath": "/identity", "readOnly": True},
                     {"name": "trust", "mountPath": "/trust", "readOnly": True}])
    pod(lab, name, account, consumer, [
        {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
            "path": "token", "expirationSeconds": 600, "audience": audience}}]}},
        {"name": "trust", "configMap": {"name": SERVICE}},
    ])


def observe(lab, name):
    result = lab.kubectl("exec", "pod/" + name, "--", "python", "-c", PROBE, allow_failure=True)
    if result.returncode != 0:
        lab.block("The fixture identity service did not return a verifiable result")
    return json.loads(result.stdout)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    for account in (APPROVED, OTHER, SERVER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account},
                    "automountServiceAccountToken": False})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRole", "metadata": {"name": SERVER},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRoleBinding", "metadata": {"name": SERVER},
                "roleRef": {"apiGroup": RBAC, "kind": "ClusterRole", "name": SERVER},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": SERVER}]})
    certificates(lab)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                "spec": {"selector": {"app": SERVICE}, "ports": [{"port": 8443, "targetPort": 8443}]}})
    start(lab, "shared")
    client(lab, "fixture-approved", APPROVED, AUDIENCE)
    client(lab, "fixture-alternate", OTHER, AUDIENCE)
    client(lab, "fixture-wrong-audience", APPROVED, "saf-other-audience")
    broad = observe(lab, "fixture-alternate")["status"] == 200
    lab.check("red", "The initial shared workload mapping accepts the separately issued alternate identity",
              broad, {"alternate_initially_mapped": broad})
    lab.kubectl("delete", "pod", SERVICE, "--wait=true", "--grace-period=1")
    start(lab, "scoped")
    other_denied = observe(lab, "fixture-alternate")["status"] == 403
    audience_denied = observe(lab, "fixture-wrong-audience")["status"] == 401
    lab.check("green", "The scoped mapping rejects the separate valid subject and the wrong audience",
              other_denied and audience_denied, {"alternate_subject_denied": other_denied, "wrong_audience_denied": audience_denied})
    allowed = observe(lab, "fixture-approved")
    expected = {"status": 200, "body": {"provider_principal": "fixture-workload-role", "public_marker": "authorized fixture"}}
    lab.check("positive", "The approved projected identity resolves to the intended local principal",
              allowed == expected, {"approved_identity_mapped": allowed == expected})
    (lab.evidence / "workload-identity-observations.json").write_text(json.dumps({
        "identity_mapping": allowed, "alternate_subject_rejected": other_denied, "wrong_audience_rejected": audience_denied,
        "actual_provider_issuance_tested": False,
    }, indent=2) + "\n")
