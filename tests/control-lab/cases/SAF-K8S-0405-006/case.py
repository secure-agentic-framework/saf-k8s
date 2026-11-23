"""Exercise actual artifact read policy independently of Kubernetes admission."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
AUDIENCE = "saf-artifact-fixture"
DEVELOPER = "fixture-artifact-developer"
RELEASE = "fixture-artifact-release"
VERIFIER = "fixture-artifact-verifier"
BASE = "fixture-artifact-baseline"
ENFORCED = "fixture-artifact-enforced"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
SCOPE = (
    "Real Kubernetes TokenReview authenticates scoped projected workload identities. A case-owned "
    "HTTPS artifact service uses approved subject and object attributes to enforce classification, "
    "sensitivity and environment on actual reads. Other stores, attribute authorities and production "
    "traffic paths require independent evidence."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def identity(name):
    return f"system:serviceaccount:{NS}:{name}"


def authority(lab):
    api = "rbac.authorization.k8s.io/v1"
    create(lab, "ServiceAccount", VERIFIER)
    create(lab, "ClusterRole", VERIFIER, api, rules=[
        {"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}])
    create(lab, "ClusterRoleBinding", VERIFIER, api,
           roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": VERIFIER},
           subjects=[{"kind": "ServiceAccount", "name": VERIFIER, "namespace": NS}])


def trust(lab):
    key = lab.kubeconfig.parent / "tls.key"
    cert = lab.kubeconfig.parent / "tls.crt"
    names = ",".join(f"DNS:{item}.{NS}.svc" for item in (BASE, ENFORCED))
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", f"/CN={ENFORCED}.{NS}.svc", "-addext", f"subjectAltName={names}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash", "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", "fixture-artifact-tls", "--key=" + str(key),
                "--cert=" + str(cert), "-o", "name")
    create(lab, "ConfigMap", "fixture-artifact-trust", immutable=True, data={"ca.crt": cert.read_text()})


def setup_policy(lab):
    def artifact(name, classification, sensitivity, environment):
        return {"classification": classification, "sensitivity": sensitivity,
                "environment": environment, "content": f"owned-marker-{name}"}
    policy = {
        "subjects": {
            identity(DEVELOPER): {"classification": ["internal"], "sensitivity": ["ordinary"],
                                  "environment": ["development"]},
            identity(RELEASE): {"classification": ["internal", "restricted"],
                                "sensitivity": ["ordinary", "high"], "environment": ["production"]},
        },
        "artifacts": {
            "development": artifact("development", "internal", "ordinary", "development"),
            "classified": artifact("classified", "restricted", "ordinary", "development"),
            "sensitive": artifact("sensitive", "internal", "high", "development"),
            "production": artifact("production", "internal", "ordinary", "production"),
        },
    }
    create(lab, "ConfigMap", "fixture-artifact-code", immutable=True,
           data={"artifact_service.py": (HERE / "artifact_service.py").read_text(), "policy.json": json.dumps(policy)})


def launch(lab, name, mode=None):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": "fixture-artifact-code"}}]
    if mode:
        who = VERIFIER
        command = ["python3", "/fixture/artifact_service.py", "server", mode]
        mounts.append({"name": "tls", "mountPath": "/certificate", "readOnly": True})
        volumes.append({"name": "tls", "secret": {"secretName": "fixture-artifact-tls", "defaultMode": 0o440}})
    else:
        who = name
        command = ["sleep", "320"]
        create(lab, "ServiceAccount", name, automountServiceAccountToken=False)
        mounts.extend([{"name": "identity", "mountPath": "/identity", "readOnly": True},
                       {"name": "trust", "mountPath": "/trust", "readOnly": True}])
        volumes.extend([{"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                                "path": "token", "audience": AUDIENCE, "expirationSeconds": 600}}]}},
                        {"name": "trust", "configMap": {"name": "fixture-artifact-trust"}}])
    unit = container("guest", image=PYTHON, command=command, volumeMounts=mounts)
    if mode:
        unit["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    request = pod(name, [unit], automountServiceAccountToken=bool(mode), serviceAccountName=who,
                  volumes=volumes, securityContext={"fsGroup": 65534})
    request["metadata"]["labels"] = {"app": name}
    lab.create(request)
    if mode:
        create(lab, "Service", name, spec={
            "selector": {"app": name}, "ports": [{"port": 8443, "targetPort": 8443}]})


def probe(lab, client, service, resource):
    result = lab.kubectl("exec", client, "--", "python3", "/fixture/artifact_service.py",
                         "probe", f"{service}.{NS}.svc", resource, allow_failure=True, timeout=15)
    return json.loads(result.stdout) if result.returncode == 0 else {}


def accepted(result, item):
    return result == {"status": 200, "decision": "approved", "marker": "owned-marker-" + item}


def await_route(lab, service):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if accepted(probe(lab, DEVELOPER, service, "development"), "development"):
            return
        time.sleep(.5)
    lab.block("The fixture authenticator and service route did not return the known public marker")


def run(lab):
    authority(lab)
    trust(lab)
    setup_policy(lab)
    launch(lab, BASE, "baseline")
    launch(lab, ENFORCED, "enforced")
    for client in (DEVELOPER, RELEASE):
        launch(lab, client)
    for name in (BASE, ENFORCED, DEVELOPER, RELEASE):
        ready(lab, name)
    unnecessary = {"classified": "classification", "sensitive": "sensitivity", "production": "environment"}
    await_route(lab, BASE)
    initial = {item: accepted(probe(lab, DEVELOPER, BASE, item), item) for item in unnecessary}
    lab.check("red", "A verified workload can read all three artifacts without the attribute policy",
              all(initial.values()), initial)

    await_route(lab, ENFORCED)
    decisions = {item: probe(lab, DEVELOPER, ENFORCED, item) for item in unnecessary}
    expected = {item: {"status": 403, "decision": field, "marker": None} for item, field in unnecessary.items()}
    lab.check("green", "Only one incompatible attribute suffices to deny the actual artifact read",
              decisions == expected, {"unapproved": decisions})

    approved = {"developer_gets_development": accepted(probe(lab, DEVELOPER, ENFORCED, "development"), "development"),
                "release_gets_production": accepted(probe(lab, RELEASE, ENFORCED, "production"), "production")}
    lab.check("positive", "Both verified workload identities retain reads within their approved context",
              all(approved.values()), approved)
    (lab.evidence / "artifact-attribute-observations.json").write_text(json.dumps({
        "identity_only_baseline": initial, "denied_attributes": decisions, "approved_contexts": approved,
    }, indent=2) + "\n")
