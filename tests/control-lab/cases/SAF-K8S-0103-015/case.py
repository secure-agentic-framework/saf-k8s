"""Exercise an authenticated live kube-scheduler extender and scheduler admission."""

import json
from pathlib import Path
import time

SCOPE = "A separate Kubernetes scheduler uses mutual TLS to one inert authorized extender route in disposable Kind."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
SCHEDULER_IMAGE = "registry.k8s.io/kube-scheduler:v1.36.1@sha256:3a4333e8ba6e1f74c9bc467c791a06a26808474e8819582cf130cfe0fddc3155"
RBAC = "rbac.authorization.k8s.io"
ADMISSION = "admissionregistration.k8s.io/v1"
SCHEDULER = "fixture-approved-scheduler"
EXTENDER = "fixture-extender"
NS = "saf-test"
HOST = f"{EXTENDER}.{NS}.svc.cluster.local"
PEER = "fixture-scheduler-peer"
MESSAGE = "Fixture scheduler requires an approved profile"


def provision_certificates(lab):
    directory = lab.kubeconfig.parent / "extender-tls"
    directory.mkdir(mode=0o700)
    ca = directory / "ca.crt"
    ca_key = directory / "ca.key"
    lab.command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SAF disposable scheduler CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(ca_key), "-out", str(ca))
    for role, subject in (("server", HOST), ("client", PEER)):
        cert, key, csr, ext = (directory / f"{role}.{suffix}" for suffix in ("crt", "key", "csr", "ext"))
        usage = "serverAuth" if role == "server" else "clientAuth"
        ext.write_text(f"extendedKeyUsage={usage}\n" + (f"subjectAltName=DNS:{HOST}\n" if role == "server" else ""))
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={subject}", "-keyout", str(key), "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", "2", "-extfile", str(ext), "-out", str(cert))
        lab.kubectl("create", "secret", "generic", f"fixture-extender-{role}", f"--from-file={ca}",
                    f"--from-file={cert}", f"--from-file={key}")


def make_pod(lab, name, image, command, *, files=(), scheduler=None, authenticated=False, allow_failure=False):
    volumes = []
    mounts = []
    for path, source, key in files:
        volume = path.removeprefix("/")
        mounts.append({"name": volume, "mountPath": path, "readOnly": True})
        volumes.append({"name": volume, source: {"name" if source == "configMap" else "secretName": key}})
    unit = {"name": "unit", "image": image, "command": command, "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "20Mi"},
                          "limits": {"cpu": "450m", "memory": "240Mi"}}}
    if name == EXTENDER:
        unit["readinessProbe"] = {"tcpSocket": {"port": 9443}, "periodSeconds": 1}
    spec = {"restartPolicy": "Never", "automountServiceAccountToken": authenticated,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "volumes": volumes}
    if authenticated:
        spec["serviceAccountName"] = SCHEDULER
    if scheduler:
        spec["schedulerName"] = scheduler
    return lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"app": name}},
                       "spec": spec}, dry_run=allow_failure, allow_failure=allow_failure)


def start(lab):
    provision_certificates(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": EXTENDER},
                "data": {"extender.py": Path(__file__).with_name("extender.py").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": EXTENDER},
                "spec": {"selector": {"app": EXTENDER}, "ports": [{"port": 9443, "targetPort": 9443}]}})
    make_pod(lab, EXTENDER, IMAGE, ["python", "-B", "/program/extender.py"],
             files=[("/program", "configMap", EXTENDER), ("/tls", "secret", "fixture-extender-server")])
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + EXTENDER, "--timeout=60s", timeout=70)

    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": SCHEDULER}})
    for role in ("system:kube-scheduler", "system:volume-scheduler"):
        lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRoleBinding",
                    "metadata": {"name": f"{SCHEDULER}-{role.split(':')[1]}"},
                    "roleRef": {"apiGroup": RBAC, "kind": "ClusterRole", "name": role},
                    "subjects": [{"kind": "ServiceAccount", "namespace": NS, "name": SCHEDULER}]})
    credential_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
    kubeconfig = {"apiVersion": "v1", "kind": "Config", "current-context": "fixture", "clusters": [{
        "name": "local", "cluster": {"server": "https://kubernetes.default.svc",
                                     "certificate-authority": f"{credential_dir}/ca.crt"}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "local", "user": "fixture"}}],
        "users": [{"name": "fixture", "user": {"tokenFile": f"{credential_dir}/token"}}]}
    config = {"apiVersion": "kubescheduler.config.k8s.io/v1", "kind": "KubeSchedulerConfiguration",
              "clientConnection": {"kubeconfig": "/config/kubeconfig.json"},
              "leaderElection": {"leaderElect": False}, "profiles": [{"schedulerName": SCHEDULER}],
              "extenders": [{"urlPrefix": f"https://{HOST}:9443", "filterVerb": "filter",
                             "enableHTTPS": True, "nodeCacheCapable": False, "ignorable": False, "httpTimeout": "4s",
                             "tlsConfig": {"caFile": "/tls/ca.crt", "certFile": "/tls/client.crt",
                                           "keyFile": "/tls/client.key", "serverName": HOST}}]}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SCHEDULER},
                "data": {"scheduler.json": json.dumps(config), "kubeconfig.json": json.dumps(kubeconfig)}})
    make_pod(lab, SCHEDULER, SCHEDULER_IMAGE,
             ["/usr/local/bin/kube-scheduler", "--config=/config/scheduler.json", "--secure-port=0"],
             files=[("/config", "configMap", SCHEDULER), ("/tls", "secret", "fixture-extender-client")],
             authenticated=True)


def set_admission(lab):
    lab.create({"apiVersion": ADMISSION, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": SCHEDULER},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"],
                }]}, "validations": [{
                    "expression": f"has(object.spec.schedulerName) && object.spec.schedulerName in ['default-scheduler', '{SCHEDULER}']",
                    "message": MESSAGE,
                }]}})
    lab.create({"apiVersion": ADMISSION, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": SCHEDULER},
                "spec": {"policyName": SCHEDULER, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/scheduler-review": "true"}}}}})


def run(lab):
    lab.kubectl("label", "namespace", NS, "fixture.example/scheduler-review=true", "pod-security.kubernetes.io/enforce=restricted")
    marker = ["python", "-c", "print('scheduled public marker')"]
    unapproved = lambda: make_pod(lab, "fixture-unapproved-pod", IMAGE, marker,
                                   scheduler="unapproved-scheduler", allow_failure=True)
    baseline = unapproved().returncode == 0
    lab.check("red", "An unapproved scheduler name is admitted before the explicit inventory policy",
              baseline, {"unapproved_scheduler_initially_admitted": baseline})
    set_admission(lab)
    deadline = time.monotonic() + 20
    denied = False
    while time.monotonic() < deadline:
        result = unapproved()
        if result.returncode != 0 and MESSAGE in result.stderr:
            denied = True
            break
        time.sleep(0.5)
    lab.check("green", "Admission rejects an unapproved scheduler profile", denied, {"policy_denied": denied})

    start(lab)
    name = "fixture-approved-pod"
    make_pod(lab, name, IMAGE, marker, scheduler=SCHEDULER)
    lab.kubectl("wait", "--for=condition=PodScheduled", "pod/" + name, "--timeout=80s", timeout=90)
    item = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    logs = lab.kubectl("logs", "pod/" + EXTENDER).stdout
    calls = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    expected = {"peer": PEER, "pod": name, "path": "/filter", "allowed": True}
    observed = expected in calls and item["spec"]["schedulerName"] == SCHEDULER and bool(item["spec"].get("nodeName"))
    lab.check("positive", "The real scheduler binds the fixture after an authorized mutually authenticated extender call",
              observed, {"approved_scheduler_bound": observed, "mutually_authenticated_call": expected in calls})
    (lab.evidence / "scheduler-extender-observations.json").write_text(json.dumps({
        "unapproved_scheduler_denied": denied, "accepted_peer": PEER, "endpoint_authorization_observed": observed,
        "fixture_bound": bool(item["spec"].get("nodeName")), "production_extender_tested": False,
    }, indent=2) + "\n")
