"""Observe API-server trust validation for two distinct extension paths."""
import base64
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
GROUP = "extension-fixture.saf-k8s.example"
APISERVICE = "v1." + GROUP
NAME = "fixture-extension"
WRONG = "fixture-other-extension"
NS = "saf-test"
LABEL = "saf-k8s.example/extension-fixture"
POLICY_DENIAL = "Owned extension deliberately denies this public fixture"
SCOPE = (
    "Separate native Kubernetes admission and API aggregation paths use the same case-owned "
    "HTTPS server. Actual API-server decisions distinguish trusted CA, service DNS identity, "
    "and an explicit admission denial. Workload-to-workload transports, extension-client "
    "authentication, CA reload and production trust policy need independent verification."
)


def root(lab, path, name):
    crt, key = path / f"{name}.crt", path / f"{name}.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(key), "-out", str(crt))
    return crt, key


def certificate(lab, path, approved):
    csr, key, cert = (path / f"fixture-service.{suffix}" for suffix in ("csr", "key", "crt"))
    conf = path / "fixture-extension.ext"
    san = f"{NAME}.{NS}.svc"
    conf.write_text(f"subjectAltName=DNS:{san}\n"
                    "extendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={san}",
                "-keyout", str(key), "-out", str(csr))
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(approved[0]), "-CAkey",
                str(approved[1]), "-CAcreateserial", "-days", "1", "-extfile", str(conf), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", "fixture-extension-tls", "--key=" + str(key),
                "--cert=" + str(cert), "-o", "name")


def endpoint(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-extension-code"},
                "data": {"extension.py": (HERE / "extension.py").read_text()}})
    unit = container("app", image=PYTHON, command=["python3", "/code/extension.py"],
        volumeMounts=[{"name": "tls", "mountPath": "/tls", "readOnly": True},
                      {"name": "code", "mountPath": "/code", "readOnly": True}],
        readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1})
    workload = pod(NAME, [unit], automountServiceAccountToken=False, securityContext={"fsGroup": 65534},
                   volumes=[{"name": "tls", "secret": {"secretName": "fixture-extension-tls", "defaultMode": 0o440}},
                            {"name": "code", "configMap": {"name": "fixture-extension-code"}}])
    workload["metadata"]["labels"] = {"app": NAME}
    lab.create(workload)
    for service in (NAME, WRONG):
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": service},
                    "spec": {"selector": {"app": NAME}, "ports": [{"port": 443, "targetPort": 8443}]}})
    ready(lab, NAME)


def webhook(service, trust):
    return {"name": "fixture-webhook.saf-k8s.example", "admissionReviewVersions": ["v1"],
            "failurePolicy": "Fail", "sideEffects": "None", "timeoutSeconds": 4,
            "clientConfig": {"caBundle": trust, "service": {
                "name": service, "namespace": NS, "path": "/admit", "port": 443}},
            "rules": [{"operations": ["CREATE"], "apiGroups": [""],
                       "apiVersions": ["v1"], "resources": ["configmaps"]}],
            "objectSelector": {"matchLabels": {LABEL: "checked"}}}


def aggregate(service, trust):
    return {"group": GROUP, "version": "v1", "groupPriorityMinimum": 90, "versionPriority": 20,
            "service": {"name": service, "namespace": NS, "port": 443},
            "insecureSkipTLSVerify": False, "caBundle": trust}


def apply_trust(lab, service, trust, initial=False):
    resources = (
        ("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", NAME, {"webhooks": [webhook(service, trust)]}),
        ("apiregistration.k8s.io/v1", "APIService", APISERVICE, {"spec": aggregate(service, trust)}),
    )
    for api, kind, name, fields in resources:
        if initial:
            lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})
        else:
            lab.kubectl("patch", kind, name, "--type=merge", "-p", json.dumps(fields), "-o", "name")


def admission(lab, deny=False):
    data = {"deny": "deliberate-public-marker"} if deny else {"allow": "deliberate-public-marker"}
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": "fixture-admission-probe", "labels": {LABEL: "checked"}}, "data": data},
        dry_run=True, allow_failure=True)


def aggregation(lab):
    out = lab.kubectl("get", "apiservice", APISERVICE, "-o", "json").stdout
    conditions = json.loads(out).get("status", {}).get("conditions") or []
    return next((condition for condition in conditions if condition["type"] == "Available"), {})


def wait_for(lab, signal, expected):
    until = time.monotonic() + 45
    while time.monotonic() < until:
        denial = admission(lab)
        api = aggregation(lab)
        if expected == "allow":
            if denial.returncode == 0 and api.get("status") == "True":
                return {"admission": True, "aggregation": True}
        elif expected == "deny":
            admit_denied = denial.returncode != 0 and signal in denial.stderr and POLICY_DENIAL not in denial.stderr
            api_denied = api.get("status") == "False" and signal in api.get("message", "")
            if admit_denied and api_denied:
                return {"admission": True, "aggregation": True}
        time.sleep(.65)
    return {"admission": False, "aggregation": False}


def run(lab):
    path = lab.kubeconfig.parent
    approved, unrelated = root(lab, path, "fixture-approved-ca"), root(lab, path, "fixture-unrelated-ca")
    certificate(lab, path, approved)
    endpoint(lab)
    pass_ca = base64.b64encode(approved[0].read_bytes()).decode()
    fail_ca = base64.b64encode(unrelated[0].read_bytes()).decode()

    apply_trust(lab, NAME, fail_ca, initial=True)
    first = wait_for(lab, "certificate signed by unknown authority", "deny")
    lab.check("red", "The API server rejects both extension paths when the trust bundle excludes the actual issuer",
              all(first.values()), first)
    apply_trust(lab, WRONG, pass_ca)
    wrong = wait_for(lab, "certificate is valid for", "deny")
    lab.check("green", "The same trusted chain is denied on both paths when the Service DNS name does not match",
              all(wrong.values()), wrong)

    apply_trust(lab, NAME, pass_ca)
    trusted = wait_for(lab, "", "allow")
    blocked = admission(lab, deny=True)
    observed = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "--raw", f"/apis/{GROUP}/v1/fixturemarkers", allow_failure=True, timeout=12)
        if response.returncode == 0 and [
                row["metadata"]["name"] for row in json.loads(response.stdout)["items"]] == ["owned-aggregation-marker"]:
            observed = True
            break
        time.sleep(.5)
    lab.kubectl("logs", NAME, allow_failure=True)
    positive = {"accepted_trusted_admission": trusted["admission"],
                "trusted_api_aggregation_marker_read": trusted["aggregation"] and observed,
                "explicit_valid_webhook_denial": blocked.returncode != 0 and POLICY_DENIAL in blocked.stderr
                and "x509" not in blocked.stderr}
    lab.check("positive", "Both trusted paths work and a valid webhook decision remains distinct from failed TLS",
              all(positive.values()), positive)
    (lab.evidence / "extension-tls-observations.json").write_text(json.dumps({
        "wrong_authority": first, "wrong_endpoint_name": wrong, "correct_tls": positive,
    }, indent=2) + "\n")
