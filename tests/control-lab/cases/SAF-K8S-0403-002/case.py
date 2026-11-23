"""Exercise real External Secrets Operator reconciliation and consumption."""

import base64
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
OPERATOR_NS = "fixture-eso"
OPERATOR_SA = "fixture-eso-sync"
SOURCE = "fixture-secret-source"
SERVER = SOURCE + "." + NS + ".svc"
TARGET = "fixture-synced-marker"
APP = "fixture-synced-reader"
LABEL = "saf.example.org/synced-secret-policy"
POLICY = "fixture-controller-secret.saf.example.org"
DENY = "the designated synchronized fixture Secret is managed by its approved controller"
OLD, NEW = "public-provider-version-one", "public-provider-version-two"
CHART_VERSION = "2.15.0"
CHART_SHA = "ed94d41cc67e392ea45e370345eb491b0fdc21387f1aaaefcf8e2e6c85089e1d"
IMAGE_TAG = "v2.15.0@sha256:6888f243e5f8f7592c6d7fae2a5547c9e33531441b47b53807b9093b25a00e31"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
SCOPE = (
    "Test External Secrets Operator against a separate, disposable HTTPS provider with public "
    "markers. Verify an approved controller write, synchronized Secret, actual application "
    "directory read, source failure indication and recovery. Managed cloud stores, CSI direct "
    "mounts, authority-side actual credential rotation and production provider audit are separate."
)


def operator(lab, temp):
    lab.command("helm", "pull", "external-secrets", "--repo", "https://charts.external-secrets.io",
                "--version", CHART_VERSION, "--destination", str(temp), timeout=90)
    chart = temp / f"external-secrets-{CHART_VERSION}.tgz"
    if hashlib.sha256(chart.read_bytes()).hexdigest() != CHART_SHA:
        lab.block("External Secrets Operator chart digest did not match the reviewed version")
    lab.command("helm", "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                "upgrade", "--install", "fixture-eso", str(chart), "--namespace", OPERATOR_NS,
                "--create-namespace", "--set-string", f"serviceAccount.name={OPERATOR_SA}",
                "--set-string", f"image.tag={IMAGE_TAG}", "--set-string", f"webhook.image.tag={IMAGE_TAG}",
                "--set-string", f"certController.image.tag={IMAGE_TAG}", "--wait", "--timeout", "160s", timeout=175)


def start_source(lab, temp):
    cert, key = temp / "provider.pem", temp / "provider-key.pem"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=" + SERVER, "-addext", "subjectAltName=DNS:" + SERVER,
                "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(key), "-out", str(cert))
    # Only the resource name is returned; the temporary key is never printed.
    lab.kubectl("create", "secret", "tls", SOURCE, "--cert=" + str(cert), "--key=" + str(key), "-o", "name")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SOURCE},
                "data": {"server.py": (HERE / "provider.py").read_text(), "value": OLD, "available": "yes"}})
    unit = container("service", image=PYTHON, command=["python3", "/source/server.py"], volumeMounts=[
        {"name": "input", "mountPath": "/source", "readOnly": True},
        {"name": "tls", "mountPath": "/tls", "readOnly": True}])
    provider = pod(SOURCE, [unit], automountServiceAccountToken=False, securityContext={"fsGroup": 65534},
                   volumes=[{"name": "input", "configMap": {"name": SOURCE}},
                            {"name": "tls", "secret": {"secretName": SOURCE, "defaultMode": 0o440}}])
    provider["metadata"]["labels"] = {"app": SOURCE}
    lab.create(provider)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SOURCE},
                "spec": {"selector": {"app": SOURCE}, "ports": [{"port": 9443, "targetPort": 9443}]}})
    ready(lab, SOURCE)
    return base64.b64encode(cert.read_bytes()).decode()


def install_policy(lab):
    lab.kubectl("label", "namespace", NS, f"{LABEL}=true")
    api = "admissionregistration.k8s.io/v1"
    actor = f"system:serviceaccount:{OPERATOR_NS}:{OPERATOR_SA}"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["secrets"]}]},
                    "validations": [{"expression": f"object.metadata.name != '{TARGET}' || request.userInfo.username == '{actor}'",
                                     "message": DENY}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {LABEL: "true"}}}}})


def poll(lab, probe, expected, context, seconds=65):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        now = probe()
        if now == expected:
            return
        time.sleep(1)
    lab.block(context)


def current(lab):
    value = lab.kubectl("get", "secret/" + TARGET, "--ignore-not-found",
                        "-o", "jsonpath={.data.value}", allow_failure=True).stdout.strip()
    return base64.b64decode(value).decode() if value else ""


def condition(lab):
    row = lab.kubectl("get", "externalsecret/" + TARGET,
                      "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}", allow_failure=True)
    return row.stdout.strip()


def change_source(lab, value, alive, tag):
    lab.kubectl("patch", "configmap/" + SOURCE, "--type=merge", "-p", json.dumps({
        "data": {"value": value, "available": "yes" if alive else "no"}}), "-o", "name")
    lab.kubectl("annotate", "pod/" + SOURCE, "saf.example.org/source-stage=" + tag, "--overwrite")
    def sync_probe():
        result = lab.kubectl("exec", SOURCE, "--", "cat", "/source/value", "/source/available", allow_failure=True)
        return result.stdout if result.returncode == 0 else ""
    poll(lab, sync_probe, value + ("yes" if alive else "no"), "The owned provider did not observe its source configuration")
    lab.kubectl("annotate", "externalsecret/" + TARGET, "force-sync=" + str(time.time_ns()), "--overwrite")


def run(lab):
    with TemporaryDirectory(prefix="saf-eso-fixture-") as directory:
        temp = Path(directory)
        operator(lab, temp)
        ca = start_source(lab, temp)

    direct = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": TARGET},
              "stringData": {"value": "public-manual-marker"}}
    manual_baseline = lab.create(direct, dry_run=True, allow_failure=True).returncode == 0
    missing_initially = current(lab) == ""
    lab.check("red", "Before the policy and reconciliation, a manual write is allowed and no synchronized Secret exists",
              manual_baseline and missing_initially, {"manual_dry_run_accepted": manual_baseline, "initial_copy_missing": missing_initially})
    install_policy(lab)
    def denied():
        result = lab.create(direct, dry_run=True, allow_failure=True)
        return result.returncode != 0 and POLICY in result.stderr and DENY in result.stderr
    poll(lab, denied, True, "The scoped policy did not deny the manual target write", seconds=30)

    api = "external-secrets.io/v1"
    lab.create({"apiVersion": api, "kind": "SecretStore", "metadata": {"name": SOURCE},
                "spec": {"provider": {"webhook": {"url": f"https://{SERVER}:9443/{{{{ .remoteRef.key }}}}",
                    "method": "GET", "timeout": "3s", "result": {"jsonPath": "$.value"}, "caBundle": ca}}}})
    lab.create({"apiVersion": api, "kind": "ExternalSecret", "metadata": {"name": TARGET},
                "spec": {"refreshPolicy": "Periodic", "refreshInterval": "5s",
                         "secretStoreRef": {"name": SOURCE, "kind": "SecretStore"},
                         "target": {"name": TARGET, "creationPolicy": "Owner", "deletionPolicy": "Retain"},
                         "data": [{"secretKey": "value", "remoteRef": {"key": "fixture-value"}}]}})
    poll(lab, lambda: current(lab), OLD, "The approved controller did not synchronize the first value")
    poll(lab, lambda: condition(lab), "True", "The ExternalSecret did not report successful reconciliation")
    owner = lab.kubectl("get", "secret/" + TARGET, "-o", "jsonpath={.metadata.ownerReferences[0].kind}").stdout.strip()
    lab.check("green", "The manual API write is denied while the real controller creates an owned synchronized copy",
              owner == "ExternalSecret", {"manual_target_write_denied": True, "controller_copy_owned": owner == "ExternalSecret"})

    unit = container("reader", command=["sh", "-c", "sleep 420"], volumeMounts=[
        {"name": "fixture", "mountPath": "/delivery", "readOnly": True}])
    lab.create(pod(APP, [unit], automountServiceAccountToken=False,
                   volumes=[{"name": "fixture", "secret": {"secretName": TARGET}}]))
    ready(lab, APP)
    def app_value():
        result = lab.kubectl("exec", APP, "--", "cat", "/delivery/value", allow_failure=True)
        return result.stdout if result.returncode == 0 else ""
    first = app_value() == OLD
    change_source(lab, OLD, False, "unavailable")
    poll(lab, lambda: condition(lab), "False", "Source outage did not appear as a failed reconciliation")
    retained = current(lab) == OLD and app_value() == OLD
    change_source(lab, NEW, True, "recovered")
    poll(lab, lambda: current(lab), NEW, "Recovery did not synchronize the next value")
    poll(lab, lambda: condition(lab), "True", "The ExternalSecret did not recover its Ready condition")
    lab.kubectl("annotate", "pod/" + APP, "saf.example.org/refresh-reader=after-recovery")
    poll(lab, app_value, NEW, "The running reader did not observe the recovered synchronized value")
    lab.check("positive", "A real source outage is visible while the last copy remains, and recovery updates the running reader",
              first and retained, {"first_value_delivered": first, "failed_reconciliation_observed": True,
               "retained_while_unavailable": retained, "recovered_reader": True})
    (lab.evidence / "external-secrets-observations.json").write_text(json.dumps({
        "controller_chart": CHART_VERSION, "chart_sha256": CHART_SHA, "controller_image": IMAGE_TAG,
        "initial_copy_missing": missing_initially, "manual_target_write_denied": True, "target_owner": owner,
        "real_https_provider": True, "source_failure_condition_seen": True, "last_copy_retained": retained,
        "running_reader_updated_after_recovery": True, "actual_credential_rotation_tested": False,
    }, indent=2) + "\n")
