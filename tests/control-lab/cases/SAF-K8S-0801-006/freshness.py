"""Verify elapsed evidence validity in the Kubernetes admission request path."""

import base64
import json
from pathlib import Path
import tempfile
import time

NAMESPACE = "saf-test"
SERVICE = "fixture-reuse-freshness"
WEBHOOK = "freshness.reuse-fixture.example"
HERE = Path(__file__).resolve().parent
INVALID = "fixture reuse evidence has invalid validity"
FUTURE = "fixture reuse evidence is not yet valid"
EXPIRED = "fixture reuse evidence expired"


def install_identity(lab, record_name):
    rbac = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": SERVICE}})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": SERVICE},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "resourceNames": [record_name], "verbs": ["get"]}]})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": SERVICE},
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": SERVICE},
                "subjects": [{"kind": "ServiceAccount", "name": SERVICE, "namespace": NAMESPACE}]})


def install_tls(lab, root):
    ca_key, ca = root / "ca.key", root / "ca.crt"
    leaf_key, leaf_csr, leaf = root / "tls.key", root / "tls.csr", root / "tls.crt"
    host = f"{SERVICE}.{NAMESPACE}.svc"
    extensions = root / "server.ext"
    extensions.write_text(f"subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n"
                          "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n",
                          encoding="ascii")
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(ca_key), "-out", str(ca), "-days", "1",
                "-subj", "/CN=SAF fixture reuse CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(leaf_key), "-out", str(leaf_csr), "-subj", f"/CN={host}")
    lab.command("openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(leaf), "-days", "1", "-extfile", str(extensions))
    lab.command("openssl", "verify", "-CAfile", str(ca), "-purpose", "sslserver", str(leaf))
    lab.kubectl("create", "secret", "tls", SERVICE, "--cert", str(leaf), "--key", str(leaf_key))
    return base64.b64encode(ca.read_bytes()).decode("ascii")


def install_webhook(lab, image, record_name, workload):
    install_identity(lab, record_name)
    with tempfile.TemporaryDirectory(prefix="saf-reuse-tls-") as directory:
        ca_bundle = install_tls(lab, Path(directory))
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SERVICE}, "immutable": True,
                "data": {"webhook.py": (HERE / "expiry-webhook.py").read_text(encoding="utf-8")}})
    labels = {"app": SERVICE}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": SERVICE, "labels": labels},
                "spec": {"serviceAccountName": SERVICE, "automountServiceAccountToken": False,
                         "restartPolicy": "Never",
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                             "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{
                             "name": "webhook", "image": image, "imagePullPolicy": "IfNotPresent",
                             "command": ["python", "-B", "/code/webhook.py"],
                             "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}},
                             "ports": [{"containerPort": 8443}],
                             "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                             "resources": {"requests": {"cpu": "5m", "memory": "24Mi"},
                                           "limits": {"cpu": "200m", "memory": "64Mi"}},
                             "volumeMounts": [
                                 {"name": "code", "mountPath": "/code", "readOnly": True},
                                 {"name": "tls", "mountPath": "/tls", "readOnly": True},
                                 {"name": "identity", "mountPath": "/identity", "readOnly": True},
                             ],
                         }],
                         "volumes": [
                             {"name": "code", "configMap": {"name": SERVICE}},
                             {"name": "tls", "secret": {"secretName": SERVICE, "defaultMode": 0o440}},
                             {"name": "identity", "projected": {"defaultMode": 0o440, "sources": [
                                 {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                                 {"configMap": {"name": "kube-root-ca.crt",
                                                "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                             ]}},
                         ]}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                "spec": {"selector": labels, "ports": [{"port": 443, "targetPort": 8443}]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{SERVICE}", "--timeout=45s", timeout=55)
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
                "metadata": {"name": SERVICE}, "webhooks": [{
                    "name": WEBHOOK, "admissionReviewVersions": ["v1"], "sideEffects": "None",
                    "failurePolicy": "Fail", "matchPolicy": "Exact", "timeoutSeconds": 5,
                    "namespaceSelector": {"matchLabels": {"fixture.example/platform": "true"}},
                    "matchConditions": [{"name": "fixture-request",
                                         "expression": f"has(object.metadata.name) && object.metadata.name == '{workload}'"}],
                    "clientConfig": {"service": {"name": SERVICE, "namespace": NAMESPACE, "port": 443,
                                                 "path": "/validate"}, "caBundle": ca_bundle},
                    "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"],
                               "scope": "Namespaced", "operations": ["CREATE"]}],
                }]})


def expected_denial(response, reason):
    indicator = f'admission webhook "{WEBHOOK}" denied the request: {reason}'
    return response.returncode != 0 and indicator in response.stderr


def set_validity(lab, name, issued, expires):
    patch = {"data": {"issued-at": str(issued), "expires-at": str(expires)}}
    result = lab.kubectl("patch", "configmap", name, "--type=merge", "--patch", json.dumps(patch), "-o", "json")
    return json.loads(result.stdout)


def run(lab, manifest, submit, image, record_name):
    workload = manifest["metadata"]["name"]
    install_webhook(lab, image, record_name, workload)
    deadline = time.monotonic() + 20
    while True:
        if expected_denial(submit(lab, manifest), INVALID):
            break
        if time.monotonic() >= deadline:
            lab.block("The fixture did not observe the named webhook deny an approval with missing validity")
        time.sleep(0.4)

    now = int(time.time())
    set_validity(lab, record_name, now + 35, now + 65)
    not_yet_valid = expected_denial(submit(lab, manifest), FUTURE)

    # The API-backed record must remain exactly the same across the expiry boundary.
    now = int(time.time())
    expires = now + 10
    original = set_validity(lab, record_name, now - 5, expires)
    allowed = submit(lab, manifest).returncode == 0
    time.sleep(max(0, expires + 0.5 - time.time()))
    expired_dry_run = expected_denial(submit(lab, manifest), EXPIRED)
    expired_live = expected_denial(submit(lab, manifest, dry_run=False), EXPIRED)
    absence = lab.kubectl("get", "pod", workload, "-o", "name", "--ignore-not-found").stdout.strip() == ""
    record = json.loads(lab.kubectl("get", "configmap", record_name, "-o", "json").stdout)
    same_record = (
        original["metadata"]["uid"] == record["metadata"]["uid"]
        and original["metadata"]["resourceVersion"] == record["metadata"]["resourceVersion"]
        and original["data"] == record["data"]
    )

    now = int(time.time())
    set_validity(lab, record_name, now - 5, now + 60)
    renewed = submit(lab, manifest).returncode == 0
    observed = {"missing_validity_denied_by_named_webhook": True,
                "future_dated_record_denied_by_named_webhook": not_yet_valid,
                "exact_request_admitted_before_expiry": allowed,
                "same_dry_run_denied_by_named_webhook_after_expiry": expired_dry_run,
                "live_create_denied_by_named_webhook_after_expiry": expired_live,
                "no_pod_persisted_after_denial": absence,
                "same_uid_resource_version_and_data_across_expiry": same_record,
                "exact_request_admitted_after_approval_renewal": renewed}
    (lab.evidence / "sanitization-release-expiry-observations.json").write_text(
        json.dumps(observed, indent=2, sort_keys=True) + "\n")
    lab.check("evidence-expiry", "Unchanged approved evidence expires in the live Pod admission path",
              all(observed.values()), observed)
