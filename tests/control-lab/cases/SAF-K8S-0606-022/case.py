"""Verify scoped admission-time Ed25519 signatures on inert ConfigMaps."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
WEBHOOK = "saf-signature-webhook"
OBJECT = "signed-fixture"
SIGNATURE = "saf.example.test/signature"
KEY = "saf.example.test/signature-key"
ORIGINAL = "hello from approved fixture"
UPDATED = "a second approved fixture revision"
MISMATCH = "signature does not verify over the signed field projection"
SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster with an HTTPS validating webhook. "
    "Ed25519 protects canonical JSON for apiVersion, kind, name, namespace, labels, data, binaryData "
    "and an optional immutable field on the selected ConfigMaps. Tests real CREATE and UPDATE, "
    "absent authorization, an unrelated valid signer, and changes to signed data and binaryData. "
    "Trust custody, other meaningful metadata, all resources and production submission paths remain open."
)


def object_template(payload=ORIGINAL):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": OBJECT, "namespace": NAMESPACE,
                         "labels": {"saf.example.test/purpose": "inert-signature-fixture"}},
            "data": {"payload": payload}, "binaryData": {"fixture": "U0FG"}}


def canonical_preimage(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode()


def signed(obj, directory, signer, version):
    obj["metadata"]["annotations"] = {
        KEY: signer, SIGNATURE: (directory / f"{signer}-{version}.sig").read_text(),
    }
    return obj


def fixture_material(lab, folder):
    folder.mkdir(mode=0o700)
    for stage, payload in (("create", ORIGINAL), ("update", UPDATED)):
        (folder / f"{stage}-projection.json").write_bytes(canonical_preimage(object_template(payload)))
    lab.command("env", "GOTOOLCHAIN=local", "GOPROXY=off", "CGO_ENABLED=0", "GOFLAGS=",
                "go", "run", "-trimpath", str(HERE / "webhook.go"), "generate-fixtures",
                str(folder), timeout=120)


def container_image(lab, folder):
    node = f"node/{lab.cluster}-control-plane"
    arch = lab.kubectl("get", node, "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if arch not in {"amd64", "arm64"}:
        lab.block(f"Unsupported Kind node architecture: {arch}")
    folder.mkdir(mode=0o700)
    lab.command("env", "GOTOOLCHAIN=local", "GOPROXY=off", "CGO_ENABLED=0", "GOFLAGS=",
                "GOOS=linux", f"GOARCH={arch}", "go", "build", "-trimpath", "-o",
                str(folder / "webhook"), str(HERE / "webhook.go"), timeout=120)
    (folder / "Dockerfile").write_text("FROM scratch\nCOPY webhook /webhook\n")
    image = f"saf-signature-fixture:{lab.cluster}"
    lab.command("docker", "build", "--network", "none", "--pull=false", "--platform", f"linux/{arch}",
                "-t", image, str(folder), timeout=120)
    try:
        lab.command("kind", "load", "docker-image", "--name", lab.cluster, image, timeout=120)
    finally:
        lab.command("docker", "image", "rm", image)
    return image


def admission_configuration(ca_pem):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": "saf-signed-configmaps"},
        "webhooks": [{
            "name": "signature.saf.example.test",
            "admissionReviewVersions": ["v1"],
            "sideEffects": "None",
            "failurePolicy": "Fail",
            "matchPolicy": "Equivalent",
            "timeoutSeconds": 5,
            "clientConfig": {
                "service": {"namespace": NAMESPACE, "name": WEBHOOK, "path": "/validate", "port": 443},
                "caBundle": b64encode(ca_pem).decode("ascii"),
            },
            "namespaceSelector": {"matchLabels": {"saf.example.test/signature-enforcement": "required"}},
            "rules": [{
                "operations": ["CREATE", "UPDATE"],
                "apiGroups": [""],
                "apiVersions": ["v1"],
                "resources": ["configmaps"],
                "scope": "Namespaced",
            }],
        }],
    }


def denied(lab, label, result, message):
    reason = result.stderr.strip()
    (lab.evidence / f"{label}-api.json").write_text(json.dumps({
        "returncode": result.returncode, "stdout": result.stdout, "stderr": reason,
    }, indent=2) + "\n")
    exact = result.returncode == 1 and "signature.saf.example.test" in reason and message in reason
    lab.check("green", f"The webhook gives the expected denial for {label}", exact,
              {"returncode": result.returncode, "expected_decision": message, "decision_matches": exact})


def deploy(lab, material, image):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": WEBHOOK + "-keys"},
                "immutable": True, "data": {f"{signer}-public.pem":
                    (material / f"{signer}-public.pem").read_text()
                    for signer in ("authorized-test", "unrelated-test")}})
    leaf = material / "tls.key"
    try:
        lab.kubectl("create", "secret", "tls", WEBHOOK + "-tls",
                    f"--cert={material / 'tls.crt'}", f"--key={leaf}")
    finally:
        leaf.unlink()
    labels = {"app": WEBHOOK}
    security = {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": WEBHOOK},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "automountServiceAccountToken": False, "securityContext": security,
                     "volumes": [
                         {"name": "keys", "configMap": {"name": WEBHOOK + "-keys"}},
                         {"name": "tls", "secret": {"secretName": WEBHOOK + "-tls"}},
                     ],
                     "containers": [{
                         "name": "webhook", "image": image, "command": ["/webhook"],
                         "imagePullPolicy": "Never", "ports": [{"name": "https", "containerPort": 8443}],
                         "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/healthz",
                                                        "port": "https"}, "periodSeconds": 1},
                         "volumeMounts": [
                             {"name": "tls", "mountPath": "/tls", "readOnly": True},
                             {"name": "keys", "mountPath": "/fixtures", "readOnly": True},
                         ],
                         "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                     }],
                 }}},
    })
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": WEBHOOK},
                "spec": {"selector": labels, "ports": [{"name": "https", "port": 443, "targetPort": "https"}]}})
    lab.kubectl("rollout", "status", f"deployment/{WEBHOOK}", "--timeout=60s", timeout=70)
    lab.create(admission_configuration((material / "webhook-ca.crt").read_bytes()))
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        ready = lab.create(object_template(), dry_run=True, allow_failure=True)
        if ready.returncode and "signature is absent" in ready.stderr:
            return
        time.sleep(0.5)
    lab.block("The Kubernetes API did not return the expected webhook denial")


def replace(lab, obj, resource_version):
    obj["metadata"]["resourceVersion"] = resource_version
    return lab.kubectl("replace", "-f", "-", "-o", "json", payload=json.dumps(obj), allow_failure=True)


def get_object(lab):
    return json.loads(lab.kubectl("get", "configmap", OBJECT, "-o", "json").stdout)


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf.example.test/signature-enforcement=required", "--overwrite")
    unsigned = object_template()
    baseline = lab.create(unsigned)
    lab.check("red", "The same unsigned ConfigMap persists before the webhook is installed",
              baseline["data"] == unsigned["data"] and baseline["binaryData"] == unsigned["binaryData"],
              {"name": baseline["metadata"]["name"], "data": baseline["data"], "binary_data": baseline["binaryData"]})
    lab.kubectl("delete", "configmap", OBJECT, "--wait=true")

    material = lab.kubeconfig.parent / "materials"
    fixture_material(lab, material)
    image = container_image(lab, lab.kubeconfig.parent / "image")
    deploy(lab, material, image)
    denied(lab, "unsigned-create", lab.create(object_template(), allow_failure=True), "signature is absent")
    untrusted = signed(object_template(), material, "unrelated-test", "create")
    denied(lab, "unrelated-signer", lab.create(untrusted, allow_failure=True),
           "signature is valid but signer is not authorized")
    altered = signed(object_template(), material, "authorized-test", "create")
    altered["binaryData"]["fixture"] = "U0FGMg=="
    denied(lab, "altered-binary-create", lab.create(altered, allow_failure=True), MISMATCH)

    approved = signed(object_template(), material, "authorized-test", "create")
    accepted = lab.create(approved)
    lab.check("positive", "The authorized signature accepts and stores the exact signed ConfigMap",
              get_object(lab)["data"] == approved["data"] and accepted["binaryData"] == approved["binaryData"],
              {"data": accepted["data"], "binary_data": accepted["binaryData"]})

    resource_version = accepted["metadata"]["resourceVersion"]
    tampered = signed(object_template(UPDATED), material, "authorized-test", "create")
    denied(lab, "altered-data-update", replace(lab, tampered, resource_version), MISMATCH)
    after = get_object(lab)
    lab.check("green", "A denied update leaves the approved ConfigMap and resource version unchanged",
              after["metadata"]["resourceVersion"] == resource_version and after["data"] == approved["data"],
              {"payload": after["data"]["payload"], "resource_version_unchanged":
                  after["metadata"]["resourceVersion"] == resource_version})

    approved_update = signed(object_template(UPDATED), material, "authorized-test", "update")
    update_result = replace(lab, approved_update, resource_version)
    stored = get_object(lab)
    lab.check("positive", "A fresh authorized signature admits the exact updated payload",
              update_result.returncode == 0 and stored["data"] == approved_update["data"]
              and stored["binaryData"] == approved_update["binaryData"],
              {"returncode": update_result.returncode, "payload": stored["data"]["payload"]})

    raw_log = lab.kubectl("logs", f"deployment/{WEBHOOK}").stdout
    (lab.evidence / "webhook-decisions.log").write_text(raw_log)
    public = {filename: (material / filename).read_text() for filename in (
        "authorized-test-public.pem", "unrelated-test-public.pem", "authorized-test-create.sig",
        "unrelated-test-create.sig", "authorized-test-update.sig", "create-projection.json",
        "update-projection.json", "webhook-ca.crt", "tls.crt",
    )}
    (lab.evidence / "public-signature-evidence.json").write_text(json.dumps(public, indent=2) + "\n")
    seen = []
    for line in raw_log.splitlines():
        matched = re.search(r'resource="configmaps" operation="(CREATE|UPDATE)" dry_run=false '
                            r'object_json_sha256=([a-f0-9]{64}) projection_sha256=([a-f0-9]{64}) '
                            r'allowed=(true|false) decision="([^"]+)"', line)
        if matched:
            operation, _, digest, allowed, decision = matched.groups()
            seen.append([operation, digest, allowed == "true", decision])
    create = sha256(canonical_preimage(object_template())).hexdigest()
    update = sha256(canonical_preimage(object_template(UPDATED))).hexdigest()
    changed = object_template()
    changed["binaryData"]["fixture"] = "U0FGMg=="
    changed_digest = sha256(canonical_preimage(changed)).hexdigest()
    expected = [
        ["CREATE", create, False, "signature is absent"],
        ["CREATE", create, False, "signature is valid but signer is not authorized"],
        ["CREATE", changed_digest, False, MISMATCH],
        ["CREATE", create, True, "authorized signature verified"],
        ["UPDATE", update, False, MISMATCH],
        ["UPDATE", update, True, "authorized signature verified"],
    ]
    lab.check("green", "Real AdmissionReviews match every expected operation, signed projection and decision",
              seen == expected, {"decisions": seen})
