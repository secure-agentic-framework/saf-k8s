"""Verify scoped admission-time Ed25519 signatures on inert ConfigMaps."""
from base64 import b64encode
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
WEBHOOK = "saf-signature-webhook"
OBJECT = "signed-fixture"
POD_OBJECT = "signed-inert-workload"
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
    "An additive, namespaced core/v1 Pod CREATE comparison uses server-side dry-run only and signs the complete Pod spec. "
    "Trust custody, other meaningful metadata, all resources and production submission paths remain open."
)


def object_template(payload=ORIGINAL):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": OBJECT, "namespace": NAMESPACE,
                         "labels": {"saf.example.test/purpose": "inert-signature-fixture"}},
            "data": {"payload": payload}, "binaryData": {"fixture": "U0FG"}}


def canonical_preimage(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode()


def pod_template():
    """One inert Pod request; it is only ever submitted as server-side dry-run."""
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POD_OBJECT, "namespace": NAMESPACE,
                     "labels": {"saf.example.test/purpose": "inert-signature-workload"}},
        "spec": {
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "fixture", "image": "registry.invalid/saf-fixture/workload:v1",
                "imagePullPolicy": "IfNotPresent", "command": ["/fixture-marker"],
                "terminationMessagePath": "/dev/termination-log",
                "terminationMessagePolicy": "File",
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "capabilities": {"drop": ["ALL"]},
                                     "runAsNonRoot": True, "runAsUser": 65534,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
            }],
            "dnsPolicy": "ClusterFirst", "enableServiceLinks": True,
            "restartPolicy": "Never", "schedulerName": "default-scheduler",
            "serviceAccountName": "default", "terminationGracePeriodSeconds": 5,
            "securityContext": {"runAsNonRoot": True,
                                "seccompProfile": {"type": "RuntimeDefault"}},
        },
    }


def _sorted_json(value):
    if isinstance(value, dict):
        return {key: _sorted_json(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_sorted_json(row) for row in value]
    return value


def canonical_pod_preimage(obj):
    projection = {
        "apiVersion": obj["apiVersion"], "kind": obj["kind"],
        "metadata": {"name": obj["metadata"]["name"],
                     "namespace": obj["metadata"]["namespace"],
                     "labels": _sorted_json(obj["metadata"].get("labels", {}))},
        "spec": obj["spec"],
    }
    # Go encoding/json sorts all map keys while preserving this struct field order.
    projection["spec"] = _sorted_json(projection["spec"])
    return json.dumps(projection, separators=(",", ":"), ensure_ascii=True).encode()


def signed(obj, directory, signer, version):
    obj["metadata"]["annotations"] = {
        KEY: signer, SIGNATURE: (directory / f"{signer}-{version}.sig").read_text(),
    }
    return obj


def signed_pod(obj, directory, signer="authorized-test"):
    obj["metadata"]["annotations"] = {
        KEY: signer, SIGNATURE: (directory / f"{signer}-pod-create.sig").read_text(),
    }
    return obj


def fixture_material(lab, folder, defaulted_pod):
    folder.mkdir(mode=0o700)
    for stage, payload in (("create", ORIGINAL), ("update", UPDATED)):
        (folder / f"{stage}-projection.json").write_bytes(canonical_preimage(object_template(payload)))
    (folder / "pod-create-projection.json").write_bytes(canonical_pod_preimage(defaulted_pod))
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
            }, {
                "operations": ["CREATE"], "apiGroups": [""],
                "apiVersions": ["v1"], "resources": ["pods"],
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


def workload_pod_dry_run(lab, material, defaulted_pod):
    unsigned = lab.create(defaulted_pod, dry_run=True, allow_failure=True)
    approved_request = signed_pod(deepcopy(defaulted_pod), material)
    approved = lab.create(approved_request, dry_run=True, allow_failure=True)
    changed_request = deepcopy(defaulted_pod)
    changed_request["spec"]["containers"][0]["command"] = ["/fixture-marker", "--revision=two"]
    changed_request = signed_pod(changed_request, material)
    changed = lab.create(changed_request, dry_run=True, allow_failure=True)

    expected_preimage = canonical_pod_preimage(defaulted_pod)
    expected_digest = sha256(expected_preimage).hexdigest()
    changed_digest = sha256(canonical_pod_preimage(changed_request)).hexdigest()
    approved_response = json.loads(approved.stdout) if approved.returncode == 0 else {}
    server_projection_matches = (approved.returncode == 0 and
                                 canonical_pod_preimage(approved_response) == expected_preimage)
    absent = lab.kubectl("get", "pod", POD_OBJECT, "-o", "json", allow_failure=True)
    pod_not_persisted = absent.returncode != 0 and "NotFound" in absent.stderr

    raw_log = lab.kubectl("logs", f"deployment/{WEBHOOK}").stdout
    pattern = re.compile(
        r'resource="pods" operation="CREATE" dry_run=true '
        r'object_json_sha256=([a-f0-9]{64}) projection_sha256=([a-f0-9]{64}) '
        r'allowed=(true|false) decision="([^"]+)"'
    )
    observed = []
    for line in raw_log.splitlines():
        match = pattern.search(line)
        if match:
            _, projection_digest, allowed, decision = match.groups()
            observed.append([projection_digest, allowed == "true", decision])
    (lab.evidence / "webhook-decisions.log").write_text(raw_log)
    expected = [
        [expected_digest, False, "signature is absent"],
        [expected_digest, True, "authorized signature verified"],
        [changed_digest, False, MISMATCH],
    ]
    (lab.evidence / "typed-pod-signature-projection.json").write_text(json.dumps({
        "projection_scope": ["apiVersion", "kind", "metadata.name", "metadata.namespace",
                             "metadata.labels", "spec"],
        "normalization": "API-defaulted complete spec, with no spec fields omitted",
        "approved_projection_sha256": expected_digest,
        "mutated_projection_sha256": changed_digest,
        "admission_decisions": observed,
        "pod_persisted": not pod_not_persisted,
    }, indent=2, sort_keys=True) + "\n")
    condition = (unsigned.returncode != 0 and "signature is absent" in unsigned.stderr
                 and approved.returncode == 0 and server_projection_matches
                 and changed.returncode != 0 and MISMATCH in changed.stderr
                 and pod_not_persisted and observed == expected)
    lab.check("green", "A typed signature admits the inert Pod dry-run and denies a changed signed spec",
              condition,
              {"unsigned_create_denied": unsigned.returncode != 0 and "signature is absent" in unsigned.stderr,
               "approved_create_dry_run_admitted": approved.returncode == 0,
               "defaulted_server_projection_matches": server_projection_matches,
               "changed_spec_denied": changed.returncode != 0 and MISMATCH in changed.stderr,
               "pod_not_persisted": pod_not_persisted,
               "exact_dry_run_decisions": observed == expected})


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
    baseline_pod = lab.create(pod_template(), dry_run=True)
    defaulted_pod = {
        "apiVersion": baseline_pod["apiVersion"], "kind": baseline_pod["kind"],
        "metadata": {key: baseline_pod["metadata"][key] for key in ("name", "namespace", "labels")},
        "spec": baseline_pod["spec"],
    }
    fixture_material(lab, material, defaulted_pod)
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
        "unrelated-test-create.sig", "authorized-test-update.sig", "authorized-test-pod-create.sig",
        "create-projection.json", "update-projection.json", "pod-create-projection.json",
        "webhook-ca.crt", "tls.crt",
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
    workload_pod_dry_run(lab, material, defaulted_pod)
