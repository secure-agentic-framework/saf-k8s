"""Native admission enforcement for two administrator-assigned AI lifecycle profiles."""
import hashlib
import base64
import json
from pathlib import Path
import subprocess
import time


HERE = Path(__file__).parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
PYTHON_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
TRAIN_NS = "saf-0905-015-train-lock"
LEARN_NS = "saf-0905-015-continuous"
APP = "saf-k8s.example/ai-system"
PROFILE = "saf-k8s.example/lifecycle-profile"
IMAGE = PYTHON_IMAGE
TRAIN_POLICY = "saf-0905-015-train-profile"
LEARN_POLICY = "saf-0905-015-learning-profile"
TRAIN_DENIAL = "train-verify-lock profile requires integrity baseline and monitor"
LEARN_DENIAL = "continuous-learning profile requires authorized updater and drift monitor"
SIGNED_WEBHOOK = "saf-0905-015-signed-verifier"
VERIFY_NS = "saf-0905-015-unassigned"
SCOPE = (
    "One fresh Kubernetes v1.36.1 kind cluster. Two administrator-labeled namespaces assign "
    "train-verify-lock and continuous-learning profiles. Kubernetes ValidatingAdmissionPolicies "
    "and namespace-selected bindings validate Deployment pod templates on CREATE and UPDATE. "
    "Matched missing-profile probes and permitted non-AI Deployments are independently checked "
    "in both namespaces. Each valid profile Deployment executes a fixed, inert Python fixture: "
    "the train-lock init container writes fixed bytes and a SHA-256 baseline consumed by an "
    "integrity monitor; the continuous-learning init container writes one fixed synthetic "
    "before/after pair and its drift monitor measures the difference. No model, external service, "
    "network service, host port, or real authorization system is used."
)


def _container(name, command, mounts):
    return {
        "name": name,
        "image": IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["python", "-u", "-c", command],
        "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "100m", "memory": "64Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True, "runAsNonRoot": True,
                             "runAsUser": 10001,
                             "capabilities": {"drop": ["ALL"]}},
        "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
    }


def deployment(name, profile, *, complete=True, ai=True, mismatch=False):
    labels = {APP: "true"} if ai else {"app": "harmless-positive"}
    labels["app.kubernetes.io/name"] = name
    if profile:
        labels[PROFILE] = profile
    spec = {
        "automountServiceAccountToken": False,
        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}, "fsGroup": 10001},
        "containers": [],
        "volumes": [{"name": "model-state", "emptyDir": {}}],
    }
    mount_rw = [{"name": "model-state", "mountPath": "/model"}]
    mount_ro = [{"name": "model-state", "mountPath": "/model", "readOnly": True}]
    if profile == "train-verify-lock":
        spec["initContainers"] = [_container(
            "integrity-baseline",
            "from pathlib import Path; import hashlib; p=Path('/model/payload.bin'); " +
            ("p.write_bytes(b'SAF synthetic altered fixture\\n'); " if mismatch else
             "p.write_bytes(b'SAF synthetic inert model bytes v1\\n'); ") +
            "Path('/model/baseline.sha256').write_text(hashlib.sha256(b'SAF synthetic inert model bytes v1\\n').hexdigest()); "
            "print('baseline_sha256='+Path('/model/baseline.sha256').read_text())",
            mount_rw)] if complete else []
        spec["containers"] = [_container(
            "integrity-monitor",
            "from pathlib import Path; import hashlib; p=Path('/model/payload.bin'); "
            "expected=Path('/model/baseline.sha256').read_text(); actual=hashlib.sha256(p.read_bytes()).hexdigest(); "
            "candidate=hashlib.sha256(b'SAF altered inert bytes\\n').hexdigest(); "
            "print('integrity_ok='+str(actual==expected)); print('integrity_sha256='+actual); "
            "print('tamper_counterfactual_detected='+str(candidate!=expected)); "
            "import time; time.sleep(3600)",
            mount_ro)]
    elif profile == "continuous-learning":
        spec["initContainers"] = [_container(
            "authorized-model-updater",
            "from pathlib import Path; p=Path('/model/payload.bin'); "
            "Path('/model/before.bin').write_bytes(b'SAF synthetic inert model bytes v1\\n'); "
            "p.write_bytes(b'SAF synthetic inert model bytes v2 approved fixture\\n'); "
            "print('update_authorized=true fixture=change-001 sha256='+__import__('hashlib').sha256(p.read_bytes()).hexdigest())",
            mount_rw)] if complete else []
        spec["containers"] = [_container(
            "drift-monitor",
            "from pathlib import Path; import hashlib; p=Path('/model/payload.bin'); "
            "previous=Path('/model/before.bin').read_bytes(); current=p.read_bytes(); "
            "print('model_drift_observed='+str(int(previous != current))+' model_sha256='+hashlib.sha256(current).hexdigest()); "
            "import time; time.sleep(3600)",
            mount_ro)]
    else:
        spec["containers"] = [_container("inert", "print('harmless workload')", [])]
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": TRAIN_NS if profile == "train-verify-lock" else LEARN_NS,
                     "labels": labels},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": spec}},
    }


def _policy(name, profile, expression, message):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{"apiGroups": ["apps"],
                "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                "resources": ["deployments"], "scope": "Namespaced"}]},
            "validations": [{"expression": (
                f"'{PROFILE}' in object.spec.template.metadata.labels && "
                f"object.spec.template.metadata.labels['{PROFILE}'] == '{profile}' && ({expression})"
            ), "message": message, "reason": "Forbidden"}],
        },
    }


def _binding(name, policy, namespace_label):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {"policyName": policy, "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {"matchLabels": namespace_label}}},
    }


def _install(lab):
    train_ok = (
        "has(object.spec.template.spec.initContainers) && "
        f"object.spec.template.spec.initContainers.exists(c, c.name == 'integrity-baseline' && c.image == '{IMAGE}' && "
        "c.volumeMounts.exists(m, m.name == 'model-state' && m.mountPath == '/model')) && "
        f"object.spec.template.spec.containers.exists(c, c.name == 'integrity-monitor' && c.image == '{IMAGE}' && "
        "c.volumeMounts.exists(m, m.name == 'model-state' && m.mountPath == '/model' && m.readOnly == true))"
    )
    def update_value(resource):
        key = "saf-k8s.example/update"
        annotations = f"{resource}.metadata.annotations"
        return f"(has({annotations}) && '{key}' in {annotations} ? {annotations}['{key}'] : '')"

    learn_ok = (
        "has(object.spec.template.spec.initContainers) && "
        f"object.spec.template.spec.initContainers.exists(c, c.name == 'authorized-model-updater' && c.image == '{IMAGE}' && "
        "c.volumeMounts.exists(m, m.name == 'model-state' && m.mountPath == '/model')) && "
        f"object.spec.template.spec.containers.exists(c, c.name == 'drift-monitor' && c.image == '{IMAGE}' && "
        "c.volumeMounts.exists(m, m.name == 'model-state' && m.mountPath == '/model' && m.readOnly == true)) && "
        f"(request.operation != 'UPDATE' || (object.spec.template == oldObject.spec.template && "
        f"{update_value('object')} == {update_value('oldObject')}) || "
        f"request.userInfo.username == 'system:serviceaccount:{LEARN_NS}:saf-model-update-authorizer')"
    )
    resources = [
        _policy(TRAIN_POLICY, "train-verify-lock", train_ok, TRAIN_DENIAL),
        _binding(TRAIN_POLICY, TRAIN_POLICY, {"saf-k8s.example/lifecycle": "train-verify-lock"}),
        _policy(LEARN_POLICY, "continuous-learning", learn_ok, LEARN_DENIAL),
        _binding(LEARN_POLICY, LEARN_POLICY, {"saf-k8s.example/lifecycle": "continuous-learning"}),
    ]
    manifest = "\n---\n".join(json.dumps(item) for item in resources)
    lab.kubectl("apply", "-f", "-", payload=manifest)


def _namespace(lab, name, lifecycle):
    lab.kubectl("create", "namespace", name)
    lab.kubectl("label", "namespace", name, f"saf-k8s.example/lifecycle={lifecycle}")


def _server_create(lab, obj):
    return lab.kubectl("-n", obj["metadata"]["namespace"], "create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def _denied(result, policy, denial):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and f"ValidatingAdmissionPolicy '{policy}'" in result.stderr
            and denial in result.stderr)


def _observation(label, result, policy, denial):
    return {"probe": label, "admitted": result.returncode == 0,
            "denied_by_expected_policy": _denied(result, policy, denial),
            "detail": result.stderr.strip()}


def _wait_ready(lab, namespace, name):
    lab.kubectl("-n", namespace, "rollout", "status", f"deployment/{name}",
                "--timeout=90s", timeout=100)


def _pod_name(lab, namespace, name):
    result = json.loads(lab.kubectl("-n", namespace, "get", "pods", "-o", "json").stdout)
    # Deployment selectors use the AI labels, so use owner reference to identify its pod.
    for pod in result.get("items", []):
        if any(ref.get("kind") == "ReplicaSet" for ref in pod.get("metadata", {}).get("ownerReferences", [])):
            owner = json.loads(lab.kubectl("-n", namespace, "get", "rs", pod["metadata"]["ownerReferences"][0]["name"], "-o", "json").stdout)
            if any(ref.get("kind") == "Deployment" and ref.get("name") == name for ref in owner.get("metadata", {}).get("ownerReferences", [])):
                return pod["metadata"]["name"]
    lab.block(f"No pod found for Deployment {name}")


def _monitor_log(lab, namespace, pod, container, marker):
    deadline = time.monotonic() + 15
    text = ""
    while time.monotonic() < deadline:
        text = lab.kubectl("-n", namespace, "logs", pod, "-c", container).stdout
        if marker in text:
            return text
        time.sleep(0.2)
    return text


def _signed_annotations(fixture):
    return {
        "saf.example.test/model-digest": "sha256:" + fixture["manifest_sha256"],
        "saf.example.test/model-signature": fixture["manifest_signature_base64"],
        "saf.example.test/attestations": json.dumps(
            fixture["attestations"], separators=(",", ":"), sort_keys=True),
    }


def _signed_admission_configuration(ca_pem):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": SIGNED_WEBHOOK},
        "webhooks": [{
            "name": "signed-model-marker.saf.example.test",
            "admissionReviewVersions": ["v1"], "sideEffects": "None",
            "failurePolicy": "Fail", "matchPolicy": "Equivalent", "timeoutSeconds": 5,
            "clientConfig": {"service": {"namespace": VERIFY_NS, "name": SIGNED_WEBHOOK,
                                            "path": "/validate", "port": 443},
                             "caBundle": base64.b64encode(ca_pem).decode("ascii")},
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/lifecycle": "train-verify-lock"}},
            "rules": [{"operations": ["CREATE"], "apiGroups": ["apps"],
                       "apiVersions": ["v1"], "resources": ["deployments"], "scope": "Namespaced"}],
        }],
    }


def _install_signed_verifier(lab, fixture):
    def create(resource):
        return lab.kubectl("-n", VERIFY_NS, "create", "-f", "-", payload=json.dumps(resource))

    material_dir = lab.kubeconfig.parent / "0905-015-tls-material"
    material_dir.mkdir(mode=0o700)
    cert, key = material_dir / "tls.crt", material_dir / "tls.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "2",
                "-subj", f"/CN={SIGNED_WEBHOOK}.{VERIFY_NS}.svc",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", f"subjectAltName=DNS:{SIGNED_WEBHOOK}.{VERIFY_NS}.svc,DNS:{SIGNED_WEBHOOK}.{VERIFY_NS}.svc.cluster.local")
    try:
        lab.kubectl("-n", VERIFY_NS, "create", "secret", "tls", SIGNED_WEBHOOK + "-tls",
                    f"--cert={cert}", f"--key={key}")
    finally:
        key.unlink(missing_ok=True)
    source_name = SIGNED_WEBHOOK + "-source"
    create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": source_name, "namespace": VERIFY_NS},
                "data": {"webhook.py": (HERE / "webhook.py").read_text(encoding="utf-8"),
                         "fixtures.json": json.dumps(fixture, sort_keys=True)}})
    labels = {"app": SIGNED_WEBHOOK}
    create({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": SIGNED_WEBHOOK, "namespace": VERIFY_NS},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                         "runAsGroup": 10001, "fsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "source", "configMap": {"name": source_name}},
                                 {"name": "tls", "secret": {"secretName": SIGNED_WEBHOOK + "-tls"}}],
                     "containers": [{"name": "verifier", "image": PYTHON_IMAGE,
                                     "command": ["python", "/app/webhook.py"],
                                     "imagePullPolicy": "IfNotPresent",
                                     "ports": [{"name": "https", "containerPort": 8443}],
                                     "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/healthz",
                                                                      "port": "https"}, "periodSeconds": 1},
                                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                   "limits": {"cpu": "100m", "memory": "96Mi"}},
                                     "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True},
                                                      {"name": "tls", "mountPath": "/tls", "readOnly": True}],
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}],
                 }}}})
    create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": SIGNED_WEBHOOK, "namespace": VERIFY_NS},
                "spec": {"selector": labels, "ports": [{"name": "https", "port": 443,
                                                            "targetPort": "https"}]}})
    lab.kubectl("-n", VERIFY_NS, "rollout", "status", f"deployment/{SIGNED_WEBHOOK}",
                "--timeout=60s", timeout=70)
    lab.create(_signed_admission_configuration(cert.read_bytes()))
    cert.unlink(missing_ok=True)
    material_dir.rmdir()


def _signed_marker_deployment(fixture, name, image_reference=None):
    obj = deployment(name, "train-verify-lock")
    obj["spec"]["replicas"] = 0
    obj["metadata"]["annotations"] = _signed_annotations(fixture)
    containers = obj["spec"]["template"]["spec"]["containers"]
    containers.append({"name": "signed-model-marker",
                       "image": image_reference or fixture["model_image_reference"],
                       "imagePullPolicy": "Never"})
    return obj


def _signed_marker_boundary(lab):
    fixture = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    fixture["namespace"] = TRAIN_NS
    fixture["model_image_reference"] = (
        "saf.example.test/models/inert-fixture@sha256:" + fixture["manifest_sha256"])
    _install_signed_verifier(lab, fixture)

    good_name = "signed-marker-approved"
    good_obj = _signed_marker_deployment(fixture, good_name)
    admitted = json.loads(lab.kubectl("-n", TRAIN_NS, "create", "-f", "-", "-o", "json",
                                      payload=json.dumps(good_obj)).stdout)
    persisted = json.loads(lab.kubectl("-n", TRAIN_NS, "get", "deployment", good_name,
                                       "-o", "json").stdout)
    exact_image = any(c.get("name") == "signed-model-marker"
                      and c.get("image") == fixture["model_image_reference"]
                      and c.get("imagePullPolicy") == "Never"
                      for c in persisted["spec"]["template"]["spec"]["containers"])
    labels = persisted["spec"]["selector"]["matchLabels"]
    selector = ",".join(f"{key}={value}" for key, value in sorted(labels.items()))
    no_pods = not json.loads(lab.kubectl("-n", TRAIN_NS, "get", "pods", "-l", selector,
                                         "-o", "json").stdout)["items"]
    good_ok = (admitted.get("metadata", {}).get("name") == good_name
               and persisted.get("spec", {}).get("replicas") == 0 and exact_image and no_pods)
    lab.kubectl("-n", TRAIN_NS, "delete", "deployment", good_name, "--wait=true")

    bad_signature_obj = _signed_marker_deployment(fixture, "signed-marker-bad-signature")
    bad_signature_obj["metadata"]["annotations"]["saf.example.test/model-signature"] = "AA=="
    bad_signature = lab.kubectl("-n", TRAIN_NS, "create", "-f", "-", "--dry-run=server",
                               payload=json.dumps(bad_signature_obj), allow_failure=True)
    signature_denied = (bad_signature.returncode != 0
                        and "SAF fixture verifier: model signature is absent or does not match the fixed signer"
                        in bad_signature.stderr)

    wrong_binding_obj = _signed_marker_deployment(
        fixture, "signed-marker-wrong-binding",
        "saf.example.test/models/inert-fixture@sha256:" + "0" * 64)
    wrong_binding = lab.kubectl("-n", TRAIN_NS, "create", "-f", "-", "--dry-run=server",
                               payload=json.dumps(wrong_binding_obj), allow_failure=True)
    binding_denied = (wrong_binding.returncode != 0
                      and "SAF fixture verifier: model image reference does not match signed marker"
                      in wrong_binding.stderr)
    lab.check("positive", "CREATE admission verifies the fixed signature and binds it to the exact zero-replica inert image reference",
              good_ok and signature_denied and binding_denied,
              {"approved_signature_and_digest_admitted": good_ok,
               "approved_deployment_persisted": admitted.get("metadata", {}).get("name") == good_name,
               "replicas_zero": persisted.get("spec", {}).get("replicas") == 0,
               "image_reference_matches_signed_manifest": exact_image,
               "no_pod_created_or_image_pulled": no_pods,
               "wrong_signature_denied": signature_denied,
               "image_digest_rebound_without_signature_denied": binding_denied})


def _authorized_release_patch(lab, name):
    base = ("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}")
    def private_call(*args):
        result = subprocess.run((*base, *args), text=True, capture_output=True,
                                env=lab.env, timeout=25)
        if result.returncode or not result.stdout.strip():
            lab.block("Could not prepare the fixture's short-lived release identity")
        return result.stdout.strip()
    token = private_call("-n", LEARN_NS, "create", "token", "saf-model-update-authorizer", "--duration=10m")
    config = json.loads(private_call("config", "view", "--raw", "--minify", "-o", "json"))
    config["users"] = [{"name": "fixture-release-identity", "user": {"token": token}}]
    config["contexts"][0]["context"]["user"] = "fixture-release-identity"
    path = lab.kubeconfig.parent / "fixture-release-identity.kubeconfig"
    path.touch(mode=0o600, exist_ok=False)
    patch = json.dumps([
        {"op": "add", "path": "/metadata/annotations/saf-k8s.example~1update",
         "value": "release-v2-approved-fixture"},
        {"op": "add", "path": "/spec/template/spec/containers/0/env/-",
         "value": {"name": "SAF_RELEASE_MARKER", "value": "v2-approved-fixture"}},
    ], separators=(",", ":"))
    try:
        path.write_text(json.dumps(config))
        return lab.command("kubectl", "--kubeconfig", str(path), "--context", f"kind-{lab.cluster}",
                           "-n", LEARN_NS, "patch", "deployment", name, "--type=json", "-p", patch,
                           allow_failure=True)
    finally:
        path.unlink(missing_ok=True)


def _post_start_watcher_boundary(lab):
    obj = deployment("runtime-train-post-start-change", "train-verify-lock")
    monitor_code = (
        "from pathlib import Path\nimport hashlib,time\n"
        "p=Path('/model/payload.bin'); baseline=Path('/model/baseline.sha256').read_text()\n"
        "current=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        "print('watcher_started=true baseline_matches='+str(current==baseline),flush=True)\n"
        "Path('/watch/monitor-ready').write_text('ready\\n')\n"
        "for _ in range(100):\n"
        " current=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " if current != baseline:\n"
        "  print('post_start_change_detected=true observed_sha256='+current,flush=True); break\n"
        " time.sleep(0.1)\n"
        "time.sleep(3600)\n")
    containers = obj["spec"]["template"]["spec"]["containers"]
    containers[0]["command"] = ["python", "-u", "-c", monitor_code]
    containers[0]["volumeMounts"].append({"name": "watch-control", "mountPath": "/watch"})
    obj["spec"]["template"]["spec"]["volumes"].append({"name": "watch-control", "emptyDir": {}})
    mutator_code = (
        "import time,hashlib\nfrom pathlib import Path\n"
        "ready=Path('/watch/monitor-ready'); deadline=time.time()+10\n"
        "while not ready.is_file() and time.time()<deadline: time.sleep(0.1)\n"
        "if not ready.is_file(): raise SystemExit('watcher readiness marker missing')\n"
        "data=b'SAF synthetic inert model bytes after-start v2\\n'\n"
        "Path('/model/payload.bin').write_bytes(data)\n"
        "print('fixed_marker_written=true sha256='+hashlib.sha256(data).hexdigest(),flush=True)\n"
        "time.sleep(3600)\n")
    containers.append(_container("bounded-fixture-mutator", mutator_code,
                                 [{"name": "model-state", "mountPath": "/model"},
                                  {"name": "watch-control", "mountPath": "/watch", "readOnly": True}]))
    lab.kubectl("create", "-f", "-", "-n", TRAIN_NS, payload=json.dumps(obj))
    _wait_ready(lab, TRAIN_NS, obj["metadata"]["name"])
    pod = _pod_name(lab, TRAIN_NS, obj["metadata"]["name"])
    watcher = _monitor_log(lab, TRAIN_NS, pod, "integrity-monitor", "post_start_change_detected=")
    marker = hashlib.sha256(b"SAF synthetic inert model bytes after-start v2\n").hexdigest()
    detected = ("watcher_started=true baseline_matches=True" in watcher
                and "post_start_change_detected=true" in watcher
                and f"observed_sha256={marker}" in watcher)
    lab.check("positive", "The running integrity watcher observes one later harmless marker change on its case-owned volume",
              detected, {"started_from_baseline": "watcher_started=true baseline_matches=True" in watcher,
                         "post_start_change_detected": "post_start_change_detected=true" in watcher,
                         "expected_marker_digest_observed": f"observed_sha256={marker}" in watcher})


def _release_identity_boundary(lab):
    name = "authorized-release-marker-target"
    target = deployment(name, "continuous-learning")
    target["metadata"]["namespace"] = LEARN_NS
    target["spec"]["replicas"] = 0
    target["metadata"]["annotations"] = {"saf-k8s.example/update": "release-v1-fixture"}
    target["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "SAF_RELEASE_MARKER", "value": "v1-fixture"})
    lab.kubectl("create", "-f", "-", "-n", LEARN_NS, payload=json.dumps(target))
    denied_patch = json.dumps([{"op": "replace",
                                "path": "/spec/template/spec/containers/0/env/1/value",
                                "value": "v2-unapproved-fixture"}], separators=(",", ":"))
    denied = lab.kubectl("-n", LEARN_NS, "patch", "deployment", name, "--type=json", "-p", denied_patch,
                         allow_failure=True)
    unchanged = json.loads(lab.kubectl("-n", LEARN_NS, "get", "deployment", name, "-o", "json").stdout)
    denied_without_mutation = (denied.returncode != 0 and "ValidatingAdmissionPolicy" in denied.stderr
                               and unchanged["spec"]["template"]["spec"]["containers"][0]["env"][1]["value"] == "v1-fixture"
                               and unchanged["metadata"]["annotations"].get("saf-k8s.example/update") == "release-v1-fixture")
    approved = _authorized_release_patch(lab, name)
    live = json.loads(lab.kubectl("-n", LEARN_NS, "get", "deployment", name, "-o", "json").stdout)
    release_marker = live["metadata"]["annotations"].get("saf-k8s.example/update") == "release-v2-approved-fixture"
    template_marker = any(env.get("name") == "SAF_RELEASE_MARKER" and env.get("value") == "v2-approved-fixture"
                          for env in live["spec"]["template"]["spec"]["containers"][0].get("env", []))
    lab.check("positive", "Only the authorized release identity can atomically update the inert workload release marker and Deployment template",
              denied_without_mutation and approved.returncode == 0 and release_marker and template_marker
              and live["spec"].get("replicas") == 0,
              {"unapproved_template_only_update_denied_without_mutation": denied_without_mutation,
               "authorized_release_identity_update_admitted": approved.returncode == 0,
               "release_annotation_persisted": release_marker,
               "template_release_marker_persisted": template_marker,
               "replicas_remain_zero": live["spec"].get("replicas") == 0})


def _authorized_update(lab):
    base = ("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}")

    def private_call(*args):
        result = subprocess.run((*base, *args), text=True, capture_output=True, env=lab.env, timeout=25)
        if result.returncode or not result.stdout.strip():
            lab.block("Could not prepare the fixture's short-lived updater identity")
        return result.stdout.strip()

    token = private_call("-n", LEARN_NS, "create", "token", "saf-model-update-authorizer", "--duration=10m")
    config = json.loads(private_call("config", "view", "--raw", "--minify", "-o", "json"))
    config["users"] = [{"name": "fixture-updater", "user": {"token": token}}]
    config["contexts"][0]["context"]["user"] = "fixture-updater"
    path = lab.kubeconfig.parent / "fixture-updater.kubeconfig"
    path.touch(mode=0o600, exist_ok=False)
    try:
        path.write_text(json.dumps(config))
        return lab.command("kubectl", "--kubeconfig", str(path), "--context", f"kind-{lab.cluster}",
                           "-n", LEARN_NS, "annotate", "deployment/authorized-update-target",
                           "saf-k8s.example/update=change-001", "--overwrite", allow_failure=True)
    finally:
        path.unlink()


def run(lab):
    _namespace(lab, TRAIN_NS, "train-verify-lock")
    _namespace(lab, LEARN_NS, "continuous-learning")
    _namespace(lab, "saf-0905-015-unassigned", "unassigned")
    lab.kubectl("-n", LEARN_NS, "create", "serviceaccount", "saf-model-update-authorizer")
    lab.kubectl("-n", LEARN_NS, "create", "role", "saf-model-update-authorizer",
                "--verb=get,patch,update", "--resource=deployments")
    lab.kubectl("-n", LEARN_NS, "create", "rolebinding", "saf-model-update-authorizer",
                "--role=saf-model-update-authorizer",
                "--serviceaccount=" + LEARN_NS + ":saf-model-update-authorizer")
    red_specs = [
        ("train-verify-lock", TRAIN_NS, TRAIN_POLICY, TRAIN_DENIAL,
         deployment("red-train-lock", "train-verify-lock", complete=False)),
        ("continuous-learning", LEARN_NS, LEARN_POLICY, LEARN_DENIAL,
         deployment("red-continuous", "continuous-learning", complete=False)),
    ]
    red_results = [(label, ns, policy, denial, _server_create(lab, obj))
                   for label, ns, policy, denial, obj in red_specs]
    lab.check("red", "Both lifecycle classes admit a matching AI workload missing its required profile component before enforcement",
              all(result.returncode == 0 for *_, result in red_results),
              [_observation(label, result, policy, denial) for label, _, policy, denial, result in red_results])

    _install(lab)

    # Re-submit the exact same missing-profile candidates after both bindings are active.
    deadline = time.monotonic() + 20
    while True:
        green_results = [(label, ns, policy, denial, _server_create(lab, obj))
                         for label, ns, policy, denial, obj in red_specs]
        if all(_denied(result, policy, denial)
               for _, _, policy, denial, result in green_results) or time.monotonic() >= deadline:
            break
        time.sleep(0.4)
    lab.check("green", "Each namespace binding rejects the matching AI workload missing its own lifecycle controls",
              all(_denied(result, policy, denial) for _, _, policy, denial, result in green_results),
              [_observation(label, result, policy, denial) for label, _, policy, denial, result in green_results])

    green_valid = []
    for name, ns, profile in [
        ("valid-train-profile", TRAIN_NS, "train-verify-lock"),
        ("valid-learning-profile", LEARN_NS, "continuous-learning"),
    ]:
        obj = deployment(name, profile)
        obj["metadata"]["namespace"] = ns
        result = _server_create(lab, obj)
        green_valid.append({"probe": name, "admitted": result.returncode == 0,
                            "detail": result.stderr.strip()})
    lab.check("green", "Both complete classification-matched control profiles pass admission",
              all(item["admitted"] for item in green_valid), green_valid)

    update_target = deployment("authorized-update-target", "continuous-learning")
    update_target["metadata"]["namespace"] = LEARN_NS
    update_target["spec"]["replicas"] = 0
    lab.kubectl("create", "-f", "-", "-n", LEARN_NS, payload=json.dumps(update_target))
    denied_update = lab.kubectl("-n", LEARN_NS, "annotate", "deployment/authorized-update-target",
                                "saf-k8s.example/update=change-001", "--overwrite", allow_failure=True)
    lab.check("green", "Continuous-learning Deployment UPDATE rejects an unapproved API identity",
              _denied(denied_update, LEARN_POLICY,
                      "continuous-learning profile requires authorized updater and drift monitor"),
              {"denied_by_expected_policy": _denied(denied_update, LEARN_POLICY, LEARN_DENIAL),
               "detail": denied_update.stderr.strip()})
    allowed_update = _authorized_update(lab)
    live_target = json.loads(lab.kubectl("-n", LEARN_NS, "get", "deployment/authorized-update-target",
                                         "-o", "json").stdout)
    persisted_update = live_target["metadata"].get("annotations", {}).get("saf-k8s.example/update") == "change-001"
    lab.check("positive", "The narrowly RBAC-bound update identity can perform the controlled Deployment UPDATE",
              allowed_update.returncode == 0 and persisted_update,
              {"admitted": allowed_update.returncode == 0, "persisted": persisted_update, "detail": allowed_update.stderr.strip()})

    unassigned = deployment("unassigned-positive", "train-verify-lock", complete=False)
    unassigned["metadata"]["namespace"] = "saf-0905-015-unassigned"
    outside = _server_create(lab, unassigned)
    lab.check("positive", "The namespace-selected profile policies leave an unassigned namespace outside this case's enforcement scope",
              outside.returncode == 0,
              {"admitted": outside.returncode == 0, "detail": outside.stderr.strip()})

    # Persist both valid profile workloads and observe the fixed inert runtime workflows.
    for name, ns, profile, marker in [
        ("runtime-train-lock", TRAIN_NS, "train-verify-lock", "integrity_ok=True"),
        ("runtime-continuous", LEARN_NS, "continuous-learning", "model_drift_observed=1"),
    ]:
        obj = deployment(name, profile)
        obj["metadata"]["namespace"] = ns
        lab.kubectl("create", "-f", "-", "-n", ns, payload=json.dumps(obj))
        _wait_ready(lab, ns, name)
        pod = _pod_name(lab, ns, name)
        if profile == "train-verify-lock":
            init = lab.kubectl("-n", ns, "logs", pod, "-c", "integrity-baseline").stdout
            monitor = _monitor_log(lab, ns, pod, "integrity-monitor", "integrity_sha256=")
            observed = {"init": init.strip(), "monitor": monitor.strip()}
            ok = ("baseline_sha256=" in init and marker in monitor
                  and "integrity_sha256=" in monitor
                  and "tamper_counterfactual_detected=True" in monitor)
        else:
            updater = lab.kubectl("-n", ns, "logs", pod, "-c", "authorized-model-updater").stdout
            monitor = _monitor_log(lab, ns, pod, "drift-monitor", "model_sha256=")
            observed = {"updater": updater.strip(), "monitor": monitor.strip()}
            checksum = hashlib.sha256(b"SAF synthetic inert model bytes v2 approved fixture\n").hexdigest()
            ok = ("update_authorized=true fixture=change-001" in updater and marker in monitor
                  and f"sha256={checksum}" in updater and f"model_sha256={checksum}" in monitor)
        lab.check("positive", f"The admitted {profile} fixture executes its inert profile workflow",
                  ok, observed)

    altered = deployment("runtime-train-altered", "train-verify-lock", mismatch=True)
    lab.kubectl("-n", TRAIN_NS, "create", "-f", "-", payload=json.dumps(altered))
    _wait_ready(lab, TRAIN_NS, altered["metadata"]["name"])
    altered_pod = _pod_name(lab, TRAIN_NS, altered["metadata"]["name"])
    actual = _monitor_log(lab, TRAIN_NS, altered_pod, "integrity-monitor", "integrity_sha256=")
    digest = hashlib.sha256(b"SAF synthetic altered fixture\n").hexdigest()
    lab.check("green", "The running integrity monitor detects changed fixture bytes against the fixed baseline",
              "integrity_ok=False" in actual and f"integrity_sha256={digest}" in actual,
              {"integrity_monitor_output": actual.strip()})
    _post_start_watcher_boundary(lab)
    _release_identity_boundary(lab)
    _signed_marker_boundary(lab)
