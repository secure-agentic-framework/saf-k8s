"""Bounded actual continuous-learning UPDATE through signed fixture bytes."""
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import time


UPDATER_NAME = "saf-model-update-authorizer"
LEARN_WEBHOOK = "saf-0905-015-learning-signed-update"
ARTIFACT_SOURCE = "model-sha256-"

INIT_CODE = (
    "from pathlib import Path; import hashlib\n"
    "source=Path('/source/payload.bin').read_bytes()\n"
    "expected=Path('/source/model.sha256').read_text().strip()\n"
    "actual='sha256:'+hashlib.sha256(source).hexdigest()\n"
    "if actual != expected: raise SystemExit('source digest does not match immutable descriptor')\n"
    "Path('/model/payload.bin').write_bytes(source)\n"
    "print('update_bytes_verified=true model_version='+actual,flush=True)\n"
)
READER_CODE = (
    "from pathlib import Path; import hashlib\n"
    "actual='sha256:'+hashlib.sha256(Path('/model/payload.bin').read_bytes()).hexdigest()\n"
    "expected=Path('/source/model.sha256').read_text().strip()\n"
    "if actual != expected: raise SystemExit('consumed model version mismatch')\n"
    "print('workload_model_version='+actual+' fixture_bytes_consumed=true',flush=True)\n"
    "import time; time.sleep(3600)\n"
)
MONITOR_CODE = (
    "from pathlib import Path; import hashlib\n"
    "actual='sha256:'+hashlib.sha256(Path('/model/payload.bin').read_bytes()).hexdigest()\n"
    "expected=Path('/source/model.sha256').read_text().strip()\n"
    "print('model_drift_observed='+str(int(actual!=expected))+' model_sha256='+actual,flush=True)\n"
    "import time; time.sleep(3600)\n"
)


def _signed_annotations(fixture, artifact_sha, *, signature=None):
    return {
        "saf.example.test/model-digest": "sha256:" + fixture["manifest_sha256"],
        "saf.example.test/model-signature": signature or fixture["manifest_signature_base64"],
        "saf.example.test/attestations": json.dumps(
            fixture["attestations"], separators=(",", ":"), sort_keys=True),
        "saf-k8s.example/update": "sha256:" + artifact_sha,
    }


def _learning_deployment(case, name, namespace, source_name):
    obj = case.deployment(name, "continuous-learning")
    obj["metadata"]["namespace"] = namespace
    obj["spec"]["replicas"] = 1
    pod_spec = obj["spec"]["template"]["spec"]
    pod_spec["volumes"].append({"name": "model-source", "configMap": {"name": source_name}})
    updater = pod_spec["initContainers"][0]
    updater["command"] = ["python", "-u", "-c", INIT_CODE]
    updater["volumeMounts"].append({"name": "model-source", "mountPath": "/source", "readOnly": True})
    monitor = next(c for c in pod_spec["containers"] if c["name"] == "drift-monitor")
    monitor["command"] = ["python", "-u", "-c", MONITOR_CODE]
    monitor["volumeMounts"].append({"name": "model-source", "mountPath": "/source", "readOnly": True})
    reader = case._container("model-reader", READER_CODE,
        [{"name": "model-state", "mountPath": "/model", "readOnly": True},
         {"name": "model-source", "mountPath": "/source", "readOnly": True}])
    pod_spec["containers"].append(reader)
    return obj


def _gate_configuration(ca_pem, server_namespace):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": LEARN_WEBHOOK},
        "webhooks": [{
            "name": "signed-learning-update.saf.example.test",
            "admissionReviewVersions": ["v1"], "sideEffects": "None",
            "failurePolicy": "Fail", "matchPolicy": "Equivalent", "timeoutSeconds": 5,
            "clientConfig": {"service": {"namespace": server_namespace,
                "name": LEARN_WEBHOOK, "path": "/validate", "port": 443},
                "caBundle": base64.b64encode(ca_pem).decode("ascii")},
            "namespaceSelector": {"matchLabels": {"saf-k8s.example/lifecycle": "continuous-learning"}},
            "rules": [{"operations": ["UPDATE"], "apiGroups": ["apps"],
                       "apiVersions": ["v1"], "resources": ["deployments"], "scope": "Namespaced"}],
        }],
    }


def _create_namespaced(lab, resource):
    namespace = resource["metadata"]["namespace"]
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(resource))


def _install_learning_verifier(lab, case, fixture):
    server_ns = case.VERIFY_NS
    material_dir = lab.kubeconfig.parent / "0905-015-learning-tls-material"
    material_dir.mkdir(mode=0o700)
    cert, key = material_dir / "tls.crt", material_dir / "tls.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "2",
                "-subj", f"/CN={LEARN_WEBHOOK}.{server_ns}.svc",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", f"subjectAltName=DNS:{LEARN_WEBHOOK}.{server_ns}.svc,DNS:{LEARN_WEBHOOK}.{server_ns}.svc.cluster.local")
    try:
        lab.kubectl("-n", server_ns, "create", "secret", "tls", LEARN_WEBHOOK + "-tls",
                    f"--cert={cert}", f"--key={key}")
    finally:
        key.unlink(missing_ok=True)
    fixture_bytes = json.dumps(fixture, sort_keys=True)
    _create_namespaced(lab, {"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": LEARN_WEBHOOK + "-source", "namespace": server_ns},
        "data": {"learning_webhook.py": (case.HERE / "learning_webhook.py").read_text(encoding="utf-8"),
                 "webhook.py": (case.HERE / "webhook.py").read_text(encoding="utf-8"),
                 "fixtures.json": fixture_bytes}})
    labels = {"app": LEARN_WEBHOOK}
    _create_namespaced(lab, {"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": LEARN_WEBHOOK, "namespace": server_ns},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
          "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "source", "configMap": {"name": LEARN_WEBHOOK + "-source"}},
                        {"name": "tls", "secret": {"secretName": LEARN_WEBHOOK + "-tls"}}],
            "containers": [{"name": "verifier", "image": case.PYTHON_IMAGE,
                "command": ["python", "/app/learning_webhook.py"], "imagePullPolicy": "IfNotPresent",
                "ports": [{"name": "https", "containerPort": 8443}],
                "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/healthz", "port": "https"},
                                   "periodSeconds": 1},
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True},
                                 {"name": "tls", "mountPath": "/tls", "readOnly": True}],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}],
          }}}})
    _create_namespaced(lab, {"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": LEARN_WEBHOOK, "namespace": server_ns},
        "spec": {"selector": labels, "ports": [{"name": "https", "port": 443, "targetPort": "https"}]}})
    lab.kubectl("-n", server_ns, "rollout", "status", f"deployment/{LEARN_WEBHOOK}",
                "--timeout=60s", timeout=70)
    lab.create(_gate_configuration(cert.read_bytes(), server_ns))
    cert.unlink(missing_ok=True)
    material_dir.rmdir()


@contextmanager
def _authorized_kubeconfig(lab, case):
    base = ("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}")
    token_result = subprocess.run((*base, "-n", case.LEARN_NS, "create", "token", UPDATER_NAME,
                                   "--duration=10m"), text=True, capture_output=True,
                                   env=lab.env, timeout=25)
    if token_result.returncode or not token_result.stdout.strip():
        lab.block("Could not prepare the fixture's short-lived updater identity")
    token = token_result.stdout.strip()
    config_result = subprocess.run((*base, "config", "view", "--raw", "--minify", "-o", "json"),
                                   text=True, capture_output=True, env=lab.env, timeout=25)
    if config_result.returncode:
        lab.block("Could not prepare the fixture updater kubeconfig")
    config = json.loads(config_result.stdout)
    config["users"] = [{"name": "fixture-update-consumer", "user": {"token": token}}]
    config["contexts"][0]["context"]["user"] = "fixture-update-consumer"
    path = lab.kubeconfig.parent / "0905-015-update-consumer.kubeconfig"
    path.touch(mode=0o600, exist_ok=False)
    try:
        path.write_text(json.dumps(config))
        yield path
    finally:
        path.unlink(missing_ok=True)
        token = ""


def _patch(lab, case, deployment_name, source_name, annotations, kubeconfig,
           *, dry_run=False):
    patch = json.dumps([
        {"op": "add", "path": "/metadata/annotations", "value": annotations},
        {"op": "replace", "path": "/spec/template/spec/volumes/1/configMap/name", "value": source_name},
    ], separators=(",", ":"))
    args = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{lab.cluster}",
            "-n", case.LEARN_NS, "patch", "deployment", deployment_name, "--type=json", "-p", patch]
    if dry_run:
        args.append("--dry-run=server")
    return lab.command(*args, allow_failure=True)


def _pod(lab, case, name):
    result = json.loads(lab.kubectl("-n", case.LEARN_NS, "get", "pods", "-l",
        f"app.kubernetes.io/name={name}", "-o", "json").stdout)
    return result.get("items", [])


def _has_log(lab, case, pod, container, marker):
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        output = lab.kubectl("-n", case.LEARN_NS, "logs", pod, "-c", container,
                             timeout=12, allow_failure=True)
        if output.returncode == 0 and marker in output.stdout:
            return True
        time.sleep(0.35)
    return False


def run_continuous_update(lab, case):
    fixture = json.loads((case.HERE / "fixtures.json").read_text(encoding="utf-8"))
    artifact = base64.b64decode(fixture["artifact"], validate=True)
    artifact_sha = hashlib.sha256(artifact).hexdigest()
    if artifact_sha != fixture["artifact_sha256"]:
        lab.block("Existing signed fixture bytes do not match their fixture digest")
    source_name = ARTIFACT_SOURCE + artifact_sha[:32]
    learning_fixture = dict(fixture)
    learning_fixture.update({"namespace": case.LEARN_NS,
        "lifecycle_profile": "continuous-learning", "artifact_configmap": source_name,
        "runtime_image": case.IMAGE})

    baseline = b"SAF synthetic previous model version\n"
    baseline_sha = "sha256:" + hashlib.sha256(baseline).hexdigest()
    baseline_name = "model-baseline-v1"
    _create_namespaced(lab, {"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": baseline_name, "namespace": case.LEARN_NS}, "immutable": True,
        "data": {"model.sha256": baseline_sha},
        "binaryData": {"payload.bin": base64.b64encode(baseline).decode("ascii")}})
    _create_namespaced(lab, {"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": source_name, "namespace": case.LEARN_NS}, "immutable": True,
        "data": {"model.sha256": "sha256:" + artifact_sha},
        "binaryData": {"payload.bin": fixture["artifact"]}})
    source_readback = json.loads(lab.kubectl("-n", case.LEARN_NS, "get", "configmap", source_name,
                                             "-o", "json").stdout)
    source_bytes = base64.b64decode(source_readback.get("binaryData", {}).get("payload.bin", ""),
                                    validate=True)
    source_exact = (source_readback.get("immutable") is True
                    and source_readback.get("data", {}).get("model.sha256") == "sha256:" + artifact_sha
                    and hashlib.sha256(source_bytes).hexdigest() == artifact_sha)

    target_name = "signed-continuous-model-update"
    target = _learning_deployment(case, target_name, case.LEARN_NS, baseline_name)
    _create_namespaced(lab, target)
    lab.kubectl("-n", case.LEARN_NS, "rollout", "status", "deployment/" + target_name,
                "--timeout=90s", timeout=100)
    old = _pod(lab, case, target_name)
    if len(old) != 1:
        lab.block("Expected exactly one baseline workload Pod")
    old_pod = old[0]
    old_gen = json.loads(lab.kubectl("-n", case.LEARN_NS, "get", "deployment", target_name,
                                     "-o", "json").stdout)
    old_generation = old_gen["metadata"]["generation"]
    baseline_observed = _has_log(lab, case, old_pod["metadata"]["name"], "model-reader",
                                 "workload_model_version=" + baseline_sha + " fixture_bytes_consumed=true")

    _install_learning_verifier(lab, case, learning_fixture)
    good_annotations = _signed_annotations(fixture, artifact_sha)
    bad_annotations = dict(good_annotations)
    bad_annotations["saf.example.test/model-signature"] = "AA=="

    # The already-authorized updater still cannot bind unsigned or altered bytes.
    with _authorized_kubeconfig(lab, case) as updater_config:
        bad_deadline = time.monotonic() + 20
        while True:
            bad = _patch(lab, case, target_name, source_name, bad_annotations,
                         updater_config, dry_run=True)
            expected_bad = (bad.returncode != 0
                            and "SAF signed learning update: manifest signature mismatch" in bad.stderr)
            if expected_bad or time.monotonic() >= bad_deadline:
                break
            time.sleep(0.3)
        after_bad = json.loads(lab.kubectl("-n", case.LEARN_NS, "get", "deployment", target_name,
                                           "-o", "json").stdout)
        after_bad_pods = _pod(lab, case, target_name)
        bad_unchanged = (expected_bad and after_bad["metadata"]["generation"] == old_generation
                         and after_bad["spec"]["template"]["spec"]["volumes"][1]["configMap"]["name"] == baseline_name
                         and len(after_bad_pods) == 1
                         and after_bad_pods[0]["metadata"]["uid"] == old_pod["metadata"]["uid"])

        # A valid signer and exact artifact are accepted by that same UPDATE gate.
        good = _patch(lab, case, target_name, source_name, good_annotations, updater_config)

    if good.returncode:
        lab.block("The authorized update with the exact signed fixture was denied")
    lab.kubectl("-n", case.LEARN_NS, "rollout", "status", "deployment/" + target_name,
                "--timeout=90s", timeout=100)
    updated = json.loads(lab.kubectl("-n", case.LEARN_NS, "get", "deployment", target_name,
                                     "-o", "json").stdout)
    new_pods = [
        pod for pod in _pod(lab, case, target_name)
        if not pod["metadata"].get("deletionTimestamp")
        and any(vol.get("name") == "model-source" and vol.get("configMap", {}).get("name") == source_name
                for vol in pod["spec"].get("volumes", []))
        and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", []))
    ]
    if len(new_pods) != 1:
        lab.block("Expected one Ready, non-terminating workload Pod bound to the updated artifact")
    new_pod = new_pods[0]
    pod_name = new_pod["metadata"]["name"]
    exact_sha = "sha256:" + artifact_sha
    saved_annotations = updated["metadata"].get("annotations", {})
    source_bound = (updated["spec"]["template"]["spec"]["volumes"][1]["configMap"]["name"] == source_name
                    and saved_annotations.get("saf-k8s.example/update") == exact_sha
                    and saved_annotations.get("saf.example.test/model-digest")
                    == "sha256:" + fixture["manifest_sha256"]
                    and saved_annotations.get("saf.example.test/model-signature")
                    == fixture["manifest_signature_base64"]
                    and json.loads(saved_annotations.get("saf.example.test/attestations", "[]"))
                    == fixture["attestations"])
    new_revision = (updated["metadata"]["generation"] > old_generation
                    and updated.get("status", {}).get("observedGeneration") == updated["metadata"]["generation"]
                    and new_pod["metadata"]["uid"] != old_pod["metadata"]["uid"])
    exact_consumption = _has_log(lab, case, pod_name, "authorized-model-updater",
                                 "update_bytes_verified=true model_version=" + exact_sha)
    reader_consumed = _has_log(lab, case, pod_name, "model-reader",
                               "workload_model_version=" + exact_sha + " fixture_bytes_consumed=true")
    monitor_matched = _has_log(lab, case, pod_name, "drift-monitor",
                               "model_drift_observed=0 model_sha256=" + exact_sha)
    passed = (source_exact and baseline_observed and bad_unchanged and new_revision and source_bound
              and good.returncode == 0 and exact_consumption and reader_consumed and monitor_matched)
    lab.check("positive", "The authorized continuous-learning UPDATE rolls out and consumes the exact signed inert artifact",
        passed, {"baseline_model_version_observed": baseline_observed,
                 "immutable_configmap_bytes_match_signed_fixture": source_exact,
                 "authorized_but_bad_signature_denied_without_rollout": bad_unchanged,
                 "authorized_exact_signed_update_admitted": good.returncode == 0,
                 "digest_qualified_immutable_source_bound": source_bound,
                 "new_generation_and_pod_uid_observed": new_revision,
                 "init_verified_exact_fixture_bytes": exact_consumption,
                 "workload_reader_observed_exact_model_version": reader_consumed,
                 "drift_monitor_matched_consumed_version": monitor_matched,
                 "manifest_digest": "sha256:" + fixture["manifest_sha256"],
                 "artifact_digest": exact_sha,
                 "pod_payload_bytes_logged": False,
                 "credential_material_logged": False})
