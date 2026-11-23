"""Native admission enforcement for two administrator-assigned AI lifecycle profiles."""
import hashlib
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
        f"(request.operation != 'UPDATE' || {update_value('object')} == {update_value('oldObject')} || request.userInfo.username == 'system:serviceaccount:{LEARN_NS}:saf-model-update-authorizer')"
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
