"""Additive, owned Argo Workflows stage-identity witness for SAF-K8S-0904-014."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
PINS_FILE = FIXTURES / "argo-pins.json"
MANIFEST = FIXTURES / "argo-controller-only.yaml"
WORKFLOW = "stage-artifact-read"
EXECUTOR_SA = "saf-argo-executor"
EXECUTOR_ROLE = "saf-argo-executor"
EXECUTOR_BINDING = "saf-argo-executor"
EXECUTOR_TOKEN_SECRET = "saf-argo-executor.service-account-token"


def load_pins(lab):
    pins = json.loads(PINS_FILE.read_text(encoding="utf-8"))
    digest_fields = (
        "controller_index_digest", "controller_linux_amd64_digest",
        "controller_linux_arm64_digest", "executor_index_digest",
        "executor_linux_amd64_digest", "executor_linux_arm64_digest",
        "controller_only_manifest_sha256",
    )
    if any(not pins.get(name) for name in digest_fields):
        lab.block("Argo v3.7.6 is source-pinned, but image index/platform digests and the controller-only manifest SHA-256 are not verified")
    for name in digest_fields[:-1]:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", pins[name]):
            lab.block("Argo v3.7.6 image pin format is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", pins["controller_only_manifest_sha256"]):
        lab.block("Argo controller-only manifest digest format is invalid")
    if not MANIFEST.is_file():
        lab.block("Verified Argo v3.7.6 controller-only manifest fixture is missing")
    raw = MANIFEST.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins["controller_only_manifest_sha256"]:
        lab.block("Argo controller-only manifest bytes do not match the reviewed pin")
    text = raw.decode("utf-8")
    controller_ref = f"quay.io/argoproj/workflow-controller@{pins['controller_index_digest']}"
    executor_ref = f"quay.io/argoproj/argoexec@{pins['executor_index_digest']}"
    if (controller_ref not in text or executor_ref not in text
            or "--namespaced" not in text
            or "argo-server" in text or ":latest" in text):
        lab.block("Argo manifest must contain the exact pinned controller/executor and omit server/UI components")
    return pins


def _workflow_object(name, stage, case):
    return {
        "apiVersion": "argoproj.io/v1alpha1", "kind": "Workflow",
        "metadata": {"name": name, "namespace": case.NAMESPACE,
                     "labels": {"saf.example/control": "SAF-K8S-0904-014"}},
        "spec": {
            "entrypoint": "fixed-stage-read",
            "serviceAccountName": f"stage-{stage}",
            "automountServiceAccountToken": False,
            "executor": {"serviceAccountName": EXECUTOR_SA},
            "activeDeadlineSeconds": 90,
            "parallelism": 1,
            "retryStrategy": {"limit": 0},
            "volumes": [
                {"name": "fixtures", "configMap": {"name": case.FED_CONFIGMAP}},
                {"name": "oidc-token", "projected": {"sources": [{
                    "serviceAccountToken": {"path": "token", "audience": case.FED_AUDIENCE,
                                             "expirationSeconds": 600}}]}},
            ],
            "templates": [{
                "name": "fixed-stage-read",
                "activeDeadlineSeconds": 60,
                "container": {
                    "name": "main", "image": case.CLIENT_IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-B", "/fixture/identity_probe.py",
                                f"workflow-read-{stage}"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                        "runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                        "readOnlyRootFilesystem": True,
                    },
                    "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                  "limits": {"cpu": "100m", "memory": "128Mi"}},
                    "volumeMounts": [
                        {"name": "fixtures", "mountPath": "/fixture", "readOnly": True},
                        {"name": "oidc-token", "mountPath": "/var/run/oidc", "readOnly": True},
                    ],
                },
            }],
        },
    }


def _wait_succeeded(lab, name, timeout_seconds=120):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "workflow", name, "-o", "json",
                             allow_failure=True, timeout=15)
        if result.returncode:
            time.sleep(0.5)
            continue
        value = json.loads(result.stdout)
        if value.get("status", {}).get("phase") in ("Failed", "Error"):
            return value, False
        if value.get("status", {}).get("phase") == "Succeeded":
            return value, True
        time.sleep(0.5)
    return None, False


def _run_stage(lab, case, stage):
    name = f"{WORKFLOW}-{stage}"
    created = lab.create(_workflow_object(name, stage, case))
    workflow, succeeded = _wait_succeeded(lab, name)
    if workflow is None:
        return {"workflow_succeeded": False, "owned_pod_count_one": False,
                "workflow_owner_matches": False, "stage_service_account_matches": False,
                "probe": {}}
    uid = created["metadata"]["uid"]
    pods_json = json.loads(lab.kubectl(
        "get", "pods", "-l", f"workflows.argoproj.io/workflow={name}", "-o", "json").stdout)
    owned = [pod for pod in pods_json.get("items", [])
             if any(ref.get("kind") == "Workflow" and ref.get("uid") == uid
                    for ref in pod.get("metadata", {}).get("ownerReferences", []))]
    if len(owned) != 1:
        return {"workflow_succeeded": succeeded, "owned_pod_count_one": False,
                "workflow_owner_matches": False, "stage_service_account_matches": False,
                "probe": {}}
    pod = owned[0]
    spec = pod.get("spec", {})
    token_sources = [source.get("serviceAccountToken", {})
                     for volume in spec.get("volumes", [])
                     for source in volume.get("projected", {}).get("sources", [])]
    token_contract = token_sources == [{"path": "token", "audience": case.FED_AUDIENCE,
                                        "expirationSeconds": 600}]
    executor_secret_mounted = any(
        volume.get("secret", {}).get("secretName") == EXECUTOR_TOKEN_SECRET
        for volume in spec.get("volumes", []))
    main_containers = [row for row in spec.get("containers", []) if row.get("name") == "main"]
    token_mount = (len(main_containers) == 1 and any(
        mount.get("name") == "oidc-token" and mount.get("mountPath") == "/var/run/oidc"
        and mount.get("readOnly") is True for mount in main_containers[0].get("volumeMounts", [])))
    logs = lab.kubectl("logs", pod["metadata"]["name"], "-c", "main",
                       timeout=20, allow_failure=True)
    probe = {}
    if logs.returncode == 0:
        observations = []
        for line in logs.stdout.splitlines():
            if line.startswith("{"):
                value = json.loads(line)
                if value.get("operation") == "workflow-read" and value.get("stage") == stage:
                    observations.append(value)
        if len(observations) == 1:
            probe = observations[0]
    return {
        "workflow_succeeded": succeeded,
        "owned_pod_count_one": len(owned) == 1,
        "workflow_owner_matches": any(ref.get("kind") == "Workflow" and ref.get("uid") == uid
                                        for ref in pod.get("metadata", {}).get("ownerReferences", [])),
        "stage_service_account_matches": (workflow.get("spec", {}).get("serviceAccountName")
                                            == f"stage-{stage}"
                                            and spec.get("serviceAccountName") == f"stage-{stage}"),
        "pod_succeeded": pod.get("status", {}).get("phase") == "Succeeded",
        "explicit_token_projection_matches": token_contract and token_mount,
        "executor_token_secret_mounted": executor_secret_mounted,
        "executor_identity_separate": (workflow.get("spec", {}).get("executor", {}).get("serviceAccountName")
                                        == EXECUTOR_SA),
        "probe": {
            "sts_accepted": probe.get("sts_status") == 200,
            "token_identity_matches": probe.get("identity_matches") is True,
            "own_marker_read_allowed": probe.get("own_read_allowed") is True,
            "own_marker_digest_matches": probe.get("own_marker_matches") is True,
            "cross_stage_marker_read_denied": probe.get("cross_read_denied") is True,
            "projected_token_fresh": probe.get("projected_expiry_window") is True,
        },
    }


def run(lab, case):
    pins = load_pins(lab)
    lab.apply(MANIFEST)
    for crd in ("clusterworkflowtemplates.argoproj.io", "cronworkflows.argoproj.io",
                "workflowartifactgctasks.argoproj.io", "workfloweventbindings.argoproj.io",
                "workflowtaskresults.argoproj.io", "workflowtasksets.argoproj.io",
                "workflowtemplates.argoproj.io", "workflows.argoproj.io"):
        lab.kubectl("wait", "--for=condition=Established", f"crd/{crd}",
                    "--timeout=45s", timeout=55)
    lab.kubectl("wait", "--for=condition=Available", "deployment/workflow-controller",
                "--timeout=90s", timeout=100)
    deployment = json.loads(lab.kubectl("get", "deployment", "workflow-controller", "-o", "json").stdout)
    if (deployment.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName") != "argo"
            or deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0].get("image")
            != f"quay.io/argoproj/workflow-controller@{pins['controller_index_digest']}"):
        lab.block("Argo controller is not the pinned, namespace-scoped fixture deployment")
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": EXECUTOR_SA, "namespace": case.NAMESPACE},
                "automountServiceAccountToken": False})
    # Argo v3.7.6 resolves executor.serviceAccountName to this conventional
    # token Secret name. Kubernetes v1.36 does not create SA token Secrets
    # automatically, so request the legacy Secret-token controller explicitly
    # in this short-lived, case-owned namespace. Never read or emit token bytes.
    executor_secret = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": EXECUTOR_TOKEN_SECRET, "namespace": case.NAMESPACE,
                     "annotations": {"kubernetes.io/service-account.name": EXECUTOR_SA}},
        "type": "kubernetes.io/service-account-token",
    }
    lab.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(executor_secret))
    token_deadline = time.monotonic() + 30
    executor_token_ready = False
    while time.monotonic() < token_deadline:
        # Lab.command records stdout/stderr, so do not use it for a Secret read.
        # Keep the API response in this process and retain only the presence bit.
        args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                f"kind-{lab.cluster}", "--namespace", case.NAMESPACE,
                "--request-timeout=5s", "get", "secret", EXECUTOR_TOKEN_SECRET,
                "-o", "json"]
        try:
            token_secret = subprocess.run(args, capture_output=True, text=True,
                                          env=lab.env, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            time.sleep(0.5)
            continue
        if token_secret.returncode == 0:
            token_data = json.loads(token_secret.stdout).get("data", {})
            populated = bool(token_data.get("token") and token_data.get("ca.crt"))
            del token_secret, token_data
            if populated:
                executor_token_ready = True
                break
        time.sleep(0.5)
    else:
        lab.block("Kubernetes did not populate the case-owned Argo executor token Secret before deadline")
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": EXECUTOR_ROLE, "namespace": case.NAMESPACE},
                "rules": [{"apiGroups": ["argoproj.io"], "resources": ["workflowtaskresults"],
                            "verbs": ["create", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": EXECUTOR_BINDING, "namespace": case.NAMESPACE},
                "subjects": [{"kind": "ServiceAccount", "name": EXECUTOR_SA,
                              "namespace": case.NAMESPACE}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": EXECUTOR_ROLE}})
    stage_a = _run_stage(lab, case, "a")
    stage_b = _run_stage(lab, case, "b")
    check_keys = ("workflow_succeeded", "owned_pod_count_one", "workflow_owner_matches",
                  "stage_service_account_matches", "pod_succeeded", "explicit_token_projection_matches",
                  "executor_token_secret_mounted", "executor_identity_separate")
    probe_keys = ("sts_accepted", "token_identity_matches", "own_marker_read_allowed",
                  "own_marker_digest_matches", "cross_stage_marker_read_denied", "projected_token_fresh")
    passed = all(stage.get(key) is True for stage in (stage_a, stage_b) for key in check_keys)
    passed = passed and all(stage.get("probe", {}).get(key) is True
                            for stage in (stage_a, stage_b) for key in probe_keys)
    passed = passed and executor_token_ready
    observed = {"stage_a": stage_a, "stage_b": stage_b,
                "serial_execution": True, "fixed_owned_s3_endpoint": "artifact-store:8333",
                "read_operations_only": True,
                "executor_token_secret_populated": executor_token_ready,
                "controller_index_pinned": bool(pins.get("controller_index_digest")),
                "executor_index_pinned": bool(pins.get("executor_index_digest"))}
    lab.check("positive", "Argo creates each stage task Pod with its assigned identity for allowed and refused fixed artifact reads",
              passed, observed)
