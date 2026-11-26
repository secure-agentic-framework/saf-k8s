"""One pinned Argo v3.7.6 WorkflowTemplate reconciliation witness."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
MANIFEST = FIXTURES / "argo-controller-only.yaml"
PINS = FIXTURES / "argo-pins.json"
EXECUTOR_SA = "saf-argo-executor"
EXECUTOR_SECRET = "saf-argo-executor.service-account-token"
EXECUTOR_ROLE = "saf-argo-executor"
WORKFLOW = "saf-approved-template-run"


def _pins(lab):
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    for key in ("controller_index_digest", "executor_index_digest"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", pins.get(key, "")):
            lab.block("Argo controller/executor image digest pin is malformed")
    raw = MANIFEST.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins.get("controller_only_manifest_sha256"):
        lab.block("Argo controller-only manifest differs from the reviewed v3.7.6 pin")
    text = raw.decode("utf-8")
    if (f"quay.io/argoproj/workflow-controller@{pins['controller_index_digest']}" not in text
            or f"quay.io/argoproj/argoexec@{pins['executor_index_digest']}" not in text
            or "--namespaced" not in text or "argo-server" in text or ":latest" in text):
        lab.block("Argo fixture is not the namespaced v3.7.6 controller-only install")
    return pins


def _wait_workflow(lab, namespace):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "workflow", WORKFLOW, "-o", "json",
                             allow_failure=True, timeout=15)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            phase = value.get("status", {}).get("phase")
            if phase in ("Failed", "Error"):
                return value, False
            if phase == "Succeeded":
                return value, True
        time.sleep(0.5)
    return None, False


def _executor_token_present_without_logging(lab, namespace):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        # Secret bytes are parsed only in memory. This subprocess is deliberately
        # not routed through lab.kubectl because the lab recorder retains output.
        args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                f"kind-{lab.cluster}", "--namespace", namespace,
                "--request-timeout=5s", "get", "secret", EXECUTOR_SECRET, "-o", "json"]
        try:
            result = subprocess.run(args, capture_output=True, text=True,
                                    env=lab.env, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            time.sleep(0.5)
            continue
        if result.returncode == 0:
            populated = bool(json.loads(result.stdout).get("data", {}).get("token"))
            del result
            if populated:
                return True
        time.sleep(0.5)
    return False


def _prepare_executor(lab, namespace):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": EXECUTOR_SA, "namespace": namespace},
                "automountServiceAccountToken": False})
    token_secret = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": EXECUTOR_SECRET, "namespace": namespace,
                     "annotations": {"kubernetes.io/service-account.name": EXECUTOR_SA}},
        "type": "kubernetes.io/service-account-token",
    }
    lab.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(token_secret))
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": EXECUTOR_ROLE, "namespace": namespace},
                "rules": [{"apiGroups": ["argoproj.io"],
                           "resources": ["workflowtaskresults"],
                           "verbs": ["create", "patch"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": EXECUTOR_ROLE, "namespace": namespace},
                "subjects": [{"kind": "ServiceAccount", "name": EXECUTOR_SA,
                              "namespace": namespace}],
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": EXECUTOR_ROLE}})


def run(lab, case):
    pins = _pins(lab)
    namespace = case.namespace
    lab.apply(MANIFEST)
    crds = ("clusterworkflowtemplates.argoproj.io", "cronworkflows.argoproj.io",
            "workflowartifactgctasks.argoproj.io", "workfloweventbindings.argoproj.io",
            "workflowtaskresults.argoproj.io", "workflowtasksets.argoproj.io",
            "workflowtemplates.argoproj.io", "workflows.argoproj.io")
    for crd in crds:
        lab.kubectl("wait", "--for=condition=Established", f"crd/{crd}",
                    "--timeout=45s", timeout=55)
    lab.kubectl("wait", "--for=condition=Available", "deployment/workflow-controller",
                "--timeout=90s", timeout=100)
    deployment = json.loads(lab.kubectl("get", "deployment", "workflow-controller",
                                        "-o", "json").stdout)
    pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
    controller_exact = (pod_spec.get("serviceAccountName") == "argo"
                        and pod_spec.get("containers", [{}])[0].get("image")
                        == f"quay.io/argoproj/workflow-controller@{pins['controller_index_digest']}")
    if not controller_exact:
        lab.block("Installed controller differs from the reviewed Argo v3.7.6 namespaced fixture")

    persisted_template = json.loads(lab.kubectl(
        "get", "workflowtemplate", case.template, "-o", "json").stdout)
    template_spec_exact = persisted_template.get("spec") == case.approved_spec
    _prepare_executor(lab, namespace)
    executor_ready = _executor_token_present_without_logging(lab, namespace)
    workflow_doc = {
        "apiVersion": "argoproj.io/v1alpha1", "kind": "Workflow",
        "metadata": {"name": WORKFLOW, "namespace": namespace,
                     "labels": {"saf.example/control": "SAF-K8S-0904-001"}},
        "spec": {
            "workflowTemplateRef": {"name": case.template},
            "executor": {"serviceAccountName": EXECUTOR_SA},
            "activeDeadlineSeconds": 90,
            "parallelism": 1,
            "retryStrategy": {"limit": 0},
        },
    }
    created = lab.create(workflow_doc)
    workflow, succeeded = _wait_workflow(lab, namespace)
    pod_observed = {}
    if workflow is not None:
        pods = json.loads(lab.kubectl(
            "get", "pods", "-l", f"workflows.argoproj.io/workflow={WORKFLOW}",
            "-o", "json").stdout).get("items", [])
        uid = created.get("metadata", {}).get("uid")
        owned = [pod for pod in pods if any(
            ref.get("kind") == "Workflow" and ref.get("uid") == uid
            for ref in pod.get("metadata", {}).get("ownerReferences", []))]
        if len(owned) == 1:
            pod, = owned
            spec = pod.get("spec", {})
            main = [row for row in spec.get("containers", []) if row.get("name") == "main"]
            main = main[0] if len(main) == 1 else {}
            volumes = spec.get("volumes", [])
            marker_volume = any(volume.get("secret", {}).get("secretName") == case.marker
                                for volume in volumes)
            token_projections = [source for volume in volumes
                                 for source in volume.get("projected", {}).get("sources", [])
                                 if "serviceAccountToken" in source]
            main_mounts = main.get("volumeMounts", [])
            marker_mount = any(row.get("mountPath") == "/run/marker"
                               and row.get("readOnly") is True for row in main_mounts)
            service_account_mount = any(
                row.get("mountPath", "").startswith("/var/run/secrets/kubernetes.io/serviceaccount")
                for row in main_mounts)
            main_container = main
            logs = lab.kubectl("logs", pod["metadata"]["name"], "-c", "main",
                               timeout=20, allow_failure=True)
            log_text = logs.stdout.strip() if logs.returncode == 0 else ""
            pod_observed = {
                "exact_workflow_owner_uid": any(
                    ref.get("kind") == "Workflow" and ref.get("uid") == uid
                    for ref in pod.get("metadata", {}).get("ownerReferences", [])),
                "one_owned_pod": len(owned) == 1,
                "workflow_succeeded": succeeded,
                "pod_succeeded": pod.get("status", {}).get("phase") == "Succeeded",
                "workflow_references_exact_template": (
                    workflow.get("spec", {}).get("workflowTemplateRef", {}).get("name")
                    == case.template and template_spec_exact),
                "template_service_account_applied": (
                    workflow.get("spec", {}).get("serviceAccountName", case.account)
                    == case.account and spec.get("serviceAccountName") == case.account),
                "template_nonroot_security_applied": (
                    main_container.get("securityContext", {}).get("runAsNonRoot") is True
                    and main_container.get("securityContext", {}).get("runAsUser") == 65534
                    and main_container.get("securityContext", {}).get("runAsGroup") == 65534),
                "main_container_has_template_restrictions": (
                    main_container.get("securityContext", {}).get("allowPrivilegeEscalation") is False
                    and main_container.get("securityContext", {}).get("readOnlyRootFilesystem") is True
                    and main_container.get("securityContext", {}).get("capabilities", {}).get("drop") == ["ALL"]),
                "read_only_public_marker_mount": marker_volume and marker_mount,
                "step_has_no_service_account_token_mount": not token_projections and not service_account_mount,
                "marker_confirmation": log_text.splitlines().count("marker-mounted") == 1,
                "marker_literal_not_logged": case.marker_text not in log_text,
            }
            raw = {"workflow": workflow, "task_pod": pod,
                   "main_log": log_text, "executor_token_secret_populated": executor_ready}
            (lab.evidence / "controller-reconciliation.raw.json").write_text(
                json.dumps(raw, indent=2) + "\n")
    passed = (executor_ready and controller_exact and
              all(value is True for value in pod_observed.values()) and len(pod_observed) == 12)
    lab.check("positive", "Pinned Argo controller runs one restricted marker step from the exact approved WorkflowTemplate",
              passed, {"controller_exact": controller_exact,
                       "executor_token_secret_populated": executor_ready,
                       **pod_observed})
