"""Combined image, GPU, securityContext and classification admission."""
import importlib.util
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
SCOPE = (
    "One disposable Kind cluster with a fixture-owned OCI registry, Kyverno ImageValidatingPolicy, "
    "and a native Kubernetes ValidatingAdmissionPolicy bound to one test namespace. "
    "Server-side dry-runs cover a fixture signer, attestation, named GPU quantity cap, "
    "security context, and classified inert Pods. GPU scheduling and production policy coverage "
    "require separate evidence."
)
CHART_VERSION = "3.10.0"
CHART_SHA256 = "55961392dc0821eb367323f0e9585c061dd4407ef7ada921bd56ea1642c2a301"
NS = "saf-1006-005"
POLICY = "saf-k8s-1006-005-image-provenance"
VAP = "saf-k8s-1006-005-ai-compliance"
DENIALS = {
    "gpu-over-cap": "a container may request at most one named GPU extended resource",
    "root": "pod and containers must use the required restricted security context",
    "privilege-escalation": "pod and containers must use the required restricted security context",
    "missing-classification": "AI classification label is required and must be governed",
    "unknown-classification": "AI classification label is required and must be governed",
}


def _install_kyverno(lab, chart_values):
    from hashlib import sha256
    helm_home = Path(lab.kubeconfig).parent / "helm"
    helm_home.mkdir(exist_ok=True)

    def helm(*args, timeout=220):
        return lab.command(
            "env", f"HELM_CACHE_HOME={helm_home / 'cache'}",
            f"HELM_CONFIG_HOME={helm_home / 'config'}",
            f"HELM_REGISTRY_CONFIG={helm_home / 'registry.json'}",
            f"HELM_DATA_HOME={helm_home / 'data'}", "helm", *args, timeout=timeout,
        )

    directory = Path(lab.kubeconfig).parent
    helm("pull", "oci://ghcr.io/kyverno/charts/kyverno", "--version", CHART_VERSION,
         "--destination", str(directory), timeout=90)
    chart = directory / f"kyverno-{CHART_VERSION}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CHART_SHA256:
        lab.block("Pinned Kyverno chart archive failed SHA-256 verification")
    helm("upgrade", "--install", "kyverno", str(chart),
         "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
         "--namespace", "kyverno", "--create-namespace", "--wait", "--timeout", "180s",
         "--values", str(chart_values), "--set", "webhooksCleanup.enabled=false",
         "--set", "features.generateValidatingAdmissionPolicy.enabled=false")


def _pod(image, *, gpu=True, gpu_quantity="1", classification="synthetic-inference",
         nonroot=True, allow_escalation=False, namespace=NS):
    labels = {"saf-k8s.example/case": "1006-005"}
    if classification is not None:
        labels["saf-k8s.example/classification"] = classification
    resources = {"requests": {"cpu": "10m", "memory": "8Mi"},
                 "limits": {"cpu": "50m", "memory": "32Mi"}}
    if gpu:
        resources["requests"]["nvidia.com/gpu"] = gpu_quantity
        resources["limits"]["nvidia.com/gpu"] = gpu_quantity
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "probe-1006-005", "namespace": namespace, "labels": labels},
        "spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": nonroot,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "inert", "image": image, "imagePullPolicy": "IfNotPresent",
                "securityContext": {
                    "allowPrivilegeEscalation": allow_escalation,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": resources,
            }],
        },
    }


def _probe(registry, pod):
    return registry.kube("-n", pod["metadata"]["namespace"], "create", "-f", "-",
                         "--dry-run=server", "-o", "json", input_text=json.dumps(pod),
                         timeout=35, allow_failure=True)


def _enroll_namespace(lab):
    # Enroll one case-owned namespace. The same Pod request must pass both the
    # image-aware Kyverno policy and the native VAP bound to this namespace.
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "-f", "-", payload=json.dumps({
                    "apiVersion": "v1", "kind": "Namespace",
                    "metadata": {"name": NS, "labels": {
                        "saf-k8s.example/ai-compliance": "enrolled",
                        "saf-k8s.example/image-validation": "enrolled",
                        "saf-k8s.example/case": "1006-005"}}}))
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "create", "namespace", NS + "-outside")


def _install_policies(lab, image, operator_key, registry):
    image_policy = image._policy(operator_key, registry.registry)
    registry.kube("apply", "-f", "-", input_text=image_policy.replace(image.POLICY, POLICY))
    image.POLICY = POLICY
    registry.kube("apply", "-f", "-", input_text=(HERE / "combined-validating-policy.yaml").read_text())


def _validating_binding_ready(lab, registry, approved_image):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        result = _probe(registry, _pod(approved_image, gpu_quantity="2"))
        if result.returncode != 0 and VAP in result.stderr and DENIALS["gpu-over-cap"] in result.stderr:
            return
        time.sleep(0.5)
    lab.block("Native fixture policy did not report its expected GPU-cap denial")


def run(lab):
    fixture = HERE.parent / "SAF-K8S-0605-002" / "image_admission.py"
    spec = importlib.util.spec_from_file_location("saf_1006_image_admission", fixture)
    image = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(image)
    with image.registry(lab) as (registry, host_port, chart_values):
        _install_kyverno(lab, chart_values)
        images = image._build_and_push(registry, host_port)
        operator_key = image._publish_signatures(registry, images)
        _enroll_namespace(lab)

        # Red control: combined bad request reaches the API before either policy
        # is installed. A success here proves an admission baseline, not runtime.
        baseline = _probe(registry, _pod(images["missing-attestation"], gpu_quantity="2",
                                        classification=None, nonroot=False, allow_escalation=True))
        lab.check("red", "Inactive policy set admits the same multi-obligation violation",
                  baseline.returncode == 0, {"admitted_before_policy": baseline.returncode == 0,
                                             "server_side_dry_run": True})
        # Install the combined policies only after recording the baseline.
        _install_policies(lab, image, operator_key, registry)
        image._wait_policy(registry)
        _validating_binding_ready(lab, registry, images["approved"])

        # All four obligations are represented on each request. The image
        # policy requires a signed image plus the exact inert fixture attestation.
        accepted = _probe(registry, _pod(images["approved"]))
        admitted = accepted.returncode == 0
        lab.check("positive", "Combined policy set admits the fully compliant Pod",
                  admitted, {"admitted": admitted, "server_side_dry_run": True,
                             "policy_set": [POLICY, VAP], "scope": NS})

        # Independent single-control failures verify every non-image branch
        # against the same request shape and the same bound VAP.
        cases = {
            "gpu-over-cap": _pod(images["approved"], gpu_quantity="2"),
            "root": _pod(images["approved"], nonroot=False),
            "privilege-escalation": _pod(images["approved"], allow_escalation=True),
            "missing-classification": _pod(images["approved"], classification=None),
            "unknown-classification": _pod(images["approved"], classification="unreviewed"),
        }
        for name, pod in cases.items():
            result = _probe(registry, pod)
            marker = DENIALS[name]
            denied = result.returncode != 0 and marker in result.stderr and VAP in result.stderr
            lab.check("green", f"Combined policy admission rejects {name}", denied,
                      {"denied": result.returncode != 0, "expected_rule": marker in result.stderr})

        for name, message in image.DENIALS.items():
            result = _probe(registry, _pod(images[name]))
            denied = result.returncode != 0 and message in result.stderr and POLICY in result.stderr
            lab.check("green", f"Combined policy admission rejects {name} provenance", denied,
                      {"denied": result.returncode != 0, "image_rule": message in result.stderr})

        no_gpu = _probe(registry, _pod(images["approved"], gpu=False))
        at_cap = _probe(registry, _pod(images["approved"], gpu_quantity="1"))
        lab.check("positive", "No-GPU and at-cap workloads remain admitted",
                  no_gpu.returncode == 0 and at_cap.returncode == 0,
                  {"no_gpu_admitted": no_gpu.returncode == 0,
                   "at_cap_admitted": at_cap.returncode == 0})

        outside = _probe(registry, _pod(images["unrelated-signer"], gpu_quantity="2",
                                       classification=None, nonroot=False, allow_escalation=True,
                                       namespace=NS + "-outside"))
        lab.check("positive", "Same violating workload is admitted outside the enrolled case namespace",
                  outside.returncode == 0,
                  {"admitted_outside_scope": outside.returncode == 0,
                   "server_side_dry_run": True})
