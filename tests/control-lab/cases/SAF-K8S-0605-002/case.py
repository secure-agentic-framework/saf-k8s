"""Exercise scoped CEL admission, mutation, and generation with Kyverno."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import time


HERE = Path(__file__).parent
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KYVERNO_VERSION = "v1.20.0"
CHART_VERSION = "3.10.0"
CHART_SHA256 = "55961392dc0821eb367323f0e9585c061dd4407ef7ada921bd56ea1642c2a301"
KYVERNO_NAMESPACE = "kyverno"
NAMESPACE = "saf-0605-002"
OUTSIDE_NAMESPACE = "saf-0605-002-outside"
VALIDATION_POLICY = "saf-0605-002-pod-baseline"
MUTATION_POLICY = "saf-0605-002-pod-defaults"
GENERATION_POLICY = "saf-0605-002-namespace-companion"
VIOLATION = (
    "SAF-K8S-0605-002: pod requires label saf-k8s.example/required=yes "
    "and spec.securityContext.runAsNonRoot=true"
)
INERT_IMAGE = (
    "registry.k8s.io/pause:3.10.1@sha256:"
    "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
)
SCOPE = (
    "One fresh disposable Kubernetes v1.36.1 Kind cluster and Kyverno v1.20.0 "
    "from Helm chart 3.10.0. A cluster-scoped GeneratingPolicy reacts only to "
    "the case namespace label; namespaced ValidatingPolicy and MutatingPolicy "
    "apply only to Pods in saf-0605-002. The case records one persisted Audit "
    "violation and its exact PolicyReport, changes that policy to Deny, checks "
    "the exact admission denial, and compares compliant and out-of-scope Pods. "
    "It checks a positive server-dry-run mutation and one inert generated "
    "ConfigMap companion. A namespace-scoped ImageValidatingPolicy compares "
    "three inert, locally registered OCI fixtures before and after enforcement "
    "and checks the same unrelated-signer reference outside the selected namespace."
)


def _kubectl(lab, *args, payload=None, timeout=40, allow_failure=False):
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={max(5, timeout - 5)}s", *args,
    ]
    try:
        return lab.command(*command, payload=payload, timeout=timeout,
                           allow_failure=allow_failure)
    except Exception as error:
        if allow_failure:
            raise
        lab.block(f"case-owned Kubernetes request failed ({type(error).__name__})")


def _helm(lab, *args, timeout=220):
    # Keep Helm's cache, config, and release metadata inside the runner's private
    # temporary directory instead of writing to the user's home directory.
    helm_home = Path(lab.kubeconfig).parent / "helm"
    helm_home.mkdir(exist_ok=True)
    env_args = [
        "env", f"HELM_CACHE_HOME={helm_home / 'cache'}",
        f"HELM_CONFIG_HOME={helm_home / 'config'}",
        f"HELM_REGISTRY_CONFIG={helm_home / 'registry.json'}",
        f"HELM_DATA_HOME={helm_home / 'data'}", "helm", *args,
    ]
    try:
        return lab.command(*env_args, timeout=timeout)
    except Exception as error:
        lab.block(f"pinned Kyverno chart install failed ({type(error).__name__})")


def _install_kyverno(lab, chart_values):
    directory = lab.kubeconfig.parent
    _helm(lab, "pull", "oci://ghcr.io/kyverno/charts/kyverno", "--version", CHART_VERSION,
          "--destination", str(directory), timeout=90)
    chart = directory / f"kyverno-{CHART_VERSION}.tgz"
    if sha256(chart.read_bytes()).hexdigest() != CHART_SHA256:
        lab.block("Pinned Kyverno chart archive failed the SHA-256 check")
    _helm(lab, "upgrade", "--install", "kyverno", str(chart),
          "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
          "--namespace", KYVERNO_NAMESPACE, "--create-namespace", "--wait", "--timeout", "180s",
          "--values", str(chart_values),
          "--set", "webhooksCleanup.enabled=false", "--set", "features.generateValidatingAdmissionPolicy.enabled=false")
    _kubectl(lab, "-n", KYVERNO_NAMESPACE, "rollout", "status",
             "deployment/kyverno-admission-controller", "--timeout=150s", timeout=160)


def _namespace(name, labels=None):
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels or {}}}


def _pod(name, *, required=True, nonroot=None, namespace=NAMESPACE):
    labels = {"saf-k8s.example/case": "0605-002"}
    if required:
        labels["saf-k8s.example/required"] = "yes"
    spec = {
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "containers": [{"name": "inert", "image": INERT_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "resources": {"requests": {"cpu": "10m", "memory": "8Mi"},
                                      "limits": {"cpu": "50m", "memory": "32Mi"}}}],
    }
    if nonroot is not None:
        spec["securityContext"] = {"runAsNonRoot": nonroot}
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": spec}


def _request(lab, resource, *, dry_run=True):
    flags = ["--dry-run=server"] if dry_run else []
    return _kubectl(lab, "-n", resource["metadata"]["namespace"], "create", "-f", "-",
                    "-o", "json", *flags, payload=json.dumps(resource), timeout=30,
                    allow_failure=True)


def _policy_report_result(lab, resource_name):
    result = _kubectl(lab, "-n", NAMESPACE, "get", "policyreports.wgpolicyk8s.io",
                      "-o", "json", allow_failure=True)
    if result.returncode:
        return None
    for report in json.loads(result.stdout).get("items", []):
        scope = report.get("scope") or {}
        if scope.get("name") != resource_name or scope.get("kind") != "Pod" or scope.get("namespace") != NAMESPACE:
            continue
        for row in report.get("results", []):
            if (row.get("policy") == f"{NAMESPACE}/{VALIDATION_POLICY}" and row.get("result") == "fail"
                    and row.get("message") == VIOLATION
                    and row.get("source") == "KyvernoValidatingPolicy"):
                return row
    return None


def _wait_report(lab, resource_name):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        row = _policy_report_result(lab, resource_name)
        if row:
            return row
        time.sleep(0.5)
    return None


def _wait_companion(lab):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = _kubectl(lab, "-n", NAMESPACE, "get", "configmap",
                          "saf-0605-002-companion", "-o", "json", allow_failure=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        time.sleep(0.5)
    return None


def _wait_policy_ready(lab, kind, name, namespace=None):
    resource = kind.lower()
    deadline = time.monotonic() + 50
    while time.monotonic() < deadline:
        args = (["-n", namespace] if namespace else [])
        result = _kubectl(lab, *args, "get", resource, name, "-o", "json",
                          allow_failure=True)
        if result.returncode == 0:
            policy = json.loads(result.stdout)
            status = policy.get("status", {}).get("conditionStatus", {})
            if status.get("ready") is True:
                return
            if any(condition.get("status") == "False" and condition.get("reason")
                   in ("Invalid", "Failed", "Error") for condition in status.get("conditions", [])):
                lab.block(f"{kind} {name} was rejected by Kyverno policy validation")
        time.sleep(0.5)
    lab.block(f"{kind} {name} did not become Ready/Accepted")


def _legacy_comparison(lab):
    legacy_name = "saf-0605-002-legacy-required-label"
    legacy = {
        "apiVersion": "kyverno.io/v1", "kind": "Policy",
        "metadata": {"name": legacy_name, "namespace": NAMESPACE},
        "spec": {"validationFailureAction": "Enforce", "background": False,
                 "rules": [{"name": "case-owned-label",
                            "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
                            "validate": {"message": VIOLATION, "pattern": {
                                "metadata": {"labels": {"saf-k8s.example/required": "yes"}},
                            }}}]},
    }
    installed = _request(lab, legacy, dry_run=False)
    retired = (installed.returncode != 0
               and 'admission webhook "validate-policy.kyverno.svc" denied the request:' in installed.stderr
               and "Kyverno v1.20 removed execution of legacy kyverno.io policy types" in installed.stderr)
    lab.check("positive", "Kyverno v1.20 explicitly rejects creation of the legacy policy",
              retired, {"legacy_write_explicitly_retired": retired})
    request = _pod("saf-0605-002-audit-violation", required=False, nonroot=False)
    result = _request(lab, request)
    lab.check("red", "Legacy Enforce policy cannot supply this label admission check on Kyverno v1.20",
              result.returncode == 0, {"noncompliant_dry_run_admitted": result.returncode == 0})


def _policy_checks(lab, chart_values):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              version.get("gitVersion") == "v1.36.1", {"server": version.get("gitVersion")})
    _install_kyverno(lab, chart_values)
    kyverno_pods = json.loads(_kubectl(lab, "-n", KYVERNO_NAMESPACE,
                                       "get", "pods", "-o", "json").stdout)["items"]
    images = sorted({container["image"] for pod in kyverno_pods
                     for container in pod["spec"].get("containers", [])})
    expected_images = {
        f"reg.kyverno.io/kyverno/{name}:{KYVERNO_VERSION}"
        for name in ("kyverno", "background-controller", "cleanup-controller", "reports-controller")
    }
    lab.check("positive", "Kyverno controller workloads use their pinned v1.20.0 images",
              expected_images.issubset(images),
              {"chart": CHART_VERSION, "images": images})

    # Install the generator before the namespace trigger exists.
    _kubectl(lab, "apply", "-f", "-", payload=(HERE / "generation-policy.yaml").read_text())
    _wait_policy_ready(lab, "GeneratingPolicy", GENERATION_POLICY)
    lab.create(_namespace(NAMESPACE, {"saf-k8s.example/generate": "true"}))
    lab.create(_namespace(OUTSIDE_NAMESPACE))
    companion = _wait_companion(lab)
    generated = bool(companion and companion.get("data") == {"purpose": "inert generated companion"}
                     and companion.get("metadata", {}).get("labels", {}).get(
                         "saf-k8s.example/generated-by") == GENERATION_POLICY)
    lab.check("green", "Scoped GeneratingPolicy creates its inert ConfigMap companion",
              generated, {"resource": "saf-0605-002-companion",
                          "generated_by_label": GENERATION_POLICY if generated else None})

    _legacy_comparison(lab)
    _kubectl(lab, "-n", NAMESPACE, "apply", "-f", "-",
             payload=(HERE / "pod-policies.yaml").read_text())
    _wait_policy_ready(lab, "NamespacedValidatingPolicy", VALIDATION_POLICY, NAMESPACE)
    _wait_policy_ready(lab, "NamespacedMutatingPolicy", MUTATION_POLICY, NAMESPACE)

    # Persist one harmless Audit-mode violation so Kyverno can record it in a
    # PolicyReport (reports describe extant resources, not server dry-runs).
    audit_pod = _pod("saf-0605-002-audit-violation", required=False, nonroot=False)
    audit_result = _request(lab, audit_pod, dry_run=False)
    audit_report = _wait_report(lab, audit_pod["metadata"]["name"])
    lab.check("red", "Same-policy noncompliant Pod is admitted in Audit mode with exact report evidence",
              audit_result.returncode == 0 and audit_report is not None,
              {"admitted_in_audit": audit_result.returncode == 0,
               "policy": VALIDATION_POLICY,
               "result": audit_report.get("result") if audit_report else None,
               "message": audit_report.get("message") if audit_report else None,
               "resource": audit_pod["metadata"]["name"]})

    _kubectl(lab, "-n", NAMESPACE, "delete", "pod", audit_pod["metadata"]["name"],
             "--wait=true", "--timeout=30s")
    _kubectl(lab, "-n", NAMESPACE, "patch", "namespacedvalidatingpolicy", VALIDATION_POLICY,
             "--type=merge", "-p", '{"spec":{"validationActions":["Deny"]}}')
    deadline = time.monotonic() + 25
    while True:
        denied = _request(lab, audit_pod)
        if (denied.returncode != 0 and VIOLATION in denied.stderr) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    named_webhook = 'admission webhook "nvpol.validate.kyverno.svc-fail" denied the request:' in denied.stderr
    denial_exact = (denied.returncode != 0 and named_webhook
                    and VALIDATION_POLICY in denied.stderr and VIOLATION in denied.stderr)
    lab.check("green", "Scoped Enforce change rejects the violation with its exact message",
              denial_exact, {"denied": denied.returncode != 0,
                             "kyverno_webhook_denied": named_webhook,
                             "policy_named": VALIDATION_POLICY in denied.stderr,
                             "exact_violation": VIOLATION in denied.stderr,
                             "correct_namespace": NAMESPACE})

    # Mutation adds safe pod-level defaults before validation sees the request.
    mutated_pod = _pod("saf-0605-002-mutated", required=True, nonroot=None)
    mutated = _request(lab, mutated_pod)
    mutated_object = json.loads(mutated.stdout) if mutated.returncode == 0 else {}
    mutation_ok = (
        mutated_object.get("metadata", {}).get("labels", {}).get(
            "saf-k8s.example/mutated") == "true"
        and mutated_object.get("spec", {}).get("securityContext", {}).get("runAsNonRoot") is True
        and mutated_object.get("spec", {}).get("securityContext", {}).get(
            "seccompProfile", {}).get("type") == "RuntimeDefault"
    )
    lab.check("positive", "MutatingPolicy adds label and pod security defaults before validation",
              mutated.returncode == 0 and mutation_ok,
              {"admitted": mutated.returncode == 0,
               "mutation_observed": mutation_ok,
               "labels": mutated_object.get("metadata", {}).get("labels"),
               "security_context": mutated_object.get("spec", {}).get("securityContext")})

    compliant = _request(lab, _pod("saf-0605-002-compliant", required=True, nonroot=True))
    lab.check("positive", "Compliant Pod remains admitted under Enforce",
              compliant.returncode == 0,
              {"admitted": compliant.returncode == 0, "server_side_dry_run": True})
    outside = _request(lab, _pod("saf-0605-002-outside-scope", required=False,
                                nonroot=False, namespace=OUTSIDE_NAMESPACE))
    lab.check("positive", "Same violation remains outside the namespaced policy scope",
              outside.returncode == 0,
              {"admitted_outside_scope": outside.returncode == 0,
               "server_side_dry_run": True})


def run(lab):
    spec = importlib.util.spec_from_file_location("kyverno_image_admission", HERE / "image_admission.py")
    image_admission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(image_admission)
    with image_admission.registry(lab) as (fixture, host_port, chart_values):
        _policy_checks(lab, chart_values)
        image_admission.run(lab, fixture, host_port)
