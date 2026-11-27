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
    "security context, and classified inert Pods. One persisted marker-only Pod with image pulls "
    "disabled exercises an approved benign UPDATE and a denied untrusted-image UPDATE. "
    "GPU scheduling and production policy coverage require separate evidence."
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
    # The copy of this case deliberately opts its local image policy into
    # UPDATE so the lifecycle witness below covers the API's image mutability.
    if image_policy.count("operations: [CREATE]") != 1:
        lab.block("Copied image policy template did not have its exact CREATE rule")
    image_policy = image_policy.replace("operations: [CREATE]", "operations: [CREATE, UPDATE]")
    registry.kube("apply", "-f", "-", input_text=image_policy.replace(image.POLICY, POLICY))
    image.POLICY = POLICY
    registry.kube("apply", "-f", "-", input_text=(HERE / "combined-validating-policy.yaml").read_text())


def _persisted_update_witness(lab, registry, image, images):
    name = "admission-update-1006-005"
    approved = images["approved"]
    approved_update = images["approved-update"]
    candidate = images["unrelated-signer"]
    pod = _pod(approved, gpu=False)
    pod["metadata"]["name"] = name
    pod["spec"]["containers"][0]["imagePullPolicy"] = "Never"
    pod["spec"]["schedulingGates"] = [{"name": "saf-k8s.example/admission-update-witness"}]
    created = None
    cleanup_ok = False
    allowed_ok = denial_ok = unchanged = False
    check_observed = {}
    raw = {"image_policy_operations": ["CREATE", "UPDATE"],
           "image_pull_policy": "Never", "running_or_ready_claimed": False}
    try:
        result = registry.kube("-n", NS, "create", "-f", "-", "-o", "json",
                               input_text=json.dumps(pod), timeout=35, allow_failure=True)
        if result.returncode:
            lab.block("Compliant inert Pod was not persistently admitted")
        created = json.loads(result.stdout)
        uid = created.get("metadata", {}).get("uid")
        if not uid:
            lab.block("Persisted inert Pod response omitted its UID")

        # A same-policy strategic image UPDATE is accepted for a second
        # independently signed repository; the benign annotation adds context.
        allowed = registry.kube(
            "-n", NS, "patch", "pod", name, "--type=strategic", "-o", "json",
            "-p", json.dumps({"metadata": {"annotations": {
                "saf-k8s.example/update-witness": "benign"}},
                "spec": {"containers": [{"name": "inert", "image": approved_update}]}}),
            timeout=35, allow_failure=True,
        )
        if allowed.returncode:
            lab.block("The compliant inert Pod did not accept the benign UPDATE")
        after_allowed = json.loads(allowed.stdout)
        allowed_uid = after_allowed.get("metadata", {}).get("uid")
        allowed_rv = after_allowed.get("metadata", {}).get("resourceVersion")
        created_rv = created.get("metadata", {}).get("resourceVersion")
        allowed_image = after_allowed.get("spec", {}).get("containers", [{}])[0].get("image")
        allowed_spec = after_allowed.get("spec", {})
        allowed_generation = after_allowed.get("metadata", {}).get("generation")
        allowed_ok = (allowed_uid == uid and allowed_rv and allowed_rv != created_rv
                      and allowed_image == approved_update
                      and after_allowed.get("metadata", {}).get("annotations", {}).get(
                          "saf-k8s.example/update-witness") == "benign")

        # This is a fixed, noncompliant fixture reference. Its UPDATE must be
        # denied and leave the already admitted object unchanged.
        denied = registry.kube(
            "-n", NS, "patch", "pod", name, "--type=strategic", "-o", "json",
            "-p", json.dumps({"spec": {"containers": [{"name": "inert", "image": candidate}]}}),
            timeout=35, allow_failure=True,
        )
        webhook = f'admission webhook "ivpol.validate.kyverno.svc-fail-finegrained-{POLICY}" denied'
        reason = image.DENIALS["unrelated-signer"]
        denial_ok = (denied.returncode != 0 and webhook in denied.stderr
                     and reason in denied.stderr and candidate in denied.stderr)
        current_result = registry.kube("-n", NS, "get", "pod", name, "-o", "json",
                                       timeout=20)
        current = json.loads(current_result.stdout)
        current_meta = current.get("metadata", {})
        current_image = current.get("spec", {}).get("containers", [{}])[0].get("image")
        unchanged = (current_meta.get("uid") == uid
                     and current.get("spec") == allowed_spec
                     and current_image == approved_update
                     and current_meta.get("generation") == allowed_generation
                     and current.get("metadata", {}).get("annotations", {}).get(
                         "saf-k8s.example/update-witness") == "benign")
        raw.update({"created_pod": created, "after_benign_update": after_allowed,
                    "approved_update_image": approved_update,
                    "denied_update_candidate_image": candidate,
                    "denied_update_returncode": denied.returncode,
                    "denied_update_stderr": denied.stderr,
                    "after_denied_update": current,
                    "assertions": {"benign_update_admitted": allowed_ok,
                                   "exact_noncompliant_update_denied": denial_ok,
                                   "post_denial_object_unchanged": unchanged}})
        check_observed = {
            "persisted_pod_uid_present": bool(uid), "benign_update_admitted": allowed_ok,
            "uid_preserved": allowed_uid == uid, "resource_version_advanced": allowed_rv != created_rv,
            "second_approved_image_accepted": allowed_image == approved_update,
            "noncompliant_update_denied": denial_ok, "exact_fixture_policy_reason": reason in denied.stderr,
            "post_denial_uid_unchanged": current_meta.get("uid") == uid,
            "post_denial_spec_unchanged": current.get("spec") == allowed_spec,
            "post_denial_image_unchanged": current_image == approved_update,
            "post_denial_generation_unchanged": current_meta.get("generation") == allowed_generation,
            "post_denial_benign_annotation_present": current_meta.get("annotations", {}).get(
                "saf-k8s.example/update-witness") == "benign",
            "image_pull_policy": "Never", "running_or_ready_claimed": False}
    finally:
        if created is not None:
            uid = created.get("metadata", {}).get("uid")
            if uid:
                options = {"apiVersion": "v1", "kind": "DeleteOptions",
                           "gracePeriodSeconds": 0, "preconditions": {"uid": uid}}
                uri = f"/api/v1/namespaces/{NS}/pods/{name}"
                deleted = registry.kube("delete", "--raw", uri, "-f", "-",
                                        input_text=json.dumps(options), timeout=20,
                                        allow_failure=True)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    gone = registry.kube("-n", NS, "get", "pod", name,
                                         "--ignore-not-found", "-o", "json",
                                         timeout=10, allow_failure=True)
                    if deleted.returncode == 0 and gone.returncode == 0 and not gone.stdout.strip():
                        cleanup_ok = True
                        break
                    time.sleep(0.25)
    if created is not None:
        raw["cleanup"] = {"deleted_and_absent": cleanup_ok,
                          "observed_uid": created.get("metadata", {}).get("uid")}
        (lab.evidence / "admission-update-raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        lab.check(
            "positive",
            "A persisted compliant inert Pod accepts a benign UPDATE and rejects a noncompliant image UPDATE without mutation",
            allowed_ok and denial_ok and unchanged,
            check_observed)
        lab.check("positive", "The case-owned persisted update witness is retired",
                  cleanup_ok, {"cleanup": "complete" if cleanup_ok else "not-confirmed",
                               "uid_bound_cleanup": bool(created.get("metadata", {}).get("uid"))})


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
    # Add one controlled second approved repository only to this module instance;
    # the shared 0605-002 helper and its published fixture remain unchanged.
    image.REPOSITORIES = {**image.REPOSITORIES,
                          "approved-update": "fixture/inert-approved-update"}
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
        _persisted_update_witness(lab, registry, image, images)
