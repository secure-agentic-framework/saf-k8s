"""Validate shared Kubernetes federation prerequisites and a static-key admission policy."""

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import time

from fixtures import container, pod, ready

NS = "saf-test"
SCOPE_LABEL = "saf.example.org/governed-workload-identity"
POLICY = "fixture-workload-identity.saf.example.org"
DENY = "approved fixture workloads cannot reference the static cloud-key Secret"
SECRET = "fixture-static-cloud-key"
AUDIENCE = "https://identity.fixture.invalid/model-registry"
APPROVED = "fixture-approved-service"
OTHER = "fixture-other-service"
TOKEN = "/assertion/identity"
SCOPE = (
    "Use real Kubernetes projected service-account tokens and TokenReview in disposable Kind, "
    "apply a scope-specific static-key admission policy, and distinguish identity validation "
    "from an exact local exchange allow rule. Provider exchanges, IAM, account settings and "
    "credential rotation in cloud deployments are separate evidence."
)


def workload(name, account):
    workload_container = container("workload", command=["sh", "-c", "sleep 300"])
    workload_container["volumeMounts"] = [{"name": "identity", "mountPath": "/assertion", "readOnly": True}]
    return pod(name, [workload_container], serviceAccountName=account, automountServiceAccountToken=False,
               volumes=[{"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
                   "audience": AUDIENCE, "expirationSeconds": 600, "path": "identity"}}]}}])


def reference_shapes():
    candidates = {}
    for key in ("secret_volume", "projected_secret_volume", "env_secret", "init_env_from"):
        candidates[key] = workload("fixture-static-" + key.replace("_", "-"), APPROVED)
    candidates["secret_volume"]["spec"]["volumes"].append({"name": "static", "secret": {"secretName": SECRET}})
    candidates["projected_secret_volume"]["spec"]["volumes"].append({
        "name": "static", "projected": {"sources": [{"secret": {"name": SECRET}}]}})
    candidates["env_secret"]["spec"]["containers"][0]["env"] = [
        {"name": "FIXTURE_KEY", "valueFrom": {"secretKeyRef": {"name": SECRET, "key": "synthetic"}}}]
    init = container("init", command=["sh", "-c", "exit 0"],
                     envFrom=[{"secretRef": {"name": SECRET}}])
    candidates["init_env_from"]["spec"]["initContainers"] = [init]
    return candidates


def install_policy(lab):
    env_refs = (
        f"(!has(c.env) || c.env.all(e, !has(e.valueFrom) || !has(e.valueFrom.secretKeyRef) || e.valueFrom.secretKeyRef.name != '{SECRET}')) && "
        f"(!has(c.envFrom) || c.envFrom.all(e, !has(e.secretRef) || e.secretRef.name != '{SECRET}'))"
    )
    volumes = (
        "!has(object.spec.volumes) || object.spec.volumes.all(v, "
        f"(!has(v.secret) || v.secret.secretName != '{SECRET}') && "
        f"(!has(v.projected) || v.projected.sources.all(s, !has(s.secret) || s.secret.name != '{SECRET}')))"
    )
    validations = [{"expression": expr, "message": DENY} for expr in (
        volumes,
        f"object.spec.containers.all(c, {env_refs})",
        f"!has(object.spec.initContainers) || object.spec.initContainers.all(c, {env_refs})",
        f"!has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.all(c, {env_refs})",
    )]
    api = "admissionregistration.k8s.io/v1"
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [
                    {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                     "resources": ["pods", "pods/ephemeralcontainers"]}]}, "validations": validations}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {SCOPE_LABEL: "true"}}}}})


def denied(response):
    return response.returncode != 0 and POLICY in response.stderr and DENY in response.stderr


def private_request(lab, *args, payload=None):
    # The owned ephemeral test token can appear in request and response.
    # Do not send this operation through the public fixture command logger.
    try:
        result = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig),
                                 "--context", f"kind-{lab.cluster}", "--namespace", NS,
                                 "--request-timeout=12s", *args],
                                input=payload, text=True, capture_output=True, env=lab.env, timeout=16)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A private Kubernetes token operation did not complete")
    if result.returncode:
        lab.block("A private Kubernetes token operation failed")
    return result.stdout


def review(lab, token, audience):
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
            "spec": {"token": token, "audiences": [audience]}}
    status = json.loads(private_request(lab, "create", "-f", "-", "-o", "json",
                                        payload=json.dumps(body)))["status"]
    return status.get("authenticated", False), status.get("user", {}).get("username"), status.get("audiences", [])


def local_exchange(status):
    return status == (True, f"system:serviceaccount:{NS}:{APPROVED}", [AUDIENCE])


def claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def run(lab):
    lab.kubectl("label", "namespace", NS, f"{SCOPE_LABEL}=true")
    for account in (APPROVED, OTHER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account},
                    "automountServiceAccountToken": False})
    references = reference_shapes()
    baseline = {name: lab.create(doc, dry_run=True, allow_failure=True).returncode == 0
                for name, doc in references.items()}
    lab.check("red", "Before the policy, admission accepts all fixture shapes that reference the designated static key",
              all(baseline.values()), baseline)
    install_policy(lab)
    primary_probe = references["secret_volume"]
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if denied(lab.create(primary_probe, dry_run=True, allow_failure=True)):
            break
        time.sleep(.5)
    rejections = {name: denied(lab.create(doc, dry_run=True, allow_failure=True))
                  for name, doc in references.items()}
    permitted = deepcopy(primary_probe)
    permitted["spec"]["volumes"][-1]["secret"]["secretName"] = "fixture-unrelated-config-secret"
    unrelated = lab.create(permitted, dry_run=True, allow_failure=True).returncode == 0
    lab.check("green", "The scoped policy rejects designated static-key references and permits unrelated declared material",
              all(rejections.values()) and unrelated, {"designated_reference_denials": rejections, "unrelated_allowed": unrelated})

    for name, account in (("fixture-first-workload", APPROVED), ("fixture-second-workload", OTHER)):
        lab.create(workload(name, account))
        ready(lab, name)
    # Ephemeral references use the actual Kubernetes subresource.
    unit = container("debug-fixture", command=["sh", "-c", "exit 0"],
                     envFrom=[{"secretRef": {"name": SECRET}}])
    patch = json.dumps({"spec": {"ephemeralContainers": [unit]}})
    ephemeral = lab.kubectl("patch", "pod/fixture-first-workload", "--subresource=ephemeralcontainers",
                           "--type=merge", "-p", patch, "--dry-run=server", "-o", "name", allow_failure=True)
    first = private_request(lab, "exec", "fixture-first-workload", "--", "cat", TOKEN).strip()
    second = private_request(lab, "exec", "fixture-second-workload", "--", "cat", TOKEN).strip()
    issuer = json.loads(lab.kubectl("get", "--raw=/.well-known/openid-configuration").stdout)["issuer"]
    inspected = claims(first)
    binding = inspected.get("kubernetes.io", {}).get("pod", {})
    lifetime = inspected.get("exp", 0) - inspected.get("iat", 0)
    timed = (inspected.get("iss") == issuer and binding.get("name") == "fixture-first-workload"
             and inspected.get("aud") == [AUDIENCE] and 0 < lifetime <= 600)
    expected = review(lab, first, AUDIENCE)
    other_subject = review(lab, second, AUDIENCE)
    wrong_audience = review(lab, first, "https://different.fixture.invalid")
    exact = (local_exchange(expected) and not local_exchange(other_subject)
             and other_subject == (True, f"system:serviceaccount:{NS}:{OTHER}", [AUDIENCE])
             and not wrong_audience[0])
    default_mount_absent = lab.kubectl("exec", "fixture-first-workload", "--", "test", "!",
        "-e", "/var/run/secrets/kubernetes.io/serviceaccount/token", allow_failure=True).returncode == 0
    lab.check("positive", "The explicit mounted token authenticates its bounded identity and an exact local exchange rule authorizes only the approved subject",
              exact and timed and default_mount_absent and denied(ephemeral),
              {"matched_identity_and_audience": exact, "bounded_projection": timed,
               "default_mount_absent": default_mount_absent, "ephemeral_secret_denied": denied(ephemeral)})
    lab.kubectl("delete", "pod/fixture-first-workload", "--wait=true", "--grace-period=0")
    deadline = time.monotonic() + 30
    retired = False
    while time.monotonic() < deadline:
        retired = not review(lab, first, AUDIENCE)[0]
        if retired:
            break
        time.sleep(1)
    lab.check("positive", "Deleting the bound Pod withdraws its Kubernetes token while the other fixture credential remains authenticated",
              retired and review(lab, second, AUDIENCE)[0], {"retired_bound_token": retired, "other_remains_authenticated": True})
    (lab.evidence / "workload-federation-observations.json").write_text(json.dumps({
        "baseline_shapes": baseline, "prohibited_references": rejections, "ephemeral_secret_denied": denied(ephemeral),
        "unrelated_reference_allowed": unrelated, "mounted_token_max_lifetime_seconds": lifetime,
        "exact_local_subject_and_audience_gate": exact, "bound_token_withdrawn": retired,
        "Kubernetes_default_automount_absent": default_mount_absent, "cloud_provider_exchange_tested": False,
    }, indent=2) + "\n")
