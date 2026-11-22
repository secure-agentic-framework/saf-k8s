"""Exercise Kubernetes-native separation-of-duties admission for an inert release record."""
import json
from pathlib import Path
import shlex
import subprocess
import time
import time


NAMESPACE = "saf-test"
RELEASE_NAME = "release-decision"
RELEASE_ID = "fixture-model-release-v1"
POLICY = "saf-model-promotion-separation-of-duties"
BINDING = "saf-model-promotion-separation-of-duties-binding"
DEVELOPER_SA = "case-developer"
REVIEWER_SA = "approved-reviewer"
DENIAL = "model approver must be authenticated, independent of proposer, and preserve the fixed release"
SCOPE = (
    "Kubernetes v1.36.1 native ValidatingAdmissionPolicy on updates to one synthetic ConfigMap release record. "
    "Two independently authenticated, short-lived ServiceAccount tokens represent the case developer and an "
    "approved reviewer. The policy binds the approver field to request.userInfo.username, preserves the original "
    "proposer and fixed release ID, denies developer self-approval, and permits the distinct reviewer to persist "
    "the same approval decision. This does not exercise a model registry, production promotion controller, human "
    "identity provider, quorum, cross-tenant workflow, artifact verification, or model execution."
)


def _save(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _private_kubectl(lab, *args, payload=None, timeout=45):
    """Run credential-bearing kubectl calls without recording stdout/stderr."""
    command = ("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}", *args)
    with (lab.evidence / "commands.log").open("a", encoding="utf-8") as log:
        log.write(f"$ {shlex.join(command)} [credential output suppressed]\n")
        try:
            result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                    env=lab.env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(f"{type(error).__name__}: private credential command failed\n\n")
            lab.block("A private credential command could not complete")
        log.write(f"[exit {result.returncode}; stdout and stderr suppressed]\n\n")
    if result.returncode:
        lab.block("A private credential command failed")
    return result.stdout


def _mint_token(lab, service_account):
    # The bearer token remains in process memory and a mode-0600 temporary
    # kubeconfig. Neither command output nor token bytes enter lab.evidence.
    raw = _private_kubectl(lab, "create", "token", service_account, "--namespace", NAMESPACE,
                           "--duration=10m", timeout=45).strip()
    if not raw or "\n" in raw:
        lab.block("The API server did not return one short-lived ServiceAccount token")
    return raw


def _actor_kubeconfig(lab, temp_dir, service_account):
    raw_config = _private_kubectl(lab, "config", "view", "--raw", "-o", "json", timeout=20)
    config = json.loads(raw_config)
    current = config["current-context"]
    context = next(item["context"] for item in config["contexts"] if item["name"] == current)
    cluster = next(item["cluster"] for item in config["clusters"] if item["name"] == context["cluster"])
    token = _mint_token(lab, service_account)
    actor = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "fixture", "cluster": {
            "server": cluster["server"], "certificate-authority-data": cluster["certificate-authority-data"]}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "actor",
                    "namespace": NAMESPACE}}],
        "current-context": "fixture",
        "users": [{"name": "actor", "user": {"token": token}}],
    }
    path = Path(temp_dir) / f"{service_account}.kubeconfig"
    path.write_text(json.dumps(actor), encoding="utf-8")
    path.chmod(0o600)
    return path


def _actor_command(lab, kubeconfig, *args, payload=None, allow_failure=False):
    result = lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", "fixture",
                         "--namespace", NAMESPACE, "--request-timeout=35s", *args,
                         payload=payload, allow_failure=allow_failure)
    return result


def _whoami(lab, kubeconfig, expected, label):
    result = _actor_command(lab, kubeconfig, "auth", "whoami", "-o", "json")
    identity = json.loads(result.stdout)
    username = identity.get("status", {}).get("userInfo", {}).get("username")
    _save(lab, f"{label}-authenticated-identity.json", identity)
    if username != expected:
        lab.block(f"{label} credential authenticated as an unexpected principal")
    return username


def _record_update(lab, kubeconfig, approver, decision, *, allow_failure=False, dry_run=False):
    patch = {"data": {"approver": approver, "decision": decision}}
    flags = ("--dry-run=server",) if dry_run else ()
    return _actor_command(lab, kubeconfig, "patch", "configmap", RELEASE_NAME,
                          "--type=merge", "-p", json.dumps(patch), "-o", "json", *flags,
                          allow_failure=allow_failure)


def _is_targeted_denial(result):
    response = (result.stderr + result.stdout).lower()
    infra_markers = ("timed out", "timeout", "connection refused", "i/o timeout",
                     "no matches for kind", "the server could not find the requested resource",
                     "unauthorized", "forbidden: user")
    return (result.returncode != 0 and POLICY.lower() in response and DENIAL.lower() in response
            and not any(marker in response for marker in infra_markers))


def _capture_response(lab, filename, result):
    # kubectl output contains the server's real API response and synthetic
    # record only; bearer credentials are held in the kubeconfig and not shown.
    _save(lab, filename, {"returncode": result.returncode, "stdout": result.stdout,
                          "stderr": result.stderr})


def run(lab):
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server_version!r}")
    _save(lab, "kubernetes-version.json", version)
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/model-promotion-fixture=enabled", "--overwrite")
    for account in (DEVELOPER_SA, REVIEWER_SA):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
            "name": account, "namespace": NAMESPACE}, "automountServiceAccountToken": False})

    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {
        "name": "release-decision-writer", "namespace": NAMESPACE}, "rules": [{
            "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [RELEASE_NAME],
            "verbs": ["get", "patch", "update"]}]}
    lab.create(role)
    for account in (DEVELOPER_SA, REVIEWER_SA):
        lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                    "metadata": {"name": f"{account}-release-writer", "namespace": NAMESPACE},
                    "subjects": [{"kind": "ServiceAccount", "name": account, "namespace": NAMESPACE}],
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                                "name": "release-decision-writer"}})

    proposer = f"system:serviceaccount:{NAMESPACE}:{DEVELOPER_SA}"
    reviewer = f"system:serviceaccount:{NAMESPACE}:{REVIEWER_SA}"
    record = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RELEASE_NAME,
              "namespace": NAMESPACE, "labels": {"saf-k8s.example/release-id": RELEASE_ID}},
              "data": {"release": RELEASE_ID, "proposer": proposer,
                       "decision": "pending", "approver": ""}}
    lab.create(record)

    credential_dir = lab.kubeconfig.parent / "0905-025-credentials"
    credential_dir.mkdir(mode=0o700)
    developer_config = _actor_kubeconfig(lab, credential_dir, DEVELOPER_SA)
    reviewer_config = _actor_kubeconfig(lab, credential_dir, REVIEWER_SA)
    developer_identity = _whoami(lab, developer_config, proposer, "developer")
    reviewer_identity = _whoami(lab, reviewer_config, reviewer, "reviewer")
    if developer_identity == reviewer_identity:
        lab.block("Developer and reviewer credentials resolved to the same authenticated identity")

    red = _record_update(lab, developer_config, developer_identity, "approved")
    _capture_response(lab, "red-self-approval-api.json", red)
    stored = json.loads(lab.kubectl("get", "configmap", RELEASE_NAME, "-o", "json").stdout)
    _save(lab, "prepolicy-stored-self-approval.json", stored)
    red_persisted = red.returncode == 0 and stored["data"] == {
        "release": RELEASE_ID, "proposer": proposer,
        "decision": "approved", "approver": developer_identity}
    lab.check("red", "The authenticated case developer can persist the exact self-approval before policy",
              red_persisted, {"returncode": red.returncode, "persisted_self_approval": red_persisted,
                              "authenticated_username": developer_identity})

    # Re-establish the same fixed release and original proposer before policy.
    reset = lab.kubectl("patch", "configmap", RELEASE_NAME, "--type=merge", "-p",
                        json.dumps({"data": {"decision": "pending", "approver": ""}}), "-o", "json")
    _capture_response(lab, "reset-pending-api.json", reset)

    policy = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
              "metadata": {"name": POLICY}, "spec": {
                  "failurePolicy": "Fail",
                  "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                      "operations": ["UPDATE"], "resources": ["configmaps"]}]},
                  "validations": [{"expression": (
                      f'object.metadata.name != "{RELEASE_NAME}" || '
                      '(object.data["proposer"] == oldObject.data["proposer"] && '
                      'object.data["release"] == oldObject.data["release"] && '
                      f'object.data["release"] == "{RELEASE_ID}" && '
                      'object.data["decision"] == "approved" && '
                      'object.data["approver"] == request.userInfo.username && '
                      f'request.userInfo.username == "{reviewer}" && '
                      'request.userInfo.username != oldObject.data["proposer"])'),
                      "message": DENIAL}]}}
    binding = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
               "metadata": {"name": BINDING}, "spec": {
                   "policyName": POLICY, "validationActions": ["Deny"],
                   "matchResources": {"namespaceSelector": {"matchLabels": {
                       "saf-k8s.example/model-promotion-fixture": "enabled"}}}}}
    lab.kubectl("apply", "-f", "-", payload=json.dumps(policy))
    lab.kubectl("apply", "-f", "-", payload=json.dumps(binding))
    observed = None
    for _ in range(40):
        observed = json.loads(lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
        typed = observed.get("status", {}).get("typeChecking")
        if typed is not None:
            _save(lab, "policy-type-checking.json", typed)
            if typed.get("expressionWarnings"):
                lab.block("The admission policy has CEL type-checking warnings")
            break
        time.sleep(0.5)
    else:
        lab.block("The API server did not complete ValidatingAdmissionPolicy type checking")

    # Policy typing and admission registration have separate readiness points.
    deadline = time.monotonic() + 35
    while True:
        probe = _record_update(lab, developer_config, developer_identity, "approved",
                               allow_failure=True, dry_run=True)
        if _is_targeted_denial(probe):
            break
        if probe.returncode != 0:
            _capture_response(lab, "policy-probe-unexpected-api.json", probe)
            lab.block("Admission readiness probe failed for a reason other than the named policy")
        if time.monotonic() >= deadline:
            _capture_response(lab, "policy-probe-unexpected-api.json", probe)
            lab.block("The installed binding did not enforce the named policy before the deadline")
        time.sleep(0.5)
    denied = _record_update(lab, developer_config, developer_identity, "approved", allow_failure=True)
    _capture_response(lab, "green-self-approval-api.json", denied)
    after_denial = json.loads(lab.kubectl("get", "configmap", RELEASE_NAME, "-o", "json").stdout)
    _save(lab, "post-denial-release-record.json", after_denial)
    unchanged = after_denial["data"] == {"release": RELEASE_ID, "proposer": proposer,
                                          "decision": "pending", "approver": ""}
    targeted = _is_targeted_denial(denied)
    lab.check("green", "The same authenticated developer update is denied by the targeted native policy",
              targeted and unchanged,
              {"targeted_policy_denial": targeted, "record_unchanged": unchanged,
               "returncode": denied.returncode, "authenticated_username": developer_identity})

    accepted = _record_update(lab, reviewer_config, reviewer, "approved")
    _capture_response(lab, "positive-reviewer-approval-api.json", accepted)
    final = json.loads(lab.kubectl("get", "configmap", RELEASE_NAME, "-o", "json").stdout)
    _save(lab, "reviewer-final-release-record.json", final)
    persisted = final["data"] == {"release": RELEASE_ID, "proposer": proposer,
                                  "decision": "approved", "approver": reviewer_identity}
    lab.check("positive", "The distinct authenticated reviewer persists the same fixed release approval",
              accepted.returncode == 0 and persisted,
              {"returncode": accepted.returncode, "persisted_reviewer_approval": persisted,
               "authenticated_username": reviewer_identity, "release_id": RELEASE_ID,
               "decision": final["data"].get("decision")})
